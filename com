"""
Unified management command for django-filer.

Location in project: rss/management/commands/filer_sync.py

This single command can:
    - Upload a single file
    - Sync an entire local directory tree (recreating subfolders)
    - Apply folder permissions (user / group / everybody) at the same time
    - List or clear permissions

It replaces the previous separate commands:
    upload_to_filer, sync_folder_to_filer, manage_filer_permissions.

USAGE EXAMPLES
==============

Upload a single file (auto-detected because the source is a file):
    python manage.py filer_sync "C:\\reports\\daily.csv" --target "Reports"

Sync a whole directory tree (auto-detected because the source is a folder):
    python manage.py filer_sync "C:\\reports\\firewall" --target "Firewall APAC Rules"

Sync + replace existing files + clean up local copies after upload:
    python manage.py filer_sync "C:\\reports\\firewall" --target "Reports" --replace --delete-source

Filter which files to upload by glob pattern:
    python manage.py filer_sync "C:\\reports" --target "Reports" --pattern "*.csv"

Upload AND grant a user read+edit access to the target folder in one go:
    python manage.py filer_sync "C:\\reports\\daily.csv" --target "Reports" ^
        --grant-user jdoe --can-read --can-edit --scope all

Upload AND grant a group access:
    python manage.py filer_sync "C:\\reports\\daily.csv" --target "Reports" ^
        --grant-group network_admins --can-read --scope all

Upload AND grant access to everybody:
    python manage.py filer_sync "C:\\reports\\daily.csv" --target "Public" ^
        --grant-everybody --can-read --scope all

Apply permissions only (no upload, just configure access):
    python manage.py filer_sync --target "Reports" --grant-user jdoe --can-read --scope all

List existing permissions on a folder:
    python manage.py filer_sync --target "Reports" --list-permissions

Clear all permissions on a folder:
    python manage.py filer_sync --target "Reports" --clear-permissions

Preview what would happen without changing anything:
    python manage.py filer_sync "C:\\reports\\firewall" --target "Reports" --dry-run
"""
from pathlib import Path

from django.contrib.auth.models import Group
from django.core.files import File as DjangoFile
from django.core.management.base import BaseCommand, CommandError

from filer.models import File as FilerFile, Folder, FolderPermission

from accounts.models import User


class Command(BaseCommand):
    help = (
        'Unified command to upload files/folders into django-filer, optionally '
        'applying folder permissions in the same call.'
    )

    SCOPE_MAP = {
        'this': FolderPermission.THIS,
        'children': FolderPermission.CHILDREN,
        'all': FolderPermission.ALL,
    }

    # ----------------------------------------------------------------------
    # CLI arguments
    # ----------------------------------------------------------------------

    def add_arguments(self, parser):
        # Source is optional: if omitted, only permission operations run
        parser.add_argument(
            'source',
            nargs='?',
            default=None,
            type=str,
            help='Optional path to a local file or directory to upload.',
        )

        # Target folder in filer (always required)
        parser.add_argument(
            '--target',
            type=str,
            required=True,
            help=(
                'Target folder path inside filer. Use "/" for nested folders, '
                'e.g. "Reports/2026". Missing folders are created automatically.'
            ),
        )

        # Upload-related options
        parser.add_argument(
            '--pattern',
            type=str,
            default='*',
            help='Glob pattern for files when source is a directory (default: "*").',
        )
        parser.add_argument(
            '--replace',
            action='store_true',
            help='Replace files that already exist in the target filer folder.',
        )
        parser.add_argument(
            '--delete-source',
            action='store_true',
            help='Delete each local file after a successful upload.',
        )

        # Permission target (one of these may be passed)
        parser.add_argument(
            '--grant-user',
            type=str,
            help='Grant permission to a user (looked up by user_uid).',
        )
        parser.add_argument(
            '--grant-group',
            type=str,
            help='Grant permission to a group name.',
        )
        parser.add_argument(
            '--grant-everybody',
            action='store_true',
            help='Grant permission to everybody.',
        )
        parser.add_argument(
            '--deny',
            action='store_true',
            help=(
                'Used together with --grant-* to store DENY instead of ALLOW '
                '(useful for explicitly blocking access).'
            ),
        )

        # Permission flags
        parser.add_argument('--can-read', action='store_true', help='Grant/deny read.')
        parser.add_argument('--can-edit', action='store_true', help='Grant/deny edit.')
        parser.add_argument('--can-add-children', action='store_true', help='Grant/deny add children.')

        # Permission scope
        parser.add_argument(
            '--scope',
            choices=['this', 'children', 'all'],
            default='this',
            help='Permission scope (default: this).',
        )

        # Permission utility actions
        parser.add_argument(
            '--list-permissions',
            action='store_true',
            help='List current permissions on the target folder and exit.',
        )
        parser.add_argument(
            '--clear-permissions',
            action='store_true',
            help='Remove all permissions from the target folder and exit.',
        )

        # Dry run
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would happen without making any changes.',
        )

    # ----------------------------------------------------------------------
    # Entry point
    # ----------------------------------------------------------------------

    def handle(self, *args, **options):
        target_path = options['target']
        source = options['source']
        dry_run = options['dry_run']

        if dry_run:
            self.stdout.write(self.style.WARNING('--- DRY RUN: no changes will be persisted ---'))

        # 1. Permission-only utility actions short-circuit early
        if options['list_permissions']:
            folder = self._resolve_folder(target_path, create_if_missing=False)
            self._list_permissions(folder)
            return

        if options['clear_permissions']:
            folder = self._resolve_folder(target_path, create_if_missing=False)
            self._clear_permissions(folder, dry_run)
            return

        # 2. Resolve / create the target folder for the rest of the workflow
        target_folder = self._resolve_folder(target_path, create_if_missing=True, dry_run=dry_run)

        # 3. If a source was provided, upload it (file or directory)
        if source:
            source_path = Path(source)
            if not source_path.exists():
                raise CommandError(f'Source path does not exist: {source_path}')

            if source_path.is_file():
                self._upload_single_file(
                    source_path=source_path,
                    target_folder=target_folder,
                    replace=options['replace'],
                    delete_source=options['delete_source'],
                    dry_run=dry_run,
                )
            else:
                self._sync_directory(
                    source_dir=source_path,
                    target_root=target_folder,
                    target_root_path=target_path,
                    pattern=options['pattern'],
                    replace=options['replace'],
                    delete_source=options['delete_source'],
                    dry_run=dry_run,
                )

        # 4. Apply permissions if any --grant-* flag was passed
        permission_target_count = sum(1 for v in (
            options['grant_user'], options['grant_group'], options['grant_everybody']
        ) if v)

        if permission_target_count > 1:
            raise CommandError(
                'Use only one of --grant-user, --grant-group, --grant-everybody.'
            )

        if permission_target_count == 1:
            self._apply_permission(target_folder, options, dry_run)

    # ----------------------------------------------------------------------
    # Folder resolution
    # ----------------------------------------------------------------------

    @staticmethod
    def _split_path(folder_path):
        """Split 'A/B/C' into ['A', 'B', 'C']."""
        parts = [p.strip() for p in folder_path.split('/') if p.strip()]
        if not parts:
            raise CommandError('Target folder path cannot be empty.')
        return parts

    def _resolve_folder(self, folder_path, create_if_missing, dry_run=False):
        """Resolve a "/"-separated folder path inside filer."""
        parts = self._split_path(folder_path)
        parent = None
        for part in parts:
            if create_if_missing:
                if dry_run:
                    # In dry-run we don't touch the DB, so we may not be able
                    # to walk down past missing folders. Bail out gracefully.
                    existing = Folder.objects.filter(name=part, parent=parent).first()
                    if existing is None:
                        self.stdout.write(f'[dry-run] Would create folder: {part}')
                        return None
                    parent = existing
                else:
                    parent, _ = Folder.objects.get_or_create(name=part, parent=parent)
            else:
                try:
                    parent = Folder.objects.get(name=part, parent=parent)
                except Folder.DoesNotExist:
                    raise CommandError(f'Folder "{part}" does not exist under the given path.')
        return parent

    # ----------------------------------------------------------------------
    # Upload helpers
    # ----------------------------------------------------------------------

    def _upload_single_file(self, source_path, target_folder, replace, delete_source, dry_run):
        """Upload one local file into the given filer folder."""
        if dry_run:
            self.stdout.write(f'[dry-run] Would upload {source_path} -> "{self._folder_display(target_folder)}"')
            return

        existing = FilerFile.objects.filter(
            folder=target_folder,
            original_filename=source_path.name,
        ).first()

        if existing:
            if replace:
                existing.delete()
                self.stdout.write(f'Removed existing file: {source_path.name}')
            else:
                self.stdout.write(self.style.WARNING(
                    f'File "{source_path.name}" already exists. Use --replace to overwrite. Skipping.'
                ))
                return

        with source_path.open('rb') as fh:
            FilerFile.objects.create(
                file=DjangoFile(fh, name=source_path.name),
                folder=target_folder,
                original_filename=source_path.name,
            )

        self.stdout.write(self.style.SUCCESS(f'Uploaded: {source_path.name}'))

        if delete_source:
            try:
                source_path.unlink()
                self.stdout.write(f'Source file deleted: {source_path}')
            except OSError as exc:
                self.stdout.write(self.style.WARNING(f'Could not delete source file: {exc}'))

    def _sync_directory(self, source_dir, target_root, target_root_path,
                        pattern, replace, delete_source, dry_run):
        """Walk a local directory and recreate its structure inside filer."""
        uploaded = 0
        skipped = 0
        replaced = 0

        for local_file in sorted(source_dir.rglob(pattern)):
            if not local_file.is_file():
                continue

            # Compute the relative folder path inside the source tree
            relative = local_file.relative_to(source_dir).parent
            relative_parts = [p for p in relative.parts if p]

            if dry_run:
                full_path = '/'.join([target_root_path] + relative_parts)
                self.stdout.write(f'[dry-run] Would upload {local_file} -> "{full_path}"')
                uploaded += 1
                continue

            # Ensure the matching subfolder structure exists in filer
            target_folder = target_root
            for part in relative_parts:
                target_folder, _ = Folder.objects.get_or_create(
                    name=part, parent=target_folder
                )

            existing = FilerFile.objects.filter(
                folder=target_folder,
                original_filename=local_file.name,
            ).first()

            if existing:
                if replace:
                    existing.delete()
                    replaced += 1
                else:
                    self.stdout.write(self.style.WARNING(
                        f'Skipped (already exists): {local_file.name} in '
                        f'"{self._folder_display(target_folder)}"'
                    ))
                    skipped += 1
                    continue

            with local_file.open('rb') as fh:
                FilerFile.objects.create(
                    file=DjangoFile(fh, name=local_file.name),
                    folder=target_folder,
                    original_filename=local_file.name,
                )

            uploaded += 1
            self.stdout.write(
                f'Uploaded: {local_file.name} -> "{self._folder_display(target_folder)}"'
            )

            if delete_source:
                try:
                    local_file.unlink()
                except OSError as exc:
                    self.stdout.write(self.style.WARNING(
                        f'Could not delete source file {local_file}: {exc}'
                    ))

        self.stdout.write(self.style.SUCCESS(
            f'Sync done. Uploaded: {uploaded}, replaced: {replaced}, skipped: {skipped}.'
        ))

    # ----------------------------------------------------------------------
    # Permission helpers
    # ----------------------------------------------------------------------

    def _apply_permission(self, folder, options, dry_run):
        """Create a FolderPermission entry on the target folder."""
        if not folder:
            raise CommandError('Cannot apply permissions: target folder could not be resolved.')

        permission_value = (
            FolderPermission.DENY if options['deny'] else FolderPermission.ALLOW
        )

        # Build the kwargs only for flags that were explicitly passed
        perm_kwargs = {
            'folder': folder,
            'type': self.SCOPE_MAP[options['scope']],
        }

        if options['can_read']:
            perm_kwargs['can_read'] = permission_value
        if options['can_edit']:
            perm_kwargs['can_edit'] = permission_value
        if options['can_add_children']:
            perm_kwargs['can_add_children'] = permission_value

        if not any(k in perm_kwargs for k in ('can_read', 'can_edit', 'can_add_children')):
            raise CommandError(
                'You must pass at least one of --can-read, --can-edit, --can-add-children.'
            )

        # Resolve the target (user / group / everybody)
        if options['grant_user']:
            try:
                user = User.objects.get(user_uid=options['grant_user'])
            except User.DoesNotExist:
                raise CommandError(f'User "{options["grant_user"]}" not found.')
            perm_kwargs['user'] = user
            target_label = f'user: {user.user_uid}'
        elif options['grant_group']:
            try:
                group = Group.objects.get(name=options['grant_group'])
            except Group.DoesNotExist:
                raise CommandError(f'Group "{options["grant_group"]}" not found.')
            perm_kwargs['group'] = group
            target_label = f'group: {group.name}'
        else:
            perm_kwargs['everybody'] = True
            target_label = 'everybody'

        if dry_run:
            self.stdout.write(
                f'[dry-run] Would set permission ({"DENY" if options["deny"] else "ALLOW"}) '
                f'on "{self._folder_display(folder)}" for {target_label} '
                f'(scope: {options["scope"]})'
            )
            return

        FolderPermission.objects.create(**perm_kwargs)
        self.stdout.write(self.style.SUCCESS(
            f'Permission granted on "{self._folder_display(folder)}" for {target_label}.'
        ))

    def _list_permissions(self, folder):
        """Print all permissions defined on a folder."""
        perms = FolderPermission.objects.filter(folder=folder).select_related('user', 'group')
        if not perms:
            self.stdout.write(f'No permissions defined on "{folder.name}".')
            return

        self.stdout.write(f'Permissions on "{folder.name}":')
        self.stdout.write('-' * 90)
        self.stdout.write(
            f'{"ID":>4} | {"Target":<30} | {"Scope":<10} | '
            f'{"Read":<6} | {"Edit":<6} | {"Add":<6}'
        )
        self.stdout.write('-' * 90)
        for p in perms:
            if p.everybody:
                target = 'EVERYBODY'
            elif p.user:
                target = f'user: {p.user.user_uid}'
            elif p.group:
                target = f'group: {p.group.name}'
            else:
                target = '?'

            def fmt(value):
                if value == FolderPermission.ALLOW:
                    return 'ALLOW'
                if value == FolderPermission.DENY:
                    return 'DENY'
                return '-'

            self.stdout.write(
                f'{p.id:>4} | {target:<30} | {p.get_type_display():<10} | '
                f'{fmt(p.can_read):<6} | {fmt(p.can_edit):<6} | {fmt(p.can_add_children):<6}'
            )

    def _clear_permissions(self, folder, dry_run):
        """Delete all permissions on a folder."""
        if dry_run:
            count = FolderPermission.objects.filter(folder=folder).count()
            self.stdout.write(f'[dry-run] Would delete {count} permission(s) on "{folder.name}".')
            return

        deleted, _ = FolderPermission.objects.filter(folder=folder).delete()
        self.stdout.write(self.style.SUCCESS(
            f'Deleted {deleted} permission(s) on "{folder.name}".'
        ))

    # ----------------------------------------------------------------------
    # Display helpers
    # ----------------------------------------------------------------------

    @staticmethod
    def _folder_display(folder):
        """Build a readable path like 'Reports/2026/April'."""
        if folder is None:
            return '(root)'
        parts = []
        node = folder
        while node is not None:
            parts.insert(0, node.name)
            node = node.parent
        return '/'.join(parts)
