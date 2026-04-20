import json
from django.core.management.base import BaseCommand
from django.db import transaction
from API_cnx.playflows import PlayflowsAPI
from rss.models import PlayflowsTagGroup, PlayflowsTagGroupLink, PlayflowsTag


class Command(BaseCommand):
    help = 'Populate PlayflowsTagGroup and PlayflowsTagGroupLink tables with group information'

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--tag-name', type=str, help='Name of the tag to process')
        group.add_argument('--all', action='store_true', help='Process all tags in the specified region')
        parser.add_argument('--region', type=str, default='emea', help='Region for Playflows API connection')
        parser.add_argument('--limit', type=int, help='Limit the number of tags to process (useful with --all)')

    def _sync_tag_groups(self, tag, result):
        """Sincroniza los grupos/links de un tag. Devuelve (processed, stale_removed)."""
        with transaction.atomic():
            # Grupos ya vinculados a ESTE tag: {name: group}
            existing = {
                link.group.name: link.group
                for link in PlayflowsTagGroupLink.objects
                    .filter(tag=tag)
                    .select_related('group')
            }

            seen_names = set()

            for group_name, group_info in result.items():
                seen_names.add(group_name)

                if group_name in existing:
                    # Ya existe para este tag -> actualizar contenido
                    group = existing[group_name]
                    group.type = group_info['type']
                    group.content = group_info['content']
                    group.save(update_fields=['type', 'content'])
                else:
                    # Nuevo para este tag -> crear grupo + link
                    # (No reutilizamos grupos de otros tags para no pisar su content)
                    group = PlayflowsTagGroup.objects.create(
                        name=group_name,
                        type=group_info['type'],
                        content=group_info['content'],
                    )
                    PlayflowsTagGroupLink.objects.create(group=group, tag=tag)

            # Links obsoletos: estaban vinculados antes pero ya no vienen del API
            stale_names = set(existing.keys()) - seen_names
            stale_removed = 0
            if stale_names:
                stale_group_ids = [existing[n].id for n in stale_names]

                # Borrar los links de este tag hacia esos grupos
                PlayflowsTagGroupLink.objects.filter(
                    tag=tag,
                    group_id__in=stale_group_ids,
                ).delete()

                # Borrar los grupos que se hayan quedado huérfanos (sin ningún link)
                stale_removed = PlayflowsTagGroup.objects.filter(
                    id__in=stale_group_ids,
                    fk_tag__isnull=True,  # 'fk_tag' es el related_name del Link hacia el Group
                ).delete()[0]

            return len(result), stale_removed

    def handle(self, *args, **options):
        region = options['region']
        limit = options['limit']

        # Conexión a Playflows API
        playflows_object = PlayflowsAPI(env=region)
        sid = playflows_object.get_sid()

        if not sid:
            self.stdout.write(self.style.ERROR('Failed to connect to Playflows API'))
            return

        if options['all']:
            tags = PlayflowsTag.objects.filter(region=region)
            if limit:
                tags = tags[:limit]

            if not tags.exists():
                self.stdout.write(self.style.WARNING(f'No tags found for region {region}'))
                return

            total = tags.count()
            self.stdout.write(self.style.SUCCESS(f'Found {total} tags to process in region {region}'))

            processed_tags = 0
            for tag in tags:
                try:
                    self.stdout.write(f"\nProcessing tag: {tag.tag_name}")

                    result = playflows_object.get_groups_with_content(sid, tag.tag_name)
                    if not result:
                        self.stdout.write(self.style.WARNING(f'No groups found for tag {tag.tag_name}'))
                        continue

                    n_groups, n_stale = self._sync_tag_groups(tag, result)

                    if n_stale:
                        self.stdout.write(self.style.WARNING(
                            f'Removed {n_stale} stale group links for tag {tag.tag_name}'
                        ))

                    self.stdout.write(self.style.SUCCESS(
                        f'Successfully processed {n_groups} groups for tag {tag.tag_name}'
                    ))
                    processed_tags += 1

                except Exception as e:
                    self.stdout.write(self.style.ERROR(
                        f'An error occurred processing tag {tag.tag_name}: {str(e)}'
                    ))
                    continue

            self.stdout.write(self.style.SUCCESS(
                f'\nSuccessfully processed {processed_tags} out of {total} tags'
            ))

        else:
            # Un solo tag
            tag_name = options['tag_name']

            result = playflows_object.get_groups_with_content(sid, tag_name)
            if not result:
                self.stdout.write(self.style.WARNING(f'No groups found for tag {tag_name}'))
                return

            try:
                with transaction.atomic():
                    tag, created = PlayflowsTag.objects.get_or_create(tag_name=tag_name)
                    if created:
                        self.stdout.write(self.style.SUCCESS(f'Created new tag: {tag_name}'))

                n_groups, n_stale = self._sync_tag_groups(tag, result)

                if n_stale:
                    self.stdout.write(self.style.WARNING(
                        f'Removed {n_stale} stale group links for tag {tag_name}'
                    ))

                self.stdout.write(self.style.SUCCESS(
                    f'Successfully processed {n_groups} groups for tag {tag_name}'
                ))

            except Exception as e:
                self.stdout.write(self.style.ERROR(
                    f'An error occurred processing tag {tag_name}: {str(e)}'
                ))
