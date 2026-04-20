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
            # Grupos actualmente vinculados a este tag
            current_groups = set(
                PlayflowsTagGroupLink.objects
                    .filter(tag=tag)
                    .values_list('group__name', flat=True)
            )

            # Procesar cada grupo que devuelve la API
            for group_name, group_info in result.items():
                group, _ = PlayflowsTagGroup.objects.update_or_create(
                    name=group_name,
                    defaults={
                        'type': group_info['type'],
                        'content': group_info['content'],
                    }
                )

                PlayflowsTagGroupLink.objects.get_or_create(
                    group=group,
                    tag=tag,
                )

                current_groups.discard(group_name)

            # Lo que queda en current_groups son links obsoletos
            stale_removed = 0
            if current_groups:
                stale_removed = PlayflowsTagGroupLink.objects.filter(
                    tag=tag,
                    group__name__in=current_groups,
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
