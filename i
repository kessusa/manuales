from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from API_cnx.playflows import PlayflowsAPI
from rss.models import PlayflowsTag, PlayflowsTagGroup, TaskUpdateDate

TASK_NAME = 'playflows_groups_update'
TASK_STATUS_RUNNING = 'running'
TASK_STATUS_SUCCESS = 'success'
TASK_STATUS_FAILED = 'failed'


def flatten_group_members(result, group_name, key, path, cache):
    """
    Return the direct members of a group plus those of its nested subgroups,
    at any depth. Works in memory on the API result (no queries).

    key: 'ips' or 'services'
    path: group names already in the current branch (cycle guard)
    cache: {group_name: set} shared across the tag so shared subgroups are
           resolved only once
    """
    if group_name in cache:
        return cache[group_name]

    members = set(result[group_name].get(key, []))
    for subgroup in result[group_name].get('subgroups', []):
        if subgroup in result and subgroup not in path:
            members |= flatten_group_members(result, subgroup, key, path | {subgroup}, cache)

    cache[group_name] = members
    return members


class Command(BaseCommand):
    help = 'Populate PlayflowsTagGroup rows and their hierarchy from playflows tags'

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--tag-name', type=str, help='Name of the tag to process')
        group.add_argument('--all', action='store_true', help='Process all tags in the specified region')
        parser.add_argument('--region', type=str, default='emea', help='Region for Playflows API connection')

    # -------------------------------------------------------------------------
    # Task log (TaskUpdateDate). Written outside the per-tag transactions so a
    # rolled back tag never erases the execution record.
    # -------------------------------------------------------------------------
    def start_task(self, region):
        return TaskUpdateDate.objects.create(
            name=TASK_NAME,
            status=TASK_STATUS_RUNNING,
            message=[{'level': 'info', 'tag': None, 'detail': f'region={region}'}],
            created_at=timezone.now(),
        )

    def finish_task(self, task, messages):
        has_errors = any(message['level'] == 'error' for message in messages)
        task.status = TASK_STATUS_FAILED if has_errors else TASK_STATUS_SUCCESS
        task.message = messages
        task.finish_at = timezone.now()
        task.save(update_fields=['status', 'message', 'finish_at'])
        return task.status

    # -------------------------------------------------------------------------
    # Sync of one tag: upsert groups, prune stale ones, rebuild hierarchy.
    # Bulk operations keep the query count flat per tag.
    # -------------------------------------------------------------------------
    def sync_tag_groups(self, tag, result):
        flatten_cache = {'ips': {}, 'services': {}}

        with transaction.atomic():
            existing = {
                (group.name, group.type): group
                for group in PlayflowsTagGroup.objects.filter(tag=tag)
            }

            to_create = []
            to_update = []
            seen_keys = set()

            for group_name, group_info in result.items():
                key = (group_name, group_info['type'])
                seen_keys.add(key)

                member_key = 'services' if group_info['type'] == 'service' else 'ips'
                content = group_info[member_key]
                resolved_content = sorted(flatten_group_members(
                    result, group_name, member_key, {group_name}, flatten_cache[member_key],
                ))

                group = existing.get(key)
                if group is None:
                    to_create.append(PlayflowsTagGroup(
                        tag=tag, name=group_name, type=group_info['type'],
                        content=content, resolved_content=resolved_content,
                    ))
                elif group.content != content or group.resolved_content != resolved_content:
                    group.content = content
                    group.resolved_content = resolved_content
                    to_update.append(group)

            if to_create:
                PlayflowsTagGroup.objects.bulk_create(to_create, batch_size=1000)
            if to_update:
                PlayflowsTagGroup.objects.bulk_update(
                    to_update, ['content', 'resolved_content'], batch_size=500,
                )

            stale_keys = set(existing.keys()) - seen_keys
            stale_removed = 0
            if stale_keys:
                stale_removed = PlayflowsTagGroup.objects.filter(
                    id__in=[existing[key].id for key in stale_keys],
                ).delete()[0]

            groups_by_name = {
                group.name: group
                for group in PlayflowsTagGroup.objects.filter(tag=tag, type='ip').only('id', 'name')
            }
            through = PlayflowsTagGroup.children.through
            through.objects.filter(from_playflowstaggroup__tag=tag).delete()

            edges = []
            for group_name, group_info in result.items():
                parent = groups_by_name.get(group_name)
                if parent is None:
                    continue
                for sub_name in group_info['subgroups']:
                    child = groups_by_name.get(sub_name)
                    if child is not None and child.id != parent.id:
                        edges.append(through(
                            from_playflowstaggroup=parent,
                            to_playflowstaggroup=child,
                        ))
            if edges:
                through.objects.bulk_create(edges, batch_size=1000, ignore_conflicts=True)

            return len(result), stale_removed

    def process_tag(self, playflows_api, sid, tag):
        self.stdout.write(f'\nProcessing tag: {tag.tag_name}')
        try:
            result = playflows_api.get_groups_with_content(sid, tag.tag_name)
            if not result:
                self.stdout.write(self.style.WARNING(f'No groups found for tag {tag.tag_name}'))
                return {'level': 'warning', 'tag': tag.tag_name, 'detail': 'No groups found'}

            n_groups, n_stale = self.sync_tag_groups(tag, result)
            self.stdout.write(self.style.SUCCESS(
                f'Successfully processed {n_groups} groups for tag {tag.tag_name}'
                f' ({n_stale} stale removed)'
            ))
            return {
                'level': 'info',
                'tag': tag.tag_name,
                'detail': f'{n_groups} groups processed, {n_stale} stale removed',
            }
        except Exception as error:
            self.stdout.write(self.style.ERROR(
                f'An error occurred processing tag {tag.tag_name}: {error}'
            ))
            return {'level': 'error', 'tag': tag.tag_name, 'detail': str(error)}

    def handle(self, *args, **options):
        region = options['region']
        task = self.start_task(region)
        messages = list(task.message)

        try:
            playflows_api = PlayflowsAPI(env=region)
            sid = playflows_api.get_sid()
            if not sid:
                raise ConnectionError('Failed to connect to Playflows API')

            if options['all']:
                tags = list(PlayflowsTag.objects.filter(region=region))
                if not tags:
                    messages.append({
                        'level': 'warning', 'tag': None,
                        'detail': f'No tags found for region {region}',
                    })
            else:
                tag, created = PlayflowsTag.objects.get_or_create(
                    tag_name=options['tag_name'], region=region,
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f'Created new tag: {tag.tag_name}'))
                tags = [tag]

            for tag in tags:
                messages.append(self.process_tag(playflows_api, sid, tag))

        except Exception as error:
            self.stdout.write(self.style.ERROR(str(error)))
            messages.append({'level': 'error', 'tag': None, 'detail': str(error)})

        finally:
            status = self.finish_task(task, messages)

        style = self.style.SUCCESS if status == TASK_STATUS_SUCCESS else self.style.ERROR
        self.stdout.write(style(f'\nTask {task.id} finished with status: {status}'))
