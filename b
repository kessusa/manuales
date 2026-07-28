def sync_tag_groups(self, tag, result):
        with transaction.atomic():
            existing = {
                (link.group.name, link.group.type): link.group
                for link in PlayflowsTagGroupLink.objects
                .filter(tag=tag)
                .select_related('group')
            }
            self.stdout.write(f'existing keys: {len(existing)}')

            seen_keys = set()
            created_count = 0
            updated_count = 0

            for group_name, group_info in result.items():
                key = (group_name, group_info['type'])
                seen_keys.add(key)

                if key in existing:
                    group = existing[key]
                    group.content = group_info['content']
                    group.save(update_fields=['content'])
                    updated_count += 1
                else:
                    group = PlayflowsTagGroup.objects.filter(
                        name=group_name, type=group_info['type'],
                    ).first()
                    if group is not None:
                        group.content = group_info['content']
                        group.save(update_fields=['content'])
                    else:
                        group = PlayflowsTagGroup.objects.create(
                            name=group_name,
                            type=group_info['type'],
                            content=group_info['content'],
                        )
                    PlayflowsTagGroupLink.objects.get_or_create(
                        group=group, tag=tag,
                    )
                    created_count += 1

            stale_keys = set(existing.keys()) - seen_keys
            self.stdout.write(
                f'updated: {updated_count}, linked/created: {created_count}, '
                f'stale: {len(stale_keys)}'
            )
            if stale_keys:
                self.stdout.write(f'stale sample: {list(stale_keys)[:5]}')

            stale_removed = 0
            if stale_keys:
                stale_group_ids = [existing[k].id for k in stale_keys]
                PlayflowsTagGroupLink.objects.filter(
                    tag=tag, group_id__in=stale_group_ids,
                ).delete()
                stale_removed = PlayflowsTagGroup.objects.filter(
                    id__in=stale_group_ids, fk_tag__isnull=True,
                ).delete()[0]

            return len(result), stale_removed
