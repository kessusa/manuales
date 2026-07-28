# =============================================================================
# EMEAPLAYFLOWS-3637 - Group Lookup with explicit hierarchy
#
# Design: the hierarchy is stored explicitly in the database.
#   - PlayflowsTagGroup.content  -> ONLY direct IPs (or services) of the group
#   - PlayflowsTagGroupRelation  -> parent/child FK rows (the tree)
# The view reads content + relations. No name matching, no type guessing.
#
# Apply order:
#   1. models.py -> add PlayflowsTagGroupRelation, then:
#      python manage.py makemigrations rss && python manage.py migrate  (STG)
#   2. playflows.py -> replace get_groups_with_content
#   3. playflows_groups_update.py -> replace sync_tag_groups
#   4. bookmark/views.py -> replace the group lookup section
#   5. python manage.py playflows_groups_update --tag-name EMEA_UK_PRD_MGMT
# =============================================================================


# -----------------------------------------------------------------------------
# 1. rss/models.py  (place right after PlayflowsTagGroupLink)
# -----------------------------------------------------------------------------
class PlayflowsTagGroupRelation(models.Model):
    """Explicit parent/child relation between playflows groups."""

    class Meta:
        managed = True
        db_table = 'pf_tag_group_relation'
        unique_together = ('parent', 'child')

    parent = models.ForeignKey(
        PlayflowsTagGroup, on_delete=models.CASCADE,
        related_name='fk_children',
    )
    child = models.ForeignKey(
        PlayflowsTagGroup, on_delete=models.CASCADE,
        related_name='fk_parents',
    )

    def __str__(self):
        return f'{self.parent.name} -> {self.child.name}'


# -----------------------------------------------------------------------------
# 2. API_cnx/playflows.py  -> PlayflowsAPI.get_groups_with_content
#    ips and subgroups are returned as SEPARATE keys. No guessing later.
# -----------------------------------------------------------------------------
def get_groups_with_content(self, sid, tag_name):
    params = {
        'sid': sid,
        'commands': [f"show objects {tag_name} groups name-to-values"],
        'version': 'upcoming',
    }
    self.connection_args['json'] = params
    response = requests.post(
        f'{self.base_url}/commands', **self.connection_args
    ).json()

    if response.get('status') != 'success':
        return None

    data = response.get('data', [])
    if not data:
        return None

    groups_info = (
        data[0].get('groups', {}).get(tag_name, {})
        .get('upcoming', {}).get('members-of', {})
    )
    name_to_values = (
        data[0].get('name-to-values', {}).get(tag_name, {})
        .get('upcoming', {})
    )

    address_map = name_to_values.get('address', {})
    service_map = name_to_values.get('service', {})
    groups_with_content = {}

    for group_name, members in groups_info.items():
        member_names = list(members.keys()) if members else []
        ips = []
        services = []
        subgroups = []

        for member in member_names:
            if member in groups_info:
                subgroups.append(member)
            elif member in address_map:
                ips.extend(address_map[member].keys())
            elif member in service_map:
                for service_key in service_map[member].keys():
                    services.append(
                        service_key[2:]
                        if service_key.startswith('S_') else service_key
                    )

        if ips or subgroups:
            group_type = 'ip'
        elif services:
            group_type = 'service'
        else:
            group_type = 'unknown'

        groups_with_content[group_name] = {
            'type': group_type,
            'ips': sorted(set(ips)),
            'services': sorted(set(services)),
            'subgroups': sorted(set(subgroups)),
        }

    return groups_with_content


# -----------------------------------------------------------------------------
# 3. rss/management/commands/playflows_groups_update.py -> sync_tag_groups
#    Pass 1 upserts groups, pass 2 rebuilds the explicit relations.
# -----------------------------------------------------------------------------
def sync_tag_groups(self, tag, result):
    with transaction.atomic():
        existing = {
            (link.group.name, link.group.type): link.group
            for link in PlayflowsTagGroupLink.objects
            .filter(tag=tag)
            .select_related('group')
        }

        seen_keys = set()
        groups_by_name = {}

        # --- Pass 1: upsert groups and tag links -----------------------------
        for group_name, group_info in result.items():
            content = (
                group_info['ips']
                if group_info['type'] != 'service'
                else group_info['services']
            )
            key = (group_name, group_info['type'])
            seen_keys.add(key)

            group = existing.get(key)
            if group is None:
                group = PlayflowsTagGroup.objects.filter(
                    name=group_name, type=group_info['type'],
                ).first()
            if group is None:
                group = PlayflowsTagGroup.objects.create(
                    name=group_name,
                    type=group_info['type'],
                    content=content,
                )
            else:
                group.content = content
                group.save(update_fields=['content'])

            PlayflowsTagGroupLink.objects.get_or_create(group=group, tag=tag)
            groups_by_name[group_name] = group

        # --- Pass 2: rebuild explicit parent/child relations -----------------
        for group_name, group_info in result.items():
            parent = groups_by_name[group_name]
            child_ids = set()
            for sub_name in group_info['subgroups']:
                child = groups_by_name.get(sub_name)
                if child is not None and child.id != parent.id:
                    child_ids.add(child.id)
                    PlayflowsTagGroupRelation.objects.get_or_create(
                        parent=parent, child=child,
                    )
            # Drop relations that no longer exist upstream
            PlayflowsTagGroupRelation.objects.filter(
                parent=parent,
            ).exclude(child_id__in=child_ids).delete()

        # --- Stale links: only if the NAME left the tag entirely -------------
        seen_names = {name for name, _ in seen_keys}
        stale_keys = {
            (name, gtype)
            for (name, gtype) in set(existing.keys()) - seen_keys
            if name not in seen_names
        }
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


# -----------------------------------------------------------------------------
# 4. bookmark/views.py -> Global Search / Group Lookup section
#    Reads content (IPs) + relations. Two queries total, recursion in memory.
# -----------------------------------------------------------------------------
GROUP_LOOKUP_TARGET_TAG = 'EMEA_UK_PRD_MGMT'   # TODO: APAC per ticket
GROUP_LOOKUP_TARGET_REGION = 'emea'            # TODO: 'apac'
GROUP_LOOKUP_MAX_DEPTH = 10


def build_group_node(group, children_map, visited=None, depth=0):
    """Build the hierarchy dict for a group using preloaded relations."""
    if visited is None:
        visited = set()

    node = {'group_name': group.name, 'ips': [], 'subgroups': []}
    if group.id in visited or depth >= GROUP_LOOKUP_MAX_DEPTH:
        return node
    visited.add(group.id)

    node['ips'] = [str(ip) for ip in (group.content or [])]
    for child in children_map.get(group.id, []):
        node['subgroups'].append(
            build_group_node(child, children_map, visited, depth + 1)
        )
    return node


@login_required
@user_passes_test(user_can_view_global_search)
def group_lookup_search(request):
    """
    Retrieve a group linked to the target tag and its full hierarchy
    (explicit relations), each level with its own IPs.
    """
    group_name = request.GET.get('q_search', '').strip()
    if not group_name:
        return JsonResponse({'error': 'No search term provided'}, status=400)

    root_group = (
        PlayflowsTagGroup.objects
        .filter(
            name__iexact=group_name,
            type='ip',
            fk_tag__tag__tag_name=GROUP_LOOKUP_TARGET_TAG,
            fk_tag__tag__region=GROUP_LOOKUP_TARGET_REGION,
        )
        .exclude(fk_tag__tag__deleted=True)
        .distinct()
        .first()
    )
    if root_group is None:
        return JsonResponse(
            {
                'error': (
                    f'Group "{group_name}" not found or not linked '
                    f'to {GROUP_LOOKUP_TARGET_TAG}'
                )
            },
            status=404,
        )

    # Load the whole relation set for the tree in one query (BFS by levels,
    # bounded by GROUP_LOOKUP_MAX_DEPTH).
    children_map = {}
    frontier = [root_group.id]
    for _ in range(GROUP_LOOKUP_MAX_DEPTH):
        if not frontier:
            break
        relations = (
            PlayflowsTagGroupRelation.objects
            .filter(parent_id__in=frontier)
            .select_related('child')
        )
        next_frontier = []
        for relation in relations:
            children_map.setdefault(relation.parent_id, []).append(
                relation.child
            )
            if relation.child_id not in children_map:
                next_frontier.append(relation.child_id)
        frontier = next_frontier

    return JsonResponse(build_group_node(root_group, children_map))
