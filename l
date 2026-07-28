# =============================================================================
# Global Search - Group Lookup (bookmark/views.py)
# Replaces the current group_lookup_search implementation.
# Keep this block in the same section order as the ProdSecHub sidebar
# (Global Search functions, next to the other *_search views).
# =============================================================================

# Per EMEAPLAYFLOWS-3637 the final target is APAC. Kept as module-level
# constants so switching from the current EMEA test values is a one-line change.
GROUP_LOOKUP_TARGET_TAG = 'EMEA_UK_PRD_MGMT'   # TODO: 'APAC_SG_PRD_DMZA_CORPWM'
GROUP_LOOKUP_TARGET_REGION = 'emea'            # TODO: 'apac'
GROUP_LOOKUP_MAX_DEPTH = 10                    # Safety guard for deep nesting


def build_group_hierarchy(group, groups_by_name, visited=None, depth=0):
    """
    Recursively build the hierarchical representation of a group content.

    Any content entry whose value matches the name of another group linked
    to the target tag is resolved as a nested subgroup (with its own IPs and
    subgroups). Everything else is treated as a plain IP entry.

    Cycle-safe (visited set) and depth-limited (GROUP_LOOKUP_MAX_DEPTH).

    Returns:
        dict: {'group_name': str, 'ips': list[str], 'subgroups': list[dict]}
    """
    if visited is None:
        visited = set()

    node = {'group_name': group.name, 'ips': [], 'subgroups': []}
    group_key = group.name.strip().lower()

    if group_key in visited or depth >= GROUP_LOOKUP_MAX_DEPTH:
        return node
    visited.add(group_key)

    content = group.content or []

    # Legacy shape support: {"subgroup_name": [ips], ...}
    if isinstance(content, dict):
        for sub_name, sub_value in content.items():
            node['subgroups'].append(
                build_inline_subgroup(
                    sub_name, sub_value, groups_by_name, visited, depth + 1
                )
            )
        return node

    for item in content:
        item_str = str(item).strip()
        sub_group = groups_by_name.get(item_str.lower())
        if sub_group is not None:
            node['subgroups'].append(
                build_group_hierarchy(
                    sub_group, groups_by_name, visited, depth + 1
                )
            )
        else:
            node['ips'].append(item_str)

    return node


def build_inline_subgroup(sub_name, sub_value, groups_by_name, visited, depth):
    """
    Resolve a subgroup declared inline inside a dict-shaped content.

    If the key matches a real PlayflowsTagGroup linked to the target tag,
    the DB record wins and is resolved recursively; otherwise the inline
    value is rendered as-is.
    """
    sub_group = groups_by_name.get(str(sub_name).strip().lower())
    if sub_group is not None:
        return build_group_hierarchy(sub_group, groups_by_name, visited, depth)

    node = {'group_name': str(sub_name), 'ips': [], 'subgroups': []}
    if depth >= GROUP_LOOKUP_MAX_DEPTH:
        return node

    if isinstance(sub_value, list):
        node['ips'] = [str(ip).strip() for ip in sub_value]
    elif isinstance(sub_value, dict):
        for child_name, child_value in sub_value.items():
            node['subgroups'].append(
                build_inline_subgroup(
                    child_name, child_value, groups_by_name, visited, depth + 1
                )
            )
    elif sub_value is not None:
        node['ips'] = [str(sub_value).strip()]

    return node


@login_required
@user_passes_test(user_can_view_global_search)
def group_lookup_search(request):
    """
    Retrieve the content of a group ONLY if it is explicitly linked to the
    target tag, resolving nested subgroups recursively with their own IPs.
    """
    group_name = request.GET.get('q_search', '').strip()
    if not group_name:
        return JsonResponse({'error': 'No search term provided'}, status=400)

    # Single query: load every group linked to the target tag once, then
    # resolve the whole hierarchy in memory (avoids one query per subgroup).
    tagged_groups = (
        PlayflowsTagGroup.objects
        .filter(
            fk_tag__tag__tag_name=GROUP_LOOKUP_TARGET_TAG,
            fk_tag__tag__region=GROUP_LOOKUP_TARGET_REGION,
            fk_tag__tag__deleted=False,
        )
        .distinct()
        .only('name', 'type', 'content')
    )
    groups_by_name = {
        group.name.strip().lower(): group for group in tagged_groups
    }

    root_group = groups_by_name.get(group_name.lower())
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

    return JsonResponse(build_group_hierarchy(root_group, groups_by_name))
