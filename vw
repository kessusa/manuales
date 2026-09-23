# =============================================================================
# bookmark/views.py -> Global Search section / Group lookup
# Server-side render (same pattern as avi_waf_search / marketplace_search).
# Imports needed at file level: render, Q, PlayflowsTagGroup
# =============================================================================

GROUP_LOOKUP_TARGET_TAG = 'EMEA_UK_PRD_MGMT'   # TODO: 'APAC_SG_PRD_DMZA_CORPWM' per ticket
GROUP_LOOKUP_TARGET_REGION = 'emea'            # TODO: 'apac'
GROUP_LOOKUP_MAX_DEPTH = 10
GROUP_LOOKUP_TEMPLATE = 'search_components/group_lookup_component.html'


def get_group_lookup_root(group_name):
    """Return the IP group of the target tag matching the name, or None."""
    return (
        PlayflowsTagGroup.objects
        .filter(
            Q(tag__deleted=False) | Q(tag__deleted__isnull=True),
            name__iexact=group_name,
            type='ip',
            tag__tag_name=GROUP_LOOKUP_TARGET_TAG,
            tag__region=GROUP_LOOKUP_TARGET_REGION,
        )
        .only('id', 'name', 'content')
        .first()
    )


def load_group_children_map(root_group_id):
    """Load the subtree edges breadth-first: one query per level."""
    through = PlayflowsTagGroup.children.through
    children_map = {}
    frontier = [root_group_id]

    for _ in range(GROUP_LOOKUP_MAX_DEPTH):
        if not frontier:
            break
        edges = (
            through.objects
            .filter(from_playflowstaggroup_id__in=frontier)
            .select_related('to_playflowstaggroup')
        )
        next_frontier = []
        for edge in edges:
            child = edge.to_playflowstaggroup
            children_map.setdefault(edge.from_playflowstaggroup_id, []).append(child)
            if child.id not in children_map:
                next_frontier.append(child.id)
        frontier = next_frontier

    return children_map


def build_group_node(group, children_map, visited=None, depth=0):
    """Build the hierarchy dict consumed by the template (cycle safe)."""
    if visited is None:
        visited = set()

    node = {'group_name': group.name, 'ips': [], 'subgroups': []}
    if group.id in visited or depth >= GROUP_LOOKUP_MAX_DEPTH:
        return node
    visited.add(group.id)

    node['ips'] = [str(ip) for ip in (group.content or [])]
    for child in children_map.get(group.id, []):
        node['subgroups'].append(build_group_node(child, children_map, visited, depth + 1))
    return node


@login_required
@user_passes_test(user_can_view_global_search)
def group_lookup_search(request):
    """Render a playflows group of the target tag with its nested subgroups and IPs."""
    group_name = request.GET.get('q_search', '').strip()
    if not group_name:
        return render(request, GROUP_LOOKUP_TEMPLATE, {'error': 'No search term provided'})

    root_group = get_group_lookup_root(group_name)
    if root_group is None:
        return render(request, GROUP_LOOKUP_TEMPLATE, {
            'error': f'Group "{group_name}" not found or not linked to {GROUP_LOOKUP_TARGET_TAG}',
        })

    hierarchy = build_group_node(root_group, load_group_children_map(root_group.id))
    return render(request, GROUP_LOOKUP_TEMPLATE, {'hierarchy': hierarchy})
