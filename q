# --- rss/views.py -----------------------------------------------------------
# Add to the existing imports at the top of the file (json may already be imported):
import json
from collections import defaultdict, deque

from rss.models import PlayflowsTagGroup


# --- Firewall section > Group Comparator ------------------------------------
# Paste this block in the Firewall section, replacing the current ajax_load_data_group_comparator.

def to_hashable(value):
    """Return a hashable, comparable representation of a group content item."""
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def load_group_maps_by_tag(root_group):
    """Return {tag_name: group_map} for every firewall tag where root_group exists.

    Walks the subgroup tree level by level: two queries per depth level for all tags at once,
    so the query count depends on the tree depth, not on the number of tags or groups.
    Groups sharing a name inside a tag (ip/service types) are merged under that name.
    """
    members_by_tag = defaultdict(lambda: defaultdict(set))
    subgroups_by_tag = defaultdict(lambda: defaultdict(set))
    group_index = {}
    level_queryset = PlayflowsTagGroup.objects.filter(name=root_group)

    while True:
        level_ids = []
        for group_id, tag_name, name, content in level_queryset.values_list('id', 'tag__tag_name', 'name', 'content'):
            group_index[group_id] = (tag_name, name)
            members_by_tag[tag_name][name].update(to_hashable(item) for item in content or ())
            level_ids.append(group_id)
        if not level_ids:
            break

        child_ids = set()
        edges = PlayflowsTagGroup.children.through.objects.filter(from_playflowstaggroup_id__in=level_ids).values_list(
            'from_playflowstaggroup_id', 'to_playflowstaggroup_id'
        )
        for parent_id, child_id in edges:
            child_ids.add(child_id)
            subgroups_by_tag[group_index[parent_id][0]][group_index[parent_id][1]].add(child_id)

        pending_ids = child_ids - group_index.keys()
        if not pending_ids:
            break
        level_queryset = PlayflowsTagGroup.objects.filter(id__in=pending_ids)

    group_maps_by_tag = {}
    for tag_name, members_by_group in members_by_tag.items():
        subgroups_by_group = {
            parent_name: {group_index[child_id][1] for child_id in child_ids}
            for parent_name, child_ids in subgroups_by_tag[tag_name].items()
        }
        # content may also list subgroup names; keep them only as subgroups
        members_by_group = {
            name: members - subgroups_by_group.get(name, set())
            for name, members in members_by_group.items()
        }
        group_maps_by_tag[tag_name] = build_group_map(root_group, members_by_group, subgroups_by_group)
    return group_maps_by_tag


def build_group_map(root_group, members_by_group, subgroups_by_group):
    """Return {group_name: {'members': set, 'subgroups': set}} for every group reachable from root_group."""
    group_map = {}
    pending = [root_group]
    while pending:
        group_name = pending.pop()
        if group_name in group_map:
            continue
        subgroups = set(subgroups_by_group.get(group_name, ()))
        group_map[group_name] = {
            'members': set(members_by_group.get(group_name, ())),
            'subgroups': subgroups,
        }
        pending.extend(subgroups - group_map.keys())
    return group_map


def diff_group_maps(root_group, reference_map, target_map):
    """Return one row per group whose direct content differs between reference_map and target_map.

    subgroup_path is the path from root_group (empty for root_group itself). A subgroup present
    on only one side is reported in added_subgroups/missing_subgroups of its parent and is not
    walked further. Shared subgroups are walked once, through their shortest path.
    """
    rows = []
    visited = set()
    pending = deque([(root_group, ())])
    while pending:
        group_name, subgroup_path = pending.popleft()
        if group_name in visited:
            continue
        visited.add(group_name)

        reference = reference_map[group_name]
        target = target_map[group_name]
        row = {
            'subgroup_path': subgroup_path,
            'added_values': sorted(target['members'] - reference['members']),
            'missing_values': sorted(reference['members'] - target['members']),
            'added_subgroups': sorted(target['subgroups'] - reference['subgroups']),
            'missing_subgroups': sorted(reference['subgroups'] - target['subgroups']),
        }
        if row['added_values'] or row['missing_values'] or row['added_subgroups'] or row['missing_subgroups']:
            rows.append(row)

        for child_name in sorted(reference['subgroups'] & target['subgroups']):
            pending.append((child_name, subgroup_path + (child_name,)))
    return rows


def build_alignment_commands(fw_tag, root_group, differences):
    """Return the Playflows commands that make the groups of fw_tag match the reference, one per line.

    Uses the long syntax with a target POLICYTAGNAME. Adds go first so no group is left empty,
    and subgroups and nodes are sent in separate commands.
    """
    add_commands = []
    rm_commands = []
    for row in differences:
        group_name = row['subgroup_path'][-1] if row['subgroup_path'] else root_group
        target_group = f'{fw_tag}:{group_name}'
        for values in (row['missing_subgroups'], row['missing_values']):
            if values:
                add_commands.append(f'add to {target_group} {" ".join(values)}')
        for values in (row['added_subgroups'], row['added_values']):
            if values:
                rm_commands.append(f'rm from {target_group} {" ".join(values)}')
    return '\n'.join(add_commands + rm_commands)


def compare_group_across_firewalls(root_group, reference_tag, group_maps_by_tag):
    """Return one entry per firewall tag: reference first, then tags with differences, then identical tags."""
    reference_map = group_maps_by_tag[reference_tag]
    firewalls = []
    for fw_tag in sorted(group_maps_by_tag):
        if fw_tag == reference_tag:
            continue
        differences = diff_group_maps(root_group, reference_map, group_maps_by_tag[fw_tag])
        firewalls.append({
            'fw_tag': fw_tag,
            'is_reference': False,
            'differences': differences,
            'added_count': sum(len(row['added_values']) + len(row['added_subgroups']) for row in differences),
            'missing_count': sum(len(row['missing_values']) + len(row['missing_subgroups']) for row in differences),
            'alignment_commands': build_alignment_commands(fw_tag, root_group, differences),
        })
    firewalls.sort(key=lambda firewall: not firewall['differences'])

    reference = {
        'fw_tag': reference_tag,
        'is_reference': True,
        'differences': [],
        'added_count': 0,
        'missing_count': 0,
        'alignment_commands': '',
    }
    return [reference] + firewalls


@login_required
@user_passes_test(user_can_change_firewall)
def ajax_load_data_group_comparator(request):
    group_name = request.GET.get('group_name', '').strip()
    reference_tag = request.GET.get('tag_name', '').strip()

    group_maps_by_tag = load_group_maps_by_tag(group_name) if group_name and reference_tag else {}
    firewalls = []
    if reference_tag in group_maps_by_tag:
        firewalls = compare_group_across_firewalls(group_name, reference_tag, group_maps_by_tag)

    context = {
        'firewalls': firewalls,
        'differing_count': sum(1 for firewall in firewalls if firewall['differences']),
        'group_name': group_name,
        'reference_tag': reference_tag,
    }
    return render(request, 'tools/firewall_components/group_comparator_component.html', context)
