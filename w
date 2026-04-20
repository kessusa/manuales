groups_info = data[0].get('groups', {}).get(tag_name, {}).get('upcoming', {}).get('members-of', {})
name_to_values = data[0].get('name-to-values', {}).get(tag_name, {}).get('upcoming', {})

groups_with_content = {}
address_map = name_to_values.get('address', {})
service_map = name_to_values.get('service', {})

def resolve_group_members(member_names, visited=None):
    """Resuelve recursivamente miembros: direcciones directas + grupos anidados + servicios."""
    if visited is None:
        visited = set()

    resolved_content = []
    has_ip = False
    has_service = False

    for member in member_names:
        if member in visited:
            continue
        visited.add(member)

        # 1) Dirección directa
        if member in address_map:
            resolved_content.extend(address_map[member].keys())
            has_ip = True

        # 2) Grupo anidado -> recursión
        elif member in groups_info:
            nested_members = list(groups_info[member].keys())
            nested_type, nested_content = resolve_group_members(nested_members, visited)
            if nested_content:
                resolved_content.extend(nested_content)
                if nested_type == 'ip':
                    has_ip = True
                elif nested_type == 'service':
                    has_service = True

        # 3) Servicio
        elif member in service_map:
            for service_key in service_map[member].keys():
                clean_service = service_key[2:] if service_key.startswith('S_') else service_key
                resolved_content.append(clean_service)
            has_service = True

    if has_ip:
        resolved_type = 'ip'
    elif has_service:
        resolved_type = 'service'
    else:
        resolved_type = 'unknown'

    return resolved_type, resolved_content

for group_name, members in groups_info.items():
    if not members:
        groups_with_content[group_name] = {
            'type': 'unknown',
            'content': None,
            'original_members': [],
            'resolved': False,
            'is_nested': False,
        }
        continue

    member_names = list(members.keys())
    content_type, content = resolve_group_members(member_names)

    if content:
        content = sorted(set(content))

    groups_with_content[group_name] = {
        'type': content_type,
        'content': content if content else None,
        'original_members': member_names,
        'resolved': bool(content),
        'is_nested': any(m in groups_info for m in member_names),
    }

return groups_with_content
