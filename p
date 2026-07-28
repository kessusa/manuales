# =============================================================================
# API_cnx/playflows.py - PlayflowsAPI.get_groups_with_content
# Replaces the flattening logic so the group hierarchy is preserved in DB.
# resolve_group_members becomes unused and can be removed (**To Be Removed).
# =============================================================================

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

    groups_with_content = {}
    address_map = name_to_values.get('address', {})
    service_map = name_to_values.get('service', {})

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
        content = []
        has_ip = False
        has_service = False
        has_subgroup = False

        for member in member_names:
            if member in groups_info:
                # Subgroup: keep the NAME so the hierarchy is preserved.
                # The subgroup gets its own PlayflowsTagGroup row and link,
                # so the view resolves it recursively at read time.
                content.append(member)
                has_subgroup = True
            elif member in address_map:
                content.extend(address_map[member].keys())
                has_ip = True
            elif member in service_map:
                for service_key in service_map[member].keys():
                    clean_service = (
                        service_key[2:]
                        if service_key.startswith('S_') else service_key
                    )
                    content.append(clean_service)
                has_service = True

        if has_ip or (has_subgroup and not has_service):
            group_type = 'ip'
        elif has_service:
            group_type = 'service'
        else:
            group_type = 'unknown'

        groups_with_content[group_name] = {
            'type': group_type,
            'content': sorted(set(content)) if content else None,
            'original_members': member_names,
            'resolved': bool(content),
            'is_nested': has_subgroup,
        }

    return groups_with_content
