@register.filter
def filter_min_position_open(data, fw_and_node_info):
    """
    Para cada flujo único (fw_tag, port, source_ip, destination_ip),
    encuentra la regla con la posición más baja (la que el firewall aplicará primero).
    Luego agrupa los resultados por (fw_tag, port) para la visualización,
    y genera to_code para las reglas con acción 'drop'.
    """
    if not fw_and_node_info:
        fw_and_node_info = {}

    # Paso 1: Para cada flujo único, encontrar la regla de posición mínima
    flow_min = {}  # key: (fw_tag, port, s_ip, d_ip) -> regla con menor posición

    for item in data:
        current_fw_tag = item.get('tag')
        current_port = item.get('port')
        s_ip = item.get('source_ip')
        d_ip = item.get('destination_ip')

        # Verificar si el firewall tag coincide con el dueño del source o destination
        owner_fw_src = fw_and_node_info.get(s_ip, {}).get('firewall_misc', "").strip()
        owner_fw_dst = fw_and_node_info.get(d_ip, {}).get('firewall_misc', "").strip()

        if current_fw_tag != owner_fw_src and current_fw_tag != owner_fw_dst:
            continue

        # Convertir posición a entero
        try:
            current_position = int(item.get('position', 0))
        except (ValueError, TypeError):
            current_position = 0

        flow_key = (current_fw_tag, current_port, s_ip, d_ip)

        if flow_key not in flow_min or current_position < flow_min[flow_key]['position']:
            flow_min[flow_key] = {
                'position': current_position,
                'action': item.get('action'),
                'section': item.get('section'),
                'comment': item.get('comment'),
                'id': item.get('id'),
                'tag': current_fw_tag,
                'port': current_port,
                's_ip': s_ip,
                'd_ip': d_ip,
                'source_node_name': item.get('source_node_name'),
                'destination_node_name': item.get('destination_node_name'),
            }

    # Paso 2: Agrupar por (fw_tag, port) para visualización
    display_groups = {}  # key: (fw_tag, port) -> datos agrupados

    for flow_key, rule in flow_min.items():
        fw_tag, port = rule['tag'], rule['port']
        group_key = (fw_tag, port)

        if group_key not in display_groups:
            display_groups[group_key] = {
                'tag': fw_tag,
                'port': port,
                'position': rule['position'],
                'action': rule['action'],
                'section': rule['section'],
                'comment': rule['comment'],
                'id': rule['id'],
                'source': [],
                'destination': [],
                '_source_ips_seen': set(),
                '_dest_ips_seen': set(),
            }

        group = display_groups[group_key]

        # Si esta regla tiene posición menor, reemplazar todo
        if rule['position'] < group['position']:
            group['position'] = rule['position']
            group['action'] = rule['action']
            group['section'] = rule['section']
            group['comment'] = rule['comment']
            group['id'] = rule['id']
            group['source'] = [{'ip': rule['s_ip'], 'node_name': rule['source_node_name']}]
            group['destination'] = [{'ip': rule['d_ip'], 'node_name': rule['destination_node_name']}]
            group['_source_ips_seen'] = {rule['s_ip']}
            group['_dest_ips_seen'] = {rule['d_ip']}

        elif rule['position'] == group['position']:
            # Misma posición mínima: agregar IPs sin duplicar
            if rule['s_ip'] not in group['_source_ips_seen']:
                group['_source_ips_seen'].add(rule['s_ip'])
                group['source'].append({'ip': rule['s_ip'], 'node_name': rule['source_node_name']})

            if rule['d_ip'] not in group['_dest_ips_seen']:
                group['_dest_ips_seen'].add(rule['d_ip'])
                group['destination'].append({'ip': rule['d_ip'], 'node_name': rule['destination_node_name']})

    # Paso 3: Construir to_code para reglas con acción 'drop'
    to_code = {}

    for group in display_groups.values():
        if group['action'] == 'drop' and group['tag']:
            fw_tag = group['tag']
            if fw_tag not in to_code:
                to_code[fw_tag] = {
                    'sources': set(),
                    'destinations': set(),
                    'services': set(),
                }
            # Agregar TODAS las IPs, no solo la primera
            for src in group['source']:
                to_code[fw_tag]['sources'].add(src['ip'])
            for dst in group['destination']:
                to_code[fw_tag]['destinations'].add(dst['ip'])
            to_code[fw_tag]['services'].add(group['port'])

    # Paso 4: Preparar resultado final
    result = []
    for group in display_groups.values():
        # Eliminar sets auxiliares y convertir posición a string
        group.pop('_source_ips_seen', None)
        group.pop('_dest_ips_seen', None)
        group['position'] = str(group['position'])
        result.append(group)

    return {
        'filtered_items': result,
        'to_code': {
            tag: {
                'sources': list(details['sources']),
                'destinations': list(details['destinations']),
                'services': list(details['services']),
            }
            for tag, details in to_code.items()
        },
    }
