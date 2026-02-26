min_flow_result = {}

for item in (i for i in result if i['type'] == 'match-flow'):
    flow_parts = item['flow'].split()
    if len(flow_parts) != 3:
        continue

    source_ip, destination_ip, port = flow_parts
    source_ip = normalize_ip(source_ip)
    destination_ip = normalize_ip(destination_ip)
    current_fw_tag = item['tag']

    # Skip if this firewall doesn't own source or destination
    owner_fw_src = fw_and_node_info.get(source_ip, {}).get('firewall_misc', '')
    owner_fw_dst = fw_and_node_info.get(destination_ip, {}).get('firewall_misc', '')
    if current_fw_tag not in (owner_fw_src, owner_fw_dst):
        continue

    flow = (item['flow'], item['tag'])
    position = int(item['position'])

    if flow not in min_flow_result or position < int(min_flow_result[flow]['position']):
        min_flow_result[flow] = {
            **item,
            'source_ip': source_ip,
            'source_node_name': fw_and_node_info[source_ip]['node_normalization'],
            'destination_ip': destination_ip,
            'destination_node_name': fw_and_node_info[destination_ip]['node_normalization'],
            'port': port
        }
