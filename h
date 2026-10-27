GROUP_COMPARATOR_CSV_HEADER = ['FW tag', 'Subgroup', 'Added value', 'Missing value']


def build_group_comparator_csv_rows(firewalls):
    """One CSV row per difference; firewalls without differences (and the reference) get one empty row."""
    for firewall in firewalls:
        if not firewall['differences']:
            yield [firewall['fw_tag'], 'N/A', '', '']
            continue
        for row in firewall['differences']:
            yield [
                firewall['fw_tag'],
                ' > '.join(row['subgroup_path']) or 'N/A',
                ', '.join(row['added_subgroups'] + row['added_values']),
                ', '.join(row['missing_subgroups'] + row['missing_values']),
            ]
