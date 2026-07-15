from collections import defaultdict

def per_device_mapping_table(region):
    qs = (FirewallRule.objects            # <- tu modelo de reglas (el del obj_list)
          .filter(tag__region=region, tag__deleted=False)
          .select_related("tag")
          .only("rule_id", "section", "per_device_mapping",
                "tag__tag_name", "tag__domain"))

    # domain -> firewall -> datos
    adoms = defaultdict(lambda: defaultdict(lambda: {
        "policies": set(), "objects": set(), "rules": [],
    }))

    for r in qs:
        groups = (r.per_device_mapping or {}).get("groups") or []
        if not groups:
            continue
        fw = adoms[r.tag.domain or "—"][r.tag.tag_name]
        fw["policies"].add(r.section)
        fw["objects"].update(groups)
        fw["rules"].append(f"{r.section}:ID:{r.rule_id}")

    table = []
    for domain, firewalls in sorted(adoms.items()):
        rows = []
        adom_objects = set()
        for fw_name, d in sorted(firewalls.items()):
            adom_objects |= d["objects"]
            rows.append({
                "firewall": fw_name,
                "policies": sorted(d["policies"]),
                "objects": sorted(d["objects"]),
                "rules": d["rules"],
                "count_per_firewall": len(d["objects"]),
            })
        table.append({
            "adom": domain,
            "rows": rows,
            "count_per_adom": len(adom_objects),   # objetos distintos en todo el ADOM
        })
    return table
