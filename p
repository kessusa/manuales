# 02_audit_waf_overrides.py
import json
import argparse
from avi_client import get_session, filter_policies


def format_subnet(subnet_obj):
    """Formatea el objeto client_subnet de Avi: {'ip_addr': {'addr': '10.0.0.0', 'type': 'V4'}, 'mask': 24}"""
    if not subnet_obj:
        return "Cualquiera (All IPs)"
    ip_addr = subnet_obj.get("ip_addr", {}).get("addr", "N/A")
    ip_type = subnet_obj.get("ip_addr", {}).get("type", "V4")
    mask = subnet_obj.get("mask", 32)
    return f"{ip_addr}/{mask} ({ip_type})"


def print_exclude_list(exclude_list, indent="          "):
    """Desglosa todos los campos reales de WafExcludeListEntry en la API de Avi"""
    for idx, exc in enumerate(exclude_list, 1):
        # 1. Subnet / IP origen
        client_subnet = exc.get("client_subnet")
        subnet_str = format_subnet(client_subnet)

        # 2. URI Path y sus criterios (match_op, match_case)
        uri_path = exc.get("uri_path")
        uri_crit = exc.get("uri_match_criteria", {})
        uri_op = uri_crit.get("match_op", "EQUALS (Default)")
        uri_case = uri_crit.get("match_case", "INSENSITIVE (Default)")

        # 3. Match Element (ARGS, REQUEST_HEADERS, etc.) y sus criterios
        match_elem = exc.get("match_element")
        elem_crit = exc.get("match_element_criteria", {})
        elem_op = elem_crit.get("match_op", "EQUALS (Default)")
        elem_case = elem_crit.get("match_case", "INSENSITIVE (Default)")

        # 4. Descripción / metadatos
        desc = exc.get("description", "")

        print(f"{indent}┌── [Exclusión #{idx}] {f'({desc})' if desc else ''}")
        print(f"{indent}│   • Client Subnet          : {subnet_str}")

        if uri_path is not None or uri_crit:
            print(f"{indent}│   • URI Path               : '{uri_path if uri_path is not None else '*'}'")
            print(f"{indent}│   • URI Match Criteria     : match_op={uri_op} | match_case={uri_case}")
        else:
            print(f"{indent}│   • URI Path               : Cualquiera (No filtrado por URI)")

        if match_elem is not None or elem_crit:
            print(f"{indent}│   • Match Element          : '{match_elem if match_elem is not None else '*'}'")
            print(f"{indent}│   • Element Match Criteria : match_op={elem_op} | match_case={elem_case}")
        else:
            print(f"{indent}│   • Match Element          : Toda la petición / Firma completa (Bypass total)")

        # Si hubiera algún otro campo extra según la versión de Avi, lo imprimimos también
        known_keys = {
            "client_subnet", "uri_path", "uri_match_criteria",
            "match_element", "match_element_criteria", "description"
        }
        extra_keys = {k: v for k, v in exc.items() if k not in known_keys}
        if extra_keys:
            print(f"{indent}│   • Campos adicionales     : {json.dumps(extra_keys)}")
        print(f"{indent}└──────────────────────────────────────────────────────────")


def print_tags_and_params(obj, indent="             "):
    """Muestra qué campos específicos se han modificado en el override de grupo o regla"""
    known_ignore = {"name", "rule_id", "rule_overrides", "exclude_list", "rules", "index"}
    changed_fields = {k: v for k, v in obj.items() if k not in known_ignore}
    if changed_fields:
        fields_str = " | ".join(f"{k}: {v}" for k, v in changed_fields.items())
        print(f"{indent}Campos configurados en Override -> [ {fields_str} ]")


def audit_overrides(policy_filter=None, group_filter=None, rule_filter=None, details=False, raw_json=False):
    api = get_session()
    policies = filter_policies(api, policy_filter)

    for p in policies:
        print(f"\n======================================================================")
        print(f"POLÍTICA: {p['name']} (UUID: {p['uuid']})")
        print(f"Modo Global: {p.get('mode')} | Paranoia: {p.get('paranoia_level')} | Delegación: {p.get('allow_mode_delegation', False)}")
        print(f"======================================================================")

        # 1. REGLAS PRE-CRS Y POST-CRS
        for stage_key, stage_label in [("pre_crs_groups", "Pre-CRS"), ("post_crs_groups", "Post-CRS")]:
            groups = p.get(stage_key, [])
            if not groups:
                continue
            print(f"\n  [{stage_label} Groups]: {len(groups)}")
            for g in groups:
                if group_filter and group_filter.lower() not in g["name"].lower():
                    continue
                g_excl = g.get("exclude_list", [])
                print(f"    • Grupo: {g['name']} | Enable: {g.get('enable', True)} | Exclusiones de Grupo: {len(g_excl)}")
                if details and g_excl:
                    print_exclude_list(g_excl, indent="        ")

                for r in g.get("rules", []):
                    if rule_filter and str(r.get("rule_id")) != str(rule_filter):
                        continue
                    r_excl = r.get("exclude_list", [])
                    print(f"       └── Regla ID {r.get('rule_id')} ({r.get('name')}) | Enable: {r.get('enable')} | Mode: {r.get('mode', 'POLICY_MODE')} | Exclusiones: {len(r_excl)}")
                    if details:
                        if r.get("rule"):
                            print(f"             SecRule: {r.get('rule').strip()}")
                        if r_excl:
                            print_exclude_list(r_excl, indent="             ")
                    if raw_json:
                        print("             [RAW JSON]:\n             " + json.dumps(r, indent=2).replace("\n", "\n             "))

        # 2. CRS OVERRIDES (Esquema moderno Avi 22.1+)
        crs_overrides = p.get("crs_overrides", [])
        if crs_overrides:
            print(f"\n  [CRS Overrides configurados]: {len(crs_overrides)} grupos con overrides")
            for ov in crs_overrides:
                g_name = ov.get("name", "N/A")
                if group_filter and group_filter.lower() not in g_name.lower():
                    continue

                g_enable = ov.get("enable", "Heredado (True)")
                g_excl = ov.get("exclude_list", [])
                print(f"\n    • GRUPO CRS: {g_name} | Enable: {g_enable} | Exclusiones de Grupo: {len(g_excl)}")

                if details:
                    print_tags_and_params(ov, indent="        ")
                    if g_excl:
                        print_exclude_list(g_excl, indent="        ")

                if raw_json and not rule_filter:
                    print("      [RAW GROUP OVERRIDE JSON]:\n      " + json.dumps(ov, indent=2).replace("\n", "\n      "))

                for r_ov in ov.get("rule_overrides", []):
                    r_id = r_ov.get("rule_id")
                    if rule_filter and str(r_id) != str(rule_filter):
                        continue

                    r_en = r_ov.get("enable", "Heredado (True)")
                    r_mode = r_ov.get("mode", "POLICY_MODE (Heredado)")
                    r_excl = r_ov.get("exclude_list", [])
                    print(f"       └── Firma ID {r_id} -> Enable: {r_en} | Mode: {r_mode} | Exclusiones: {len(r_excl)}")

                    if details:
                        print_tags_and_params(r_ov, indent="             ")
                        if r_excl:
                            print_exclude_list(r_excl, indent="             ")

                    if raw_json:
                        print("             [RAW RULE OVERRIDE JSON]:\n             " + json.dumps(r_ov, indent=2).replace("\n", "\n             "))

        # 3. CRS GROUPS EMBEBIDOS (Esquema antiguo Avi <= 21.1)
        elif p.get("crs_groups"):
            print("\n  [CRS Groups (Árbol directo - Mostrando grupos/reglas con cambios o exclusiones)]:")
            for g in p.get("crs_groups", []):
                if group_filter and group_filter.lower() not in g["name"].lower():
                    continue
                g_excl = g.get("exclude_list", [])
                g_modified = not g.get("enable", True) or bool(g_excl)
                modified_rules = [
                    r for r in g.get("rules", [])
                    if (not r.get("enable", True) or r.get("mode") or r.get("exclude_list"))
                    and (not rule_filter or str(r.get("rule_id")) == str(rule_filter))
                ]

                if not g_modified and not modified_rules:
                    continue

                print(f"\n    • GRUPO CRS: {g['name']} | Enable: {g.get('enable', True)} | Exclusiones de Grupo: {len(g_excl)}")
                if details and g_excl:
                    print_exclude_list(g_excl, indent="        ")

                for r in modified_rules:
                    r_excl = r.get("exclude_list", [])
                    print(f"       └── Firma ID {r['rule_id']} ({r.get('name')}) -> Enable: {r.get('enable')} | Mode: {r.get('mode', 'POLICY_MODE')} | Exclusiones: {len(r_excl)}")
                    if details and r_excl:
                        print_exclude_list(r_excl, indent="             ")
                    if raw_json:
                        print("             [RAW RULE JSON]:\n             " + json.dumps(r, indent=2).replace("\n", "\n             "))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audita overrides y muestra todos los parámetros de cada excepción WAF")
    parser.add_argument("--filter", help="Filtrar por nombre de política WAF")
    parser.add_argument("--group", help="Filtrar por nombre de grupo CRS (ej. 942 o SQLi)")
    parser.add_argument("--rule", help="Filtrar por un ID de firma específico (ej. 942100)")
    parser.add_argument("--details", action="store_true", help="Muestra client_subnet, uri_path, uri_match_criteria, match_element y match_element_criteria")
    parser.add_argument("--raw-json", action="store_true", help="Imprime el JSON puro devuelto por Avi para cada override")
    args = parser.parse_args()

    audit_overrides(args.filter, args.group, args.rule, args.details, args.raw_json)
