# 02_audit_waf_overrides.py
import json
import argparse
from avi_client import get_session, filter_policies

def print_exclude_list(exclude_list, indent="          "):
    """Desglosa de forma legible todos los parámetros de un bloque exclude_list de Avi"""
    for idx, exc in enumerate(exclude_list, 1):
        mc = exc.get("match_criteria", {})
        uri_str = f"{mc.get('match_op', 'CONTAINS')} '{mc.get('uri_path', '*')}'" if "uri_path" in mc else "Cualquier URI"
        ip_str = ""
        if "client_ip" in mc:
            addrs = [a.get("addr") for a in mc["client_ip"].get("addrs", [])]
            prefixes = [f"{p['ip_addr']['addr']}/{p['mask']}" for p in mc["client_ip"].get("prefixes", [])]
            ip_str = f" | IPs: {', '.join(addrs + prefixes)}"

        elems = []
        for el in exc.get("uri_match_elements", []):
            e_type = el.get("name", "PARAM") # ARGS, REQUEST_HEADERS, REQUEST_COOKIES, etc.
            e_sub = el.get("sub_element", "*")
            e_op = el.get("match_op", "EQUALS")
            excluded = " [EXCLUIDO]" if el.get("excluded") else ""
            elems.append(f"{e_type}:{e_sub} ({e_op}){excluded}")

        elem_str = ", ".join(elems) if elems else "Toda la petición (Rule Bypass en esa URI/IP)"
        print(f"{indent}[Exclusión #{idx}] Condición URI: {uri_str}{ip_str}")
        print(f"{indent}               Elementos excluidos: {elem_str}")

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
                print(f"    • Grupo: {g['name']} | Activo: {g.get('enable', True)}")
                if g.get("exclude_list"):
                    print(f"      Exclusiones a nivel de grupo ({len(g['exclude_list'])}):")
                    if details:
                        print_exclude_list(g["exclude_list"], indent="        ")
                for r in g.get("rules", []):
                    if rule_filter and str(r.get("rule_id")) != str(rule_filter):
                        continue
                    print(f"       └── Regla {r.get('rule_id')} ({r.get('name')}) | Enable: {r.get('enable')} | Mode: {r.get('mode', 'POLICY_MODE')}")
                    if details and r.get("rule"):
                        print(f"           SecRule: {r.get('rule').strip()}")
                    if r.get("exclude_list"):
                        print_exclude_list(r["exclude_list"], indent="           ")
                    if raw_json:
                        print("           JSON:", json.dumps(r, indent=2).replace("\n", "\n           "))

        # 2. CRS OVERRIDES (Esquema moderno Avi 22.1+)
        crs_overrides = p.get("crs_overrides", [])
        if crs_overrides:
            print(f"\n  [CRS Overrides configurados]: {len(crs_overrides)} grupos con cambios")
            for ov in crs_overrides:
                g_name = ov.get("name", "N/A")
                if group_filter and group_filter.lower() not in g_name.lower():
                    continue

                g_enable = ov.get("enable", "Por defecto (True)")
                g_excl = ov.get("exclude_list", [])
                print(f"\n    • GRUPO CRS: {g_name} | Enable Override: {g_enable} | Exclusiones de Grupo: {len(g_excl)}")

                if details and g_excl:
                    print_exclude_list(g_excl, indent="        ")

                if raw_json and not rule_filter:
                    print("      [RAW GROUP OVERRIDE JSON]:")
                    print("      " + json.dumps(ov, indent=2).replace("\n", "\n      "))

                for r_ov in ov.get("rule_overrides", []):
                    r_id = r_ov.get("rule_id")
                    if rule_filter and str(r_id) != str(rule_filter):
                        continue

                    r_en = r_ov.get("enable", "Por defecto (True)")
                    r_mode = r_ov.get("mode", "POLICY_MODE (Heredado)")
                    r_excl = r_ov.get("exclude_list", [])
                    print(f"       └── Firma ID {r_id} -> Enable: {r_en} | Mode: {r_mode} | Exclusiones: {len(r_excl)}")

                    if details and r_excl:
                        print_exclude_list(r_excl, indent="             ")

                    if raw_json:
                        print("             [RAW RULE OVERRIDE JSON]:")
                        print("             " + json.dumps(r_ov, indent=2).replace("\n", "\n             "))

        # 3. CRS GROUPS EMBEBIDOS (Esquema antiguo Avi <= 21.1)
        elif p.get("crs_groups"):
            print("\n  [CRS Groups (Árbol directo - Mostrando grupos/reglas modificados)]:")
            for g in p.get("crs_groups", []):
                if group_filter and group_filter.lower() not in g["name"].lower():
                    continue
                g_modified = not g.get("enable", True) or bool(g.get("exclude_list"))
                modified_rules = [
                    r for r in g.get("rules", [])
                    if (not r.get("enable", True) or r.get("mode") or r.get("exclude_list"))
                    and (not rule_filter or str(r.get("rule_id")) == str(rule_filter))
                ]

                if not g_modified and not modified_rules:
                    continue

                print(f"\n    • GRUPO CRS: {g['name']} | Enable: {g.get('enable', True)} | Exclusiones de Grupo: {len(g.get('exclude_list', []))}")
                if details and g.get("exclude_list"):
                    print_exclude_list(g["exclude_list"], indent="        ")

                for r in modified_rules:
                    r_excl = r.get("exclude_list", [])
                    print(f"       └── Firma ID {r['rule_id']} ({r.get('name')}) -> Enable: {r.get('enable')} | Mode: {r.get('mode', 'POLICY_MODE')} | Exclusiones: {len(r_excl)}")
                    if details and r_excl:
                        print_exclude_list(r_excl, indent="             ")
                    if raw_json:
                        print("             " + json.dumps(r, indent=2).replace("\n", "\n             "))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Obtiene los overrides, exclusiones detalladas y JSON completo de políticas WAF")
    parser.add_argument("--filter", help="Filtrar por nombre de política WAF")
    parser.add_argument("--group", help="Filtrar por nombre de grupo CRS (ej. 942 o SQLi)")
    parser.add_argument("--rule", help="Filtrar por un ID de firma específico (ej. 942100)")
    parser.add_argument("--details", action="store_true", help="Desglosa todas las condiciones URI/IP/Parámetros de cada exclusión y muestra la SecRule")
    parser.add_argument("--raw-json", action="store_true", help="Imprime el bloque JSON exacto del override tal y como lo guarda Avi")
    args = parser.parse_args()

    audit_overrides(args.filter, args.group, args.rule, args.details, args.raw_json)
