# 04_manage_crs_signatures.py
import argparse
from avi_client import get_session, filter_policies, backup_policy

def list_crs_groups(policy_filter=None):
    """Lista los nombres exactos de los grupos CRS disponibles en las políticas"""
    api = get_session()
    policies = filter_policies(api, policy_filter)
    if not policies:
        print("[-] No se encontraron políticas.")
        return

    p = policies[0]
    print(f"[*] Grupos CRS disponibles (basado en la política '{p['name']}'):")
    if p.get("crs_groups"):
        for g in p["crs_groups"]:
            print(f"  • {g['name']} ({len(g.get('rules', []))} reglas)")
    elif p.get("waf_crs_ref"):
        crs_uuid = p["waf_crs_ref"].split("/")[-1]
        crs_catalog = api.get(f"wafcrs/{crs_uuid}").json()
        for g in crs_catalog.get("groups", []):
            print(f"  • {g['name']} ({len(g.get('rules', []))} reglas)")

def update_crs_signatures(groups=None, rules=None, enable=True, mode="WAF_MODE_ENFORCEMENT", policy_filter=None, dry_run=False):
    api = get_session()
    policies = filter_policies(api, policy_filter)
    target_groups = set(groups or [])
    target_rules = set(str(r) for r in (rules or []))
    crs_cache = {}

    for p in policies:
        changed = False

        # ---------------------------------------------------------------------
        # CASO A: Estructura crs_groups antigua (embebida en la política)
        # ---------------------------------------------------------------------
        if p.get("crs_groups"):
            for g in p["crs_groups"]:
                if g["name"] in target_groups:
                    g["enable"] = enable
                    for r in g.get("rules", []):
                        r["enable"] = enable
                        if mode == "POLICY_MODE":
                            r.pop("mode", None) # Al borrar 'mode', hereda el Policy Mode
                        else:
                            r["mode"] = mode
                    changed = True
                    print(f"  [*] '{p['name']}' -> Grupo '{g['name']}' pasado a {mode} (Enable={enable})")

                for r in g.get("rules", []):
                    if str(r.get("rule_id")) in target_rules:
                        if enable:
                            g["enable"] = True
                        r["enable"] = enable
                        if mode == "POLICY_MODE":
                            r.pop("mode", None)
                        else:
                            r["mode"] = mode
                        changed = True
                        print(f"  [*] '{p['name']}' -> Regla {r['rule_id']} pasada a {mode} (Enable={enable})")

        # ---------------------------------------------------------------------
        # CASO B: Estructura crs_overrides moderna (Avi 22.1+)
        # ---------------------------------------------------------------------
        else:
            if not p.get("waf_crs_ref"):
                continue

            crs_uuid = p["waf_crs_ref"].split("/")[-1]
            if crs_uuid not in crs_cache:
                crs_cache[crs_uuid] = api.get(f"wafcrs/{crs_uuid}").json()

            crs_catalog = crs_cache[crs_uuid]
            overrides = p.setdefault("crs_overrides", [])

            for cg in crs_catalog.get("groups", []):
                g_name = cg["name"]
                is_target_group = g_name in target_groups

                if is_target_group:
                    rules_to_override = [str(r["rule_id"]) for r in cg.get("rules", [])]
                else:
                    rules_to_override = [
                        str(r["rule_id"]) for r in cg.get("rules", [])
                        if str(r.get("rule_id")) in target_rules
                    ]

                if not is_target_group and not rules_to_override:
                    continue

                ov = next((o for o in overrides if o.get("name") == g_name), None)
                if not ov:
                    if mode == "POLICY_MODE" and enable:
                        # Si no había override y pedimos volver a Policy Mode + Enable, ya está por defecto
                        continue
                    ov = {"name": g_name, "rule_overrides": []}
                    overrides.append(ov)

                if is_target_group:
                    ov["enable"] = enable
                elif enable:
                    ov["enable"] = True

                r_ovs = ov.setdefault("rule_overrides", [])
                for rid in rules_to_override:
                    rov = next((x for x in r_ovs if str(x.get("rule_id")) == rid), None)
                    
                    if mode == "POLICY_MODE":
                        if rov:
                            # Eliminamos la clave 'mode' para devolver la firma a Policy Mode
                            rov.pop("mode", None)
                            rov["enable"] = enable
                            # Si la firma queda en enable=True y no tiene exclude_list, podemos limpiar el override redundante
                            if enable and not rov.get("exclude_list"):
                                r_ovs.remove(rov)
                    else:
                        if not rov:
                            rov = {"rule_id": rid}
                            r_ovs.append(rov)
                        rov["enable"] = enable
                        rov["mode"] = mode

                changed = True
                print(f"  [*] '{p['name']}' -> Grupo '{g_name}': {len(rules_to_override)} firmas ajustadas a {mode} (Enable={enable})")

        if not changed:
            print(f"[-] '{p['name']}': Sin cambios necesarios.")
            continue

        if dry_run:
            print(f"[DRY-RUN] Cambios preparados en '{p['name']}'")
            continue

        bkp = backup_policy(p)
        resp = api.put(f"wafpolicy/{p['uuid']}", data=p)
        if resp.status_code == 200:
            print(f"[+] Política '{p['name']}' actualizada -> HTTP 200 (Backup: {bkp})")
        else:
            print(f"[!] Error en '{p['name']}': HTTP {resp.status_code} - {resp.text}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modifica estado y modo de grupos o firmas CRS")
    parser.add_argument("--list-groups", action="store_true", help="Lista los nombres exactos de los grupos CRS y sale")
    parser.add_argument("--groups", nargs="+", help="Nombres de los grupos CRS")
    parser.add_argument("--rules", nargs="+", help="IDs de las reglas CRS")
    parser.add_argument("--disable", action="store_true", help="Deshabilitar en lugar de habilitar")
    parser.add_argument(
        "--mode",
        default="WAF_MODE_ENFORCEMENT",
        choices=["WAF_MODE_ENFORCEMENT", "WAF_MODE_DETECTION_ONLY", "POLICY_MODE"],
        help="Modo de las firmas (usa POLICY_MODE para devolverlas al modo que hereden de la política)"
    )
    parser.add_argument("--filter", help="Filtrar por nombre de política")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.list_groups:
        list_crs_groups(args.filter)
    else:
        update_crs_signatures(args.groups, args.rules, not args.disable, args.mode, args.filter, args.dry_run)
