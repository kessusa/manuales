# 04_manage_crs_signatures.py
import argparse
from avi_client import get_session, filter_policies, backup_policy

def update_crs_signatures(groups=None, rules=None, enable=True, mode="WAF_MODE_ENFORCEMENT", policy_filter=None, dry_run=False):
    api = get_session()
    policies = filter_policies(api, policy_filter)
    target_groups = set(groups or [])
    target_rules = set(str(r) for r in (rules or []))

    # Caché del catálogo CRS para no hacer múltiples GET al mismo objeto wafcrs
    crs_cache = {}

    for p in policies:
        changed = False

        # ---------------------------------------------------------------------
        # CASO A: Estructura crs_groups antigua (embebida en la propia política)
        # ---------------------------------------------------------------------
        if p.get("crs_groups"):
            for g in p["crs_groups"]:
                if g["name"] in target_groups:
                    g["enable"] = enable
                    for r in g.get("rules", []):
                        r["enable"] = enable
                        r["mode"] = mode
                    changed = True
                    print(f"  [*] '{p['name']}' -> Grupo '{g['name']}' completo actualizado a {mode} (Enable={enable})")

                for r in g.get("rules", []):
                    if str(r.get("rule_id")) in target_rules:
                        if enable:
                            g["enable"] = True
                        r["enable"] = enable
                        r["mode"] = mode
                        changed = True
                        print(f"  [*] '{p['name']}' -> Regla {r['rule_id']} actualizada a {mode} (Enable={enable})")

        # ---------------------------------------------------------------------
        # CASO B: Estructura crs_overrides moderna (Avi 22.1+)
        # ---------------------------------------------------------------------
        else:
            if not p.get("waf_crs_ref"):
                print(f"[!] La política '{p['name']}' no tiene referencia waf_crs_ref.")
                continue

            crs_uuid = p["waf_crs_ref"].split("/")[-1]
            if crs_uuid not in crs_cache:
                resp_crs = api.get(f"wafcrs/{crs_uuid}")
                resp_crs.raise_for_status()
                crs_cache[crs_uuid] = resp_crs.json()

            crs_catalog = crs_cache[crs_uuid]
            overrides = p.setdefault("crs_overrides", [])

            for cg in crs_catalog.get("groups", []):
                g_name = cg["name"]
                is_target_group = g_name in target_groups

                # Si pediste el grupo entero (--groups), extraemos TODOS los rule_id de ese grupo
                # para cambiarles el modo uno por uno dentro de rule_overrides
                if is_target_group:
                    rules_to_override = [str(r["rule_id"]) for r in cg.get("rules", [])]
                else:
                    rules_to_override = [
                        str(r["rule_id"]) for r in cg.get("rules", [])
                        if str(r.get("rule_id")) in target_rules
                    ]

                if not is_target_group and not rules_to_override:
                    continue

                # Buscar o crear el bloque del grupo en crs_overrides
                ov = next((o for o in overrides if o.get("name") == g_name), None)
                if not ov:
                    ov = {"name": g_name, "rule_overrides": []}
                    overrides.append(ov)

                if is_target_group:
                    ov["enable"] = enable
                elif enable:
                    ov["enable"] = True

                # Recorrer todas las firmas afectadas y fijar su enable y su mode
                r_ovs = ov.setdefault("rule_overrides", [])
                for rid in rules_to_override:
                    rov = next((x for x in r_ovs if str(x.get("rule_id")) == rid), None)
                    if not rov:
                        rov = {"rule_id": rid}
                        r_ovs.append(rov)
                    rov["enable"] = enable
                    rov["mode"] = mode

                changed = True
                print(f"  [*] '{p['name']}' -> Grupo '{g_name}': {len(rules_to_override)} firmas puestas en {mode} (Enable={enable})")

        if not changed:
            print(f"[-] En '{p['name']}' no se encontró ningún grupo o regla que coincida con los parámetros.")
            continue

        if dry_run:
            print(f"[DRY-RUN] Cambios preparados para '{p['name']}' (no aplicados).")
            continue

        bkp = backup_policy(p)
        resp = api.put(f"wafpolicy/{p['uuid']}", data=p)
        if resp.status_code == 200:
            print(f"[+] Política '{p['name']}' guardada con éxito -> HTTP 200 (Backup: {bkp})")
        else:
            print(f"[!] Error al guardar '{p['name']}': HTTP {resp.status_code} - {resp.text}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modifica estado y modo de grupos o firmas CRS")
    parser.add_argument("--groups", nargs="+", help="Nombres exactos de los grupos CRS (ej. CRS_942_Application_Attack_SQLi)")
    parser.add_argument("--rules", nargs="+", help="IDs de las reglas CRS (ej. 942100 932100)")
    parser.add_argument("--disable", action="store_true", help="Deshabilitar en lugar de habilitar")
    parser.add_argument("--mode", default="WAF_MODE_ENFORCEMENT", choices=["WAF_MODE_ENFORCEMENT", "WAF_MODE_DETECTION_ONLY"])
    parser.add_argument("--filter", help="Filtrar por nombre de política")
    parser.add_argument("--dry-run", action="store_true", help="Simular sin guardar cambios")
    args = parser.parse_args()

    update_crs_signatures(args.groups, args.rules, not args.disable, args.mode, args.filter, args.dry_run)
