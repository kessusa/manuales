# -*- coding: utf-8 -*-
"""
Herramientas de Playflows — v2.
La tool principal es check_flow: compone get_node_name + match_flow para
responder directamente "¿está permitido este flujo y por qué regla?".
El LLM ya no infiere sobre listados de reglas: Playflows hace el matching.
"""


def register_playflows_tools(registry, playflows_api):
    state = {"sid": None}

    def _sid():
        if not state["sid"]:
            state["sid"] = playflows_api.get_sid()
        return state["sid"]

    def _topology(ip):
        """Lista de nodos de topología para una IP. Normaliza el retorno de
        get_node_name: puede ser lista, dict contenedor o dict de un nodo."""
        raw = playflows_api.get_node_name(ip, _sid())
        if not raw:
            return []
        if isinstance(raw, list):
            return [n for n in raw if isinstance(n, dict)]
        if isinstance(raw, dict):
            for key in ("data", "matches", "results", "nodes"):
                if isinstance(raw.get(key), list):
                    return [n for n in raw[key] if isinstance(n, dict)]
            return [raw]  # dict de un único nodo
        return []

    def _node_info_for(*ips):
        """Replica el fw_and_node_info de la vista: dict por IP con las claves
        exactas que espera match_flow, y la lista de tags únicos."""
        info = {}
        for ip in ips:
            nodes = _topology(ip)
            if not nodes:
                # incluir la IP aunque no esté en topología, como hace la vista
                info.setdefault(ip, {"ip_address": ip,
                                     "node_normalization": "",
                                     "firewall_misc": ""})
                continue
            for n in nodes:
                key = n.get("ip_address") or ip
                info[key] = {
                    "ip_address": n.get("ip_address", ip),
                    "node_normalization": n.get("node_normalization", ""),
                    "firewall_misc": (n.get("firewall_misc") or "").strip(),
                }
        node_name_list = list(info.values())
        tags = list(dict.fromkeys(
            v["firewall_misc"] for v in node_name_list if v["firewall_misc"]))
        return node_name_list, tags

    # ------------------------------------------------------------
    # TOOL PRINCIPAL: check_flow
    # ------------------------------------------------------------
    @registry.tool(
        name="check_flow",
        description=(
            "Checks whether a network flow (src_ip -> dst_ip on a service) is "
            "allowed or blocked by the firewall. Returns the matching rule with "
            "its position, action (accept/drop) and firewall tag, or 'no_match' "
            "if no rule matches. Use this FIRST for connectivity issues."
        ),
        params={
            "src_ip": "Source IP address",
            "dst_ip": "Destination IP address",
            "service": "Service as 'protocol-port', e.g. 'tcp-3389' or 'udp-123'",
        },
    )
    def check_flow(src_ip, dst_ip, service):
        sid = _sid()
        node_name_list, tags = _node_info_for(src_ip, dst_ip)
        if not tags:
            return {"error": f"No firewall tag found in topology for "
                             f"{src_ip} / {dst_ip}. Check the IPs with "
                             f"get_topology_for_ip."}

        # Una sola llamada, igual que la vista: tag = lista de policies
        result = playflows_api.match_flow(
            sid=sid,
            tag=tags,
            source=src_ip,
            destination=dst_ip,
            service=service,
            node_name_list=node_name_list,
        )

        if not result:
            return {
                "result": "no_match",
                "meaning": "No firewall rule matches this flow: the firewall "
                           "is blocking it (implicit deny).",
                "tags_checked": tags,
            }

        matches = []
        for m in result:  # match_flow devuelve min_flow_result.values()
            matches.append({
                "tag": m.get("tag"),
                "rule_position": m.get("position"),
                "action": m.get("action"),
                "flow": m.get("flow"),
                "source_node": m.get("source_node_name"),
                "destination_node": m.get("destination_node_name"),
                "service": m.get("service"),
            })
        return {"result": "match", "matches": matches, "tags_checked": tags}

    # ------------------------------------------------------------
    # TOOLS AUXILIARES (contexto / diagnóstico)
    # ------------------------------------------------------------
    @registry.tool(
        name="get_topology_for_ip",
        description=(
            "Returns topology info for an IP: node name and firewall tag/zone. "
            "Useful to verify an IP exists in the network model or to identify "
            "its firewall."
        ),
        params={"ip": "IP address"},
    )
    def get_topology_for_ip(ip):
        nodes = _topology(ip)
        if not nodes:
            return {"error": f"IP {ip} not found in topology."}
        return [
            {"ip": n.get("ip_address"),
             "node_name": (n.get("node_normalization") or "").strip(),
             "firewall_tag": (n.get("firewall_misc") or "").strip()}
            for n in nodes
        ]

    @registry.tool(
        name="list_rules_in_tag",
        description=(
            "Lists all firewall rules of a tag/zone. Only use as a fallback if "
            "check_flow fails or you need to inspect surrounding rules."
        ),
        params={"tag": "Firewall tag, e.g. 'EMEA_FR_PRD_DMZA_HVD'"},
    )
    def list_rules_in_tag(tag):
        rules = playflows_api.get_tag_rules(_sid(), tag)
        return [
            {"pos": r.get("position"), "action": r.get("action"),
             "service": r.get("service"), "src": r.get("source_names"),
             "dst": r.get("destination_names")}
            for r in rules
        ]
