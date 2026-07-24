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

    def _candidates_for(ip):
        """Candidatos (node_name, firewall_tag) para una IP, en el orden que
        los devuelve get_node_name (el primero suele ser el más específico).
        IMPORTANTE: match_flow filtra con item['ip_address'] == norm(src/dst),
        así que las entradas de node_name_list deben llevar EXACTAMENTE la IP
        consultada, no la red/CIDR que devuelva la topología."""
        cands = []
        for n in _topology(ip):
            tag = (n.get("firewall_misc") or "").strip()
            name = (n.get("node_normalization") or "").strip()
            if (name, tag) not in cands:
                cands.append((name, tag))
        if not cands:
            cands = [("", "")]
        return cands

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
        src_cands = _candidates_for(src_ip)
        dst_cands = _candidates_for(dst_ip)

        all_tags = list(dict.fromkeys(
            t for _, t in src_cands + dst_cands if t))
        if not all_tags:
            return {"error": f"No firewall tag found in topology for "
                             f"{src_ip} / {dst_ip}. Check the IPs with "
                             f"get_topology_for_ip."}

        # match_flow solo acepta UN firewall_misc por IP (hace next() por
        # ip_address), así que probamos combinaciones de candidatos hasta
        # encontrar match. La primera suele ser la más específica.
        MAX_CALLS = 12
        tried, calls = [], 0
        for s_name, s_tag in src_cands:
            for d_name, d_tag in dst_cands:
                if calls >= MAX_CALLS:
                    break
                calls += 1
                tried.append({"src_tag": s_tag, "dst_tag": d_tag})
                node_name_list = [
                    {"ip_address": src_ip, "node_normalization": s_name,
                     "firewall_misc": s_tag},
                    {"ip_address": dst_ip, "node_normalization": d_name,
                     "firewall_misc": d_tag},
                ]
                result = playflows_api.match_flow(
                    sid=sid,
                    tag=all_tags,
                    source=src_ip,
                    destination=dst_ip,
                    service=service,
                    node_name_list=node_name_list,
                )
                if result:
                    matches = [{
                        "tag": m.get("tag"),
                        "rule_position": m.get("position"),
                        "action": m.get("action"),
                        "flow": m.get("flow"),
                        "source_node": m.get("source_node_name"),
                        "destination_node": m.get("destination_node_name"),
                        "service": m.get("service"),
                    } for m in result]
                    return {"result": "match", "matches": matches,
                            "src_tag": s_tag, "dst_tag": d_tag}

        return {
            "result": "no_match",
            "meaning": "No firewall rule matches this flow: the firewall "
                       "is blocking it (implicit deny).",
            "tags_checked": all_tags,
            "combinations_tried": tried,
        }

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
