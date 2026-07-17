# -*- coding: utf-8 -*-
"""
BUSQUEDA DE CANDIDATAS Y PROPUESTA FINAL (nucleo del agente de flujos).
Ubicacion: API_cnx/rule_candidates.py

Consume metodos de TU clase PlayflowsAPI existente:
  - get_groups_with_content(sid, tag) -> {grupo: {type, content, ...}}
    (ya resuelve anidamiento y name-to-values, incluido strip de S_)
  - get_tag_rules(sid, tag)           -> reglas con src/dst/service

Flujo (todo determinista salvo la propuesta final):
  A. Inventario: grupos con su contenido (IPs/servicios ya resueltos).
  B. Membresia: ¿cada IP del flujo ya esta en algun grupo? (containment real)
  C. Grupos candidatos para IPs no cubiertas: misma red + similitud de naming
     (tokens del grupo vs node_normalization + aplicacion de Serenity).
  D. Reglas candidatas a actualizar: cubren PARCIALMENTE el flujo.
  E. Propuesta final: el LLM elige entre candidatos y emite comandos con la
     sintaxis oficial de plantillas (add to / set to / insert to).
"""

import json
import ipaddress
import re

SUBNET_CANDIDATA = 24     # 'misma red' para proponer grupo (ajustable)


# =========================================================================
# A. INVENTARIO (reusa get_groups_with_content de tu clase)
# =========================================================================
def load_inventory(pf, sid, tag):
    """pf: instancia de tu PlayflowsAPI. Devuelve grupos->IPs y reglas.
    get_groups_with_content ya entrega {grupo: {'type','content',...}} con
    el contenido resuelto; aqui solo nos quedamos con los grupos de IPs."""
    groups = pf.get_groups_with_content(sid, tag) or {}
    group_ips = {
        g: info.get("content") or []
        for g, info in groups.items()
        if info.get("type") == "ip" and info.get("content")
    }
    rules = pf.get_tag_rules(sid, tag) or []
    return {"tag": tag, "groups_raw": groups,
            "group_ips": group_ips, "rules": rules}


# =========================================================================
# B. MEMBRESIA: ¿la IP ya esta cubierta por algun grupo?
# =========================================================================
def _contains(cidr, ip):
    try:
        red = ipaddress.ip_network(str(cidr), strict=False)
        objetivo = ipaddress.ip_network(str(ip), strict=False)
        return (objetivo.network_address in red
                and objetivo.broadcast_address in red)
    except ValueError:
        return False


def ip_membership(inv, ip):
    """Grupos que YA contienen la IP (containment real, no comparar strings)."""
    return {"grupos": [g for g, ips in inv["group_ips"].items()
                       if any(_contains(c, ip) for c in ips)]}


# =========================================================================
# C. GRUPOS CANDIDATOS (misma red + similitud de naming/aplicacion)
# =========================================================================
def _tokens(nombre):
    return {t for t in re.split(r"[_\-.]", str(nombre).upper())
            if len(t) > 2 and not t.isdigit()}


def _misma_red(cidr, ip, prefix=SUBNET_CANDIDATA):
    try:
        red_a = ipaddress.ip_network(str(cidr), strict=False)
        red_b = ipaddress.ip_network(str(ip), strict=False)
        return (red_a.supernet(new_prefix=prefix).network_address
                == red_b.supernet(new_prefix=prefix).network_address)
    except (ValueError, TypeError):
        return False


def candidate_groups(inv, ip, node_info=None):
    """Grupos donde ENCAJARIA la IP, con puntuacion explicable.
    node_info: {'node_normalization': ..., 'application': ..., ...}"""
    tokens_nodo = set()
    for v in (node_info or {}).values():
        tokens_nodo |= _tokens(v)

    candidatos = []
    for group, ips in inv["group_ips"].items():
        razones, score = [], 0
        if any(_misma_red(c, ip) for c in ips):
            score += 2
            razones.append("miembros en la misma /%d" % SUBNET_CANDIDATA)
        solape = _tokens(group) & tokens_nodo
        if solape:
            score += len(solape)
            razones.append("naming coincide: %s" % ",".join(sorted(solape)))
        if score:
            candidatos.append({"grupo": group, "score": score,
                               "razones": razones,
                               "miembros_actuales": len(ips)})
    return sorted(candidatos, key=lambda x: -x["score"])[:5]


# =========================================================================
# D. REGLAS CANDIDATAS A ACTUALIZAR (matching parcial)
# =========================================================================
def _campo_cubre(campo_regla, valores):
    contents = (campo_regla or {}).get("contents", []) or []
    return {v: any(_contains(c, v) for c in contents) for v in valores}


def _servicio_cubre(campo_srv, servicios):
    contents = [str(s).lower()
                for s in ((campo_srv or {}).get("contents", []) or [])]
    return {s: (str(s).lower() in contents or "any" in contents)
            for s in servicios}


def candidate_rules(inv, flujo):
    """Reglas que cubren parcialmente el flujo -> actualizar mejor que crear."""
    candidatas = []
    for rule in inv["rules"]:
        if str(rule.get("disabled", "false")).lower() == "true":
            continue
        src_ok = _campo_cubre(rule.get("src"), flujo["sources"])
        dst_ok = _campo_cubre(rule.get("dst"), flujo["destinations"])
        srv_ok = _servicio_cubre(rule.get("service"), flujo["services"])

        cubre = {"src": all(src_ok.values()), "dst": all(dst_ok.values()),
                 "srv": all(srv_ok.values())}
        n_ok = sum(cubre.values())
        if n_ok == 3 or n_ok == 0:      # total ya lo da match-flow; nulo sobra
            continue

        candidatas.append({
            "position": rule.get("position"),
            "src_names": (rule.get("src") or {}).get("names", []),
            "dst_names": (rule.get("dst") or {}).get("names", []),
            "service_names": (rule.get("service") or {}).get("names", []),
            "cubre": cubre,
            "falta": [k for k, v in cubre.items() if not v],
            "ips_sin_cubrir": (
                [i for i, ok in src_ok.items() if not ok] +
                [i for i, ok in dst_ok.items() if not ok]),
            "score": n_ok,
        })
    return sorted(candidatas, key=lambda x: -x["score"])[:5]


# =========================================================================
# E. PROPUESTA FINAL (el LLM elige entre candidatos deterministas)
# =========================================================================
PLAYFLOWS_TEMPLATES = """SINTAXIS OFICIAL DE MODIFICACIONES (usar EXACTAMENTE):

Anadir IPs a un grupo existente (nombre del grupo y las IPs debajo):
<NOMBRE_GRUPO>
    <ip1>
    <ip2>

Anadir SRC/DST/SRV a una regla existente:
audit: <rule number>
add to <FW name>:src-<rule number> <objeto>
add to <FW name>:dst-<rule number> <objeto>
add to <FW name>:srv-<rule number> <tcp/udp port>
add to <FW name>:comment-<rule number> <Tufin ticket>
Ejemplo: add to MAN:src-59 AN_PCORE_ADMIN_FORCE_CALLBACK

Sustituir origen/destino en una regla:
set to <FW name>:src/dst-<rule number> <objeto sustituto>
Ejemplo: set to EMDEN_EXTRA_UAT:src-35 IV2-EMEA_CORE_OVERLAY_DEV_TREP

Crear regla nueva (y seccion):
audit: <rule number>
insert to <FW name>:src-<rule number> <objeto>
insert to <FW name>:dst-<rule number> <objeto>
insert to <FW name>:srv-<rule number> <tcp/udp port>
insert to <FW name>:zsrc-<rule number> <interfaz>
insert to <FW name>:zdst-<rule number> <interfaz>
insert to <FW name>:log-<rule number> active
insert to <FW name>:comment-<rule number> <Tufin ticket>
insert to <FW name>:section-<section name>

Cierre (siempre al final del bloque de cambios):
forceupdate
audit:<CHG o Tufin ticket>

NOTA: <FW name> es el firewall_misc del nodo. <rule number> es la position."""

PROPOSAL_PROMPT = """Eres ingeniero senior de firewalls. Recibes un flujo
solicitado y CANDIDATOS ya verificados programaticamente (membresias reales,
grupos compatibles por red/naming, reglas que cubren parcialmente el flujo).
NO inventes grupos, reglas ni posiciones que no esten en los candidatos.

Elige la mejor propuesta con esta prioridad:
1. "actualizar_grupo": si una regla candidata cubre dst+srv y solo falta el
   src (o viceversa) Y las IPs sin cubrir encajan en un grupo candidato ya
   usado por esa regla -> anadir la IP al grupo (minimo cambio, regla intacta).
2. "actualizar_regla": add to sobre la regla candidata (usa su position como
   <rule number> y el fw_name como <FW name>).
3. "nueva_regla": plantilla insert to completa, con seccion.
Se conservador: no propongas ampliar grupos cuyo naming indique otra
aplicacion u otra zona aunque la red coincida.

En "cambios" escribe los comandos con la sintaxis oficial de abajo, uno por
linea, con la linea audit inicial cuando toques una regla y el cierre
forceupdate + audit:<TICKET>. Usa <TICKET> como placeholder del Tufin/CHG.

%s

Devuelve JSON:
{"propuesta": "actualizar_grupo|actualizar_regla|nueva_regla",
 "objetivo": "<grupo o FW:position>",
 "cambios": ["linea 1", "linea 2", "..."],
 "justificacion": "",
 "riesgos": ""}
Maximo 30 palabras en justificacion y riesgos.""" % PLAYFLOWS_TEMPLATES


def build_proposal(llm_json_fn, tag, flujo, membresias, grupos_cand,
                   reglas_cand):
    evidencia = {
        "fw_name": tag,     # = firewall_misc: usar como <FW name> en comandos
        "flujo_solicitado": flujo,
        "membresia_actual_por_ip": membresias,
        "grupos_candidatos": grupos_cand,
        "reglas_candidatas_actualizar": reglas_cand,
    }
    return llm_json_fn(PROPOSAL_PROMPT,
                       json.dumps(evidencia, ensure_ascii=False),
                       schema_keys=["propuesta", "objetivo", "cambios",
                                    "justificacion", "riesgos"])


# =========================================================================
# Orquestacion del bloque (se llama desde el agente por cada tag del AR)
# =========================================================================
def analizar_candidatas(pf, sid, tag, flujo, node_info_por_ip, llm_json_fn):
    """pf: instancia de tu PlayflowsAPI.
    node_info_por_ip: {ip: {node_normalization, application, ...}}."""
    inv = load_inventory(pf, sid, tag)

    membresias, grupos_cand = {}, {}
    for ip in flujo["sources"] + flujo["destinations"]:
        m = ip_membership(inv, ip)
        membresias[ip] = m
        if not m["grupos"]:            # solo buscar candidatos si no esta ya
            grupos_cand[ip] = candidate_groups(
                inv, ip, node_info_por_ip.get(ip))

    reglas_cand = candidate_rules(inv, flujo)

    propuesta = build_proposal(llm_json_fn, tag, flujo, membresias,
                               grupos_cand, reglas_cand)
    return {"tag": tag, "membresias": membresias,
            "grupos_candidatos": grupos_cand,
            "reglas_candidatas": reglas_cand,
            "propuesta": propuesta}
