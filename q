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


def tag_gestionado(tag, inv=None):
    """True si el tag/FW lo gestiona el equipo (esta en NUESTRO Playflows).
    Senales (convencion interna):
    - Los FW propios NO tienen espacios en el nombre.
    - Suelen incluir entorno: prd / dev / stg.
    - Si el inventario esta vacio (sin grupos ni reglas), el tag no esta en
      nuestro Playflows -> no tenemos acceso, no proponer nada.
    Los FW ajenos (p.ej. 'APAC NETWORKS') se obvian: no podemos codificar."""
    if " " in str(tag):
        return False
    if not re.search(r"(?i)(?:^|[_\-])(prd|dev|stg)(?:[_\-]|$)", str(tag)):
        return False
    if inv is not None and not inv.get("group_members") \
            and not inv.get("rules"):
        return False
    return True


# =========================================================================
# A. INVENTARIO (reusa get_groups_with_content y get_rule_per_tag de tu clase)
# =========================================================================
def _normalizar_regla(item):
    """Adapta la salida de tu get_rule_per_tag al esquema interno."""
    return {
        "id": item.get("comment_id"),
        "position": item.get("position"),
        "action": (item.get("action") or "").lower(),
        "disabled": (item.get("status") or "").lower() == "disable",
        "section": (item.get("section") or "").strip(),
        "comment": item.get("comment") or "",
        "wideness": item.get("wideness"),
        "src": {"contents": item.get("source") or [],
                "names": item.get("source_names") or []},
        "dst": {"contents": item.get("destination") or [],
                "names": item.get("destination_names") or []},
        "service": {"contents": item.get("service") or [], "names": []},
    }


def load_inventory(pf, sid, tag):
    """pf: instancia de tu PlayflowsAPI. get_groups_with_content para grupos
    y TU get_rule_per_tag para reglas (id=comment_id, position, section,
    comment, wideness, action, status ya parseados)."""
    groups = pf.get_groups_with_content(sid, tag) or {}
    group_ips = {
        g: info.get("content") or []
        for g, info in groups.items()
        if info.get("type") == "ip" and info.get("content")
    }
    todas = [_normalizar_regla(r)
             for r in (pf.get_rule_per_tag(sid, tag) or [])]
    return {"tag": tag, "groups_raw": groups,
            "group_ips": group_ips,
            # para candidatas solo cuentan las que PERMITEN y estan activas:
            # drops/denies/disabled NO van al LLM (ahorro de tokens y ruido)
            "rules": [r for r in todas
                      if r["action"] == "accept" and not r["disabled"]],
            # para secciones/posiciones cuentan TODAS (orden real del FW)
            "rules_todas": todas,
            "sections": _secciones(todas)}


def _secciones(rules):
    """Secciones del tag con su ULTIMA posicion (y tokens de seccion +
    comentarios): para colocar reglas nuevas sin desordenar el FW."""
    out = {}
    for r in rules or []:
        s = r.get("section") or ""
        if not s:
            continue
        try:
            pos = int(r.get("position") or 0)
        except (TypeError, ValueError):
            pos = 0
        e = out.setdefault(s, {"seccion": s, "ultima_posicion": 0,
                               "n_reglas": 0, "_tokens": set()})
        e["ultima_posicion"] = max(e["ultima_posicion"], pos)
        e["n_reglas"] += 1
        e["_tokens"] |= _tokens(s) | _tokens(r.get("comment"))
    return out


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


UMBRAL_MIEMBRO_ESPECIFICO = 24   # un miembro /24 o mas concreto = membresia
                                 # real; /8-/16 son grupos paraguas
WIDENESS_WIDE = 60.0             # escala 0-100: 100 no filtra nada; >=60 es
                                 # "Wide rule", solo aceptable para reglas
                                 # de infraestructura


def ip_membership(inv, ip, max_grupos=15):
    """Grupos que contienen la IP mediante miembros ESPECIFICOS (>= /24).
    Los grupos paraguas (PRIVATE_IPS, BNPP_ALL... con /8) contienen
    cualquier IP interna y no son membresia real: solo se cuentan."""
    especificos, amplios = [], 0
    for g, ips in inv["group_ips"].items():
        for c in ips:
            if _contains(c, ip):
                try:
                    pl = ipaddress.ip_network(str(c), strict=False).prefixlen
                except ValueError:
                    pl = 0
                if pl >= UMBRAL_MIEMBRO_ESPECIFICO:
                    especificos.append(g)
                else:
                    amplios += 1
                break
    return {"grupos": especificos[:max_grupos],
            "grupos_amplios_descartados": amplios}


# =========================================================================
# C. GRUPOS CANDIDATOS (misma red + similitud de naming/aplicacion)
# =========================================================================
def _tokens(nombre):
    return {t for t in re.split(r"[_\-.:\s/]+", str(nombre).upper())
            if len(t) > 2 and not t.isdigit()}


def tokens_contexto(node_info_por_ip, extra=None):
    """Tokens del contexto del flujo: node_normalization, aplicacion,
    grupos de membresia... para medir afinidad con reglas."""
    toks = set()
    for v in (node_info_por_ip or {}).values():
        for x in (v or {}).values():
            toks |= _tokens(x)
    for x in (extra or []):
        toks |= _tokens(x)
    return toks


def afinidad_regla(regla, tokens_ctx):
    """¿La regla tiene RELACION con el flujo? Tokens comunes entre los
    nombres de grupos/seccion/comentario de la regla y el contexto del
    flujo. Incluye wideness si Playflows lo da (mayor = mas amplia)."""
    campos = []
    for k in ("src_names", "dst_names", "service_names"):
        campos += list(regla.get(k) or [])
    for k in ("section", "comment", "tag"):
        if regla.get(k):
            campos.append(regla[k])
    toks = set()
    for c in campos:
        toks |= _tokens(c)
    comunes = sorted(toks & tokens_ctx)
    wideness = regla.get("wideness")
    try:
        es_wide = (wideness is not None
                   and float(wideness) >= WIDENESS_WIDE)
    except (TypeError, ValueError):
        es_wide = False
    return {"tokens_comunes": comunes,
            "score": len(comunes),
            "wideness": wideness,
            "es_wide_rule": es_wide}


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
    """Clasifica las reglas del tag frente al flujo:
    - 'parciales': cubren parte -> candidatas a add to.
    - 'cobertura_total': cubren TODO el flujo. Si match-flow no las devolvio
      (p.ej. regla solo en upcoming pendiente de forceupdate), esta es la
      red de seguridad que evita proponer duplicados."""
    parciales, totales = [], []
    for rule in inv["rules"]:
        if str(rule.get("disabled", "false")).lower() == "true":
            continue
        src_ok = _campo_cubre(rule.get("src"), flujo["sources"])
        dst_ok = _campo_cubre(rule.get("dst"), flujo["destinations"])
        srv_ok = _servicio_cubre(rule.get("service"), flujo["services"])

        cubre = {"src": all(src_ok.values()), "dst": all(dst_ok.values()),
                 "srv": all(srv_ok.values())}
        n_ok = sum(cubre.values())
        if n_ok == 0:
            continue

        entrada = {
            "id": rule.get("id"),
            "position": rule.get("position"),
            "section": rule.get("section", ""),
            "comment": rule.get("comment", ""),
            "wideness": rule.get("wideness"),
            "src_names": (rule.get("src") or {}).get("names", []),
            "dst_names": (rule.get("dst") or {}).get("names", []),
            "service_names": (rule.get("service") or {}).get("names", []),
            "cubre": cubre,
            "falta": [k for k, v in cubre.items() if not v],
            "ips_sin_cubrir": (
                [i for i, ok in src_ok.items() if not ok] +
                [i for i, ok in dst_ok.items() if not ok]),
            "score": n_ok,
        }
        if n_ok == 3:
            totales.append(entrada)
        else:
            parciales.append(entrada)
    return (sorted(parciales, key=lambda x: -x["score"])[:5],
            totales[:3])


# =========================================================================
# E. PROPUESTA FINAL (el LLM elige entre candidatos deterministas)
# =========================================================================
# =========================================================================
# E. SUGERENCIA DETERMINISTA DE SECCION Y POSICION (solo para nueva_regla)
# =========================================================================
def sugerir_seccion(inv, tokens_ctx):
    """Solo se calcula cuando va a haber regla NUEVA (sin cobertura total,
    sin reglas hermanas ni parciales que ampliar).
    - Si una seccion existente tiene afinidad (tokens de su nombre y de los
      comentarios de sus reglas vs el contexto del flujo): usarla, con
      posicion = ULTIMA regla de esa seccion.
    - Si ninguna encaja: proponer crear seccion; la posicion se decide por
      orden ALFABETICO respecto a las existentes (ultima regla de la
      seccion alfabeticamente anterior).
    - Secciones INFRA: advertencia, son mas sensibles de actualizar."""
    secciones = inv.get("sections") or {}
    if not secciones:
        return {"existe": False, "seccion": None, "posicion_sugerida": None,
                "advertencia_infra": False,
                "secciones_alfabeticas": [],
                "motivo": "El tag no tiene secciones registradas"}

    alfabeticas = [{"seccion": s, "ultima_posicion": e["ultima_posicion"]}
                   for s, e in sorted(secciones.items())]

    mejor, mejor_solape = None, set()
    for s, e in secciones.items():
        solape = e["_tokens"] & tokens_ctx
        if len(solape) > len(mejor_solape):
            mejor, mejor_solape = s, solape

    if mejor and mejor_solape:
        return {"existe": True, "seccion": mejor,
                "posicion_sugerida": secciones[mejor]["ultima_posicion"],
                "advertencia_infra": "INFRA" in mejor.upper(),
                "secciones_alfabeticas": alfabeticas,
                "motivo": "afinidad por tokens: %s"
                          % ",".join(sorted(mejor_solape))}

    return {"existe": False, "seccion": None, "posicion_sugerida": None,
            "advertencia_infra": False,
            "secciones_alfabeticas": alfabeticas,
            "motivo": ("ninguna seccion existente encaja: proponer nombre "
                       "nuevo y colocarlo por orden alfabetico (posicion = "
                       "ultima regla de la seccion anterior)")}


PLAYFLOWS_TEMPLATES = """SINTAXIS OFICIAL DE MODIFICACIONES (usar EXACTAMENTE):

REGLA DE ORO: NUNCA se anaden IPs sueltas a reglas. SIEMPRE grupos, aunque
sea una sola IP. Si las IPs no estan en un grupo especifico, primero se
CREA el grupo con la naming convention y luego se referencia en la regla.

Crear grupo nuevo (nombre segun naming: REGION_PAIS_ENV_ZONA_APP-ROL,
ejemplos reales: AMER_US_PRD_DMZE_MKT-ETS_PROD_FORCE, AMER_USA-NY-FORCE):
<NOMBRE_GRUPO_PROPUESTO>
    <ip1>
    <ip2>

Anadir IPs a un grupo existente (nombre del grupo y las IPs debajo):
<NOMBRE_GRUPO>
    <ip1>

Anadir SRC/DST/SRV a una regla existente. PRIMERA linea siempre el audit
con el ticket REAL. Identificador de regla: PREFERIBLE el id con prefijo
id- (src-id-1028); si no hay id, la position (src-59).
Ejemplo real completo:
audit:SN631685
add to EMEA_FR_PRD_DMZA_CIS-ADMIN:srv-id-1028 TCP_455
add to EMEA_FR_PRD_DMZA_CIS-ADMIN:comment-id-1028 SN631685

Sustituir origen/destino en una regla:
audit:<TICKET REAL>
set to <FW name>:src/dst-<rule number> <GRUPO sustituto>

Crear regla nueva (y seccion). <POS> es la POSICION REAL calculada
(posicion_sugerida o la alfabetica), NUNCA un placeholder:
audit:<TICKET REAL>
insert to <FW name>:src-<POS> <GRUPO>
insert to <FW name>:dst-<POS> <GRUPO>
insert to <FW name>:srv-<POS> <tcp/udp port>
insert to <FW name>:log-<POS> active
insert to <FW name>:comment-<POS> <TICKET REAL>
insert to <FW name>:section-<POS> <nombre de seccion>

NO incluir nunca forceupdate: lo ejecuta el implementador al aplicar.
NOTA: <FW name> es el firewall_misc del nodo."""

PROPOSAL_PROMPT = """Eres ingeniero senior de firewalls. Recibes un flujo
solicitado y CANDIDATOS ya verificados programaticamente. NO inventes
grupos, reglas, ids ni posiciones que no esten en los candidatos.

Elige la mejor propuesta con esta prioridad:
0. Si "reglas_cobertura_total" NO esta vacio: el flujo YA esta cubierto por
   esa regla en la version upcoming (probablemente pendiente de
   forceupdate). Propuesta "ya_cubierto", cambios=[], y en justificacion
   referencia la regla (position/names).
1. Si "reglas_mismo_ar" tiene reglas (ya permiten flujos hermanos de este
   mismo AR): son EL candidato natural -> "actualizar_regla" con add to
   por id (src-id-<id> / dst-id-<id> / srv-id-<id>) para cubrir lo que
   falta. Si lo que falta son IPs, PRIMERO crear/ampliar grupo y anadir
   el GRUPO a la regla.
2. "actualizar_grupo": si una regla candidata cubre el resto y las IPs sin
   cubrir encajan en un grupo candidato ya usado por esa regla.
3. "actualizar_regla" sobre una regla candidata parcial.
4. "nueva_regla": la plantilla insert to referenciando GRUPOS.

REGLAS SOBRE GRUPOS (obligatorias):
- Si una IP YA tiene grupos en "membresia_actual_por_ip" -> USA uno de esos
  grupos existentes en la regla (elige el que mejor encaje por naming con
  la aplicacion/zona del flujo). PROHIBIDO crear un grupo nuevo para una IP
  que ya tiene membresia especifica, y PROHIBIDO inventar variantes _SRC o
  _DST de grupos existentes.
- "grupos_nuevos" SOLO para IPs sin membresia especifica y sin grupo
  candidato razonable.
PROHIBIDO poner IPs sueltas en src/dst de reglas: siempre grupos.

AFINIDAD Y AMPLITUD (cada regla trae "afinidad": tokens_comunes con el
flujo, score, wideness y es_wide_rule. Escala wideness 0-100: 100 no
filtra nada; >=60 es "Wide rule", solo aceptable en reglas de
infraestructura):
- Una regla con es_wide_rule=true y afinidad score 0 es una permisiva
  generica sin relacion con este flujo (p.ej. salida generica): NO
  apoyarse en ella ni ampliarla; probablemente se reduzca en el futuro.
  Prefiere regla relacionada o nueva_regla especifica.
- En el FW de ORIGEN del flujo (ver "rol_de_este_fw_en_el_flujo") una
  regla amplia de salida es aceptable como cobertura; la especificidad se
  exige sobre todo en el FW de DESTINO.
- Para add to sobre una regla parcial exige afinidad razonable (score>0 o
  misma seccion/aplicacion) y que NO sea Wide rule; si no, nueva_regla.

SECCION (solo aparece "sugerencia_seccion" cuando la propuesta va a ser
nueva_regla; en los demas casos NO se toca la organizacion del FW):
- Si sugerencia_seccion.existe=true: usa esa seccion en
  insert to ...:section-<N> y su posicion_sugerida como <N>.
- Si existe=false: propon un nombre de seccion coherente con la naming,
  y elige <N> = ultima_posicion de la seccion alfabeticamente ANTERIOR al
  nombre propuesto (datos en secciones_alfabeticas).
- Si advertencia_infra=true o colocas la regla en una seccion INFRA:
  incluye en riesgos "ATENCION: seccion INFRA, sensible de actualizar".
Se conservador: no amplies grupos cuyo naming indique otra aplicacion u
otra zona aunque la red coincida.

FORMATO DE "cambios" (obligatorio):
- La PRIMERA linea es siempre "audit:<valor de ticket_id>" con el valor
  REAL de ticket_id de la evidencia. Igual en las lineas comment. Nada de
  <TICKET> ni placeholders.
- <POS>/<N> se rellenan con NUMEROS REALES: posicion_sugerida de
  sugerencia_seccion si existe=true; si existe=false, la ultima_posicion
  de la seccion alfabeticamente anterior al nombre que propongas
  (secciones_alfabeticas). Para ampliar regla usa su id (src-id-<id>).
  PROHIBIDO dejar <N>, <POS> o posiciones sin rellenar.
- PROHIBIDO incluir forceupdate: lo ejecuta el implementador.

En "cambios" escribe los comandos con la sintaxis oficial de abajo, uno
por linea.

%s

Devuelve JSON:
{"propuesta": "ya_cubierto|actualizar_grupo|actualizar_regla|nueva_regla",
 "objetivo": "<grupo o FW:id o FW:position>",
 "grupos_nuevos": [{"nombre": "", "ips": []}],
 "cambios": ["linea 1", "linea 2", "..."],
 "justificacion": "",
 "riesgos": ""}
grupos_nuevos vacio si no se crea ninguno.
Maximo 30 palabras en justificacion y riesgos.""" % PLAYFLOWS_TEMPLATES


def build_proposal(llm_json_fn, tag, flujo, membresias, grupos_cand,
                   reglas_cand, reglas_totales=None, reglas_mismo_ar=None,
                   rol_fw=None, sugerencia_seccion=None, ticket_id=None):
    evidencia = {
        "fw_name": tag,     # = firewall_misc: usar como <FW name> en comandos
        "ticket_id": ticket_id or "<TICKET>",
        "rol_de_este_fw_en_el_flujo": rol_fw or "desconocido",
        "flujo_solicitado": flujo,
        "membresia_actual_por_ip": membresias,
        "grupos_candidatos": grupos_cand,
        "reglas_candidatas_actualizar": reglas_cand,
        # reglas que ya cubren TODO el flujo en upcoming (match-flow puede
        # no verlas si estan pendientes de forceupdate)
        "reglas_cobertura_total": reglas_totales or [],
        # reglas que YA permiten flujos hermanos de este AR (del multi-match,
        # con id): candidato prioritario para add to por id
        "reglas_mismo_ar": reglas_mismo_ar or [],
    }
    # solo cuando va a haber nueva_regla (ahorro de tokens en el resto)
    if sugerencia_seccion is not None:
        evidencia["sugerencia_seccion"] = sugerencia_seccion
    return llm_json_fn(PROPOSAL_PROMPT,
                       json.dumps(evidencia, ensure_ascii=False),
                       schema_keys=["propuesta", "objetivo", "grupos_nuevos",
                                    "cambios", "justificacion", "riesgos"])


# =========================================================================
# Filtro de tags gestionados: solo proponemos en FWs que codificamos
# =========================================================================
TOKENS_GESTIONADO = {"DEV", "PRD", "STG"}


def tag_gestionado(tag):
    """Nuestros FWs: sin espacios en el nombre y con dev/prd/stg como token.
    'APAC NETWORKS' o 'SUPER NETWORKS' -> no gestionados (zonas/terceros)."""
    t = str(tag or "").strip()
    if not t or " " in t:
        return False
    tokens = set(re.split(r"[_\-.]", t.upper()))
    return bool(tokens & TOKENS_GESTIONADO)


def _propuesta_fuera_de_alcance(tag, motivo):
    """Propuesta determinista (sin LLM) con el mismo esquema que las demas:
    nunca se propone nada sobre FWs que no gestionamos."""
    return {"propuesta": "fuera_de_alcance",
            "objetivo": tag,
            "grupos_nuevos": [],
            "cambios": [],
            "justificacion": motivo,
            "riesgos": ""}


# =========================================================================
# Orquestacion del bloque (se llama desde el agente por cada tag del AR)
# =========================================================================
def analizar_candidatas(pf, sid, tag, flujo, node_info_por_ip, llm_json_fn,
                        reglas_mismo_ar=None, rol_fw=None, ticket_id=None):
    """pf: instancia de tu PlayflowsAPI DEL ENTORNO DEL TAG (emea o cis).
    node_info_por_ip: {ip: {node_normalization, application, ...}}.
    reglas_mismo_ar: reglas (con id) que ya permiten flujos hermanos de
    este AR, sacadas del multi-match del agente."""

    # 1er seguro: naming de FW no gestionado -> nada que proponer
    if not tag_gestionado(tag):
        return {"tag": tag, "gestionado": False,
                "membresias": {}, "grupos_candidatos": {},
                "reglas_candidatas": [], "reglas_cobertura_total": [],
                "reglas_mismo_ar": reglas_mismo_ar or [],
                "propuesta": _propuesta_fuera_de_alcance(
                    tag, "FW no gestionado por nosotros (naming): "
                         "no se propone codificacion")}

    inv = load_inventory(pf, sid, tag)

    # 2o seguro: Playflows no devuelve inventario -> sin acceso a ese FW
    if not inv.get("group_ips") and not inv.get("groups_raw") \
            and not inv.get("rules"):
        return {"tag": tag, "gestionado": False,
                "membresias": {}, "grupos_candidatos": {},
                "reglas_candidatas": [], "reglas_cobertura_total": [],
                "reglas_mismo_ar": reglas_mismo_ar or [],
                "propuesta": _propuesta_fuera_de_alcance(
                    tag, "Sin respuesta de Playflows para este tag: "
                         "sin acceso o no codificamos este FW")}

    membresias, grupos_cand = {}, {}
    for ip in flujo["sources"] + flujo["destinations"]:
        m = ip_membership(inv, ip)
        membresias[ip] = m
        if not m["grupos"]:            # solo buscar candidatos si no esta ya
            grupos_cand[ip] = candidate_groups(
                inv, ip, node_info_por_ip.get(ip))

    reglas_cand, reglas_totales = candidate_rules(inv, flujo)

    # afinidad de cada regla con el flujo (naming + seccion + comentario +
    # wideness): la senal para no apoyarse en reglas amplias sin relacion
    tokens_ctx = tokens_contexto(
        node_info_por_ip,
        extra=[g for m in membresias.values() for g in m.get("grupos", [])])
    hermanas = list(reglas_mismo_ar or [])
    for coleccion in (reglas_cand, reglas_totales, hermanas):
        for regla in coleccion:
            regla["afinidad"] = afinidad_regla(regla, tokens_ctx)

    # SECCION: se calcula siempre que una regla NUEVA sea posible (sin
    # cobertura total ni reglas hermanas), aunque haya parciales: el LLM
    # puede descartarlas y necesitara seccion/posicion reales
    sugerencia_seccion = None
    if not reglas_totales and not hermanas:
        sugerencia_seccion = sugerir_seccion(inv, tokens_ctx)

    propuesta = build_proposal(llm_json_fn, tag, flujo, membresias,
                               grupos_cand, reglas_cand,
                               reglas_totales=reglas_totales,
                               reglas_mismo_ar=hermanas,
                               rol_fw=rol_fw,
                               sugerencia_seccion=sugerencia_seccion,
                               ticket_id=ticket_id)
    return {"tag": tag, "gestionado": True,
            "rol_fw": rol_fw,
            "membresias": membresias,
            "grupos_candidatos": grupos_cand,
            "reglas_candidatas": reglas_cand,
            "reglas_cobertura_total": reglas_totales,
            "reglas_mismo_ar": hermanas,
            "sugerencia_seccion": sugerencia_seccion,
            "propuesta": propuesta}
