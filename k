# -*- coding: utf-8 -*-
"""
AGENTE DE PROPUESTAS DE FLUJOS DE FIREWALL.
Ubicacion: API_cnx/fw_proposal_agent.py (junto a serenity.py, playflows.py
y rule_candidates.py)

Pipeline por cada AR del ticket:
  1. Serenity -> datos del AR.
  2. Validacion de admisibilidad (heuristicas + LLM).
  3. Playflows /webapi/1.1/commands:
       a. sin matchandcontinue  -> REGLA EFECTIVA (permitido si/no y por que)
       b. con matchandcontinue  -> TODAS las reglas (analisis de genericidad)
     En EMEA siempre; en CIS solo si hay tags CIS (como en tu view).
  4. Si hace falta regla nueva: rule_candidates.analizar_candidatas ->
     membresia real por IP, grupos candidatos (red + naming), reglas con
     matching parcial, y propuesta con la sintaxis oficial de plantillas
     (add to / set to / insert to / forceupdate). FW name = firewall_misc;
     rule number = position.
  5. Decision LLM: ya_permitido | reutilizar | nueva_regla | excepcion | denegar
  6. Borrador de mail (NO se envia: aprobacion humana).
"""

import os
import json
import time
import ipaddress
from itertools import product

import requests
import urllib3

from rule_candidates import (analizar_candidatas, afinidad_regla,
                             tokens_contexto, especificidad_regla)

urllib3.disable_warnings()

# =========================================================================
# LLM gateway interno (token SIEMPRE por entorno, nunca hardcodeado)
# =========================================================================
LLM_URL = "https://llm.auria.dev.echonet/remote/llm-at-cib/v1/chat/completions"
LLM_API_KEY = os.environ["LLM_AT_CIB_TOKEN"]
LLM_MODEL = "llama3.3-70b"
MAX_RETRIES = 3

DETERMINISTIC_ACTIONS = {"accept", "deny", "drop", "reject"}


def _consume_stream(headers, data):
    """Acumula la respuesta SSE. El streaming evita el 504: los tokens
    fluyen desde el primer segundo y el proxy no corta la conexion."""
    chunks = []
    with requests.post(LLM_URL, headers=headers, json=data, verify=False,
                       stream=True, timeout=(10, 600)) as r:
        r.raise_for_status()
        for raw in r.iter_lines():
            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore")
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                delta = (json.loads(payload)["choices"][0]
                         .get("delta", {}).get("content") or "")
                chunks.append(delta)
            except (ValueError, KeyError, IndexError):
                continue
    return "".join(chunks)


def llm_json(system, user, schema_keys=None, retries=MAX_RETRIES,
             model=None, temperature=0):
    """Llamada con streaming + validacion de esquema + reintento con feedback."""
    headers = {"Authorization": "Bearer %s" % LLM_API_KEY,
               "Content-Type": "application/json"}
    system += ("\nResponde EXCLUSIVAMENTE con un objeto JSON valido. "
               "Sin markdown, sin backticks, sin texto adicional.")
    last_err = None
    for attempt in range(retries):
        data = {"model": model or LLM_MODEL, "stream": True,
                "temperature": temperature,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        try:
            content = _consume_stream(headers, data)
            clean = content.replace("```json", "").replace("```", "").strip()
            result = json.loads(clean)
            if schema_keys and not all(k in result for k in schema_keys):
                raise ValueError("faltan claves: %s"
                                 % (set(schema_keys) - set(result)))
            return result
        except Exception as e:                          # noqa: BLE001
            last_err = str(e)
            user += ("\n\nTu respuesta anterior fue invalida (%s). "
                     "Corrige y devuelve SOLO el JSON." % last_err)
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("LLM fallo tras %d intentos: %s" % (retries, last_err))


# =========================================================================
# Helpers sobre resultados de match_flows (metodo de TU PlayflowsAPI)
# =========================================================================
def normalizar_servicio(srv):
    """Serenity trae TCP_455 / TCP_17000-17010; el match quiere tcp-455."""
    return str(srv).strip().replace("_", "-").lower()


def build_flows(sources, destinations, services):
    return ["%s %s %s" % (s, d, normalizar_servicio(srv))
            for s, d, srv in product(sources, destinations, services)]


def is_implicit_drop(rule):
    return (rule.get("action") == "drop" and not rule.get("id")
            and "implicit" in (rule.get("comment") or "").lower())


def deterministic(rules):
    """Filtra vpn/auth/nat (match-and-continue)."""
    return [r for r in rules if r.get("action") in DETERMINISTIC_ACTIONS]


# =========================================================================
# Heuristicas deterministas (gratis, antes de gastar LLM)
# =========================================================================
def regla_es_generica(regla):
    # wideness de Playflows (0-100): >=60 es Wide rule
    try:
        if float(regla.get("wideness")) >= 60.0:
            return True
    except (TypeError, ValueError):
        pass
    src = str(regla.get("source", regla.get("flow", ""))).lower()
    dst = str(regla.get("destination", "")).lower()
    srv = str(regla.get("service", "")).lower()
    if "any" in (src, dst) or srv in ("any", "*"):
        return True
    for campo in (src, dst):
        try:
            if ipaddress.ip_network(campo, strict=False).prefixlen <= 16:
                return True
        except ValueError:
            pass
    return False


# =========================================================================
# Prompts (aqui va VUESTRA politica real: iterar sobre esto)
# =========================================================================
# (validacion y decision ahora son deterministas; el LLM queda para la
#  eleccion de candidatas en rule_candidates y para el mail del ticket)

MAIL_PROMPT = """Redacta un email profesional y conciso en espanol para el
solicitante del ticket explicando la resolucion de su peticion de flujos.
Recibes la decision de CADA AR con su motivo. Estructura: saludo, resumen
por AR (decision + motivo en 1-2 lineas), proximos pasos, despedida.
Devuelve JSON: {"asunto": "", "cuerpo": ""}"""


def decidir_ar(validacion, analisis, especificidad, propuestas_tags):
    """DETERMINISTA (sin LLM): mapea la evidencia a una accion."""
    if not validacion.get("admisible"):
        return {"accion": "denegar" if "any" in validacion.get("motivo", "")
                          else "revisar",
                "detalle": validacion.get("motivo", ""),
                "justificacion": "Validacion de admisibilidad"}

    gestionadas = [p for p in propuestas_tags if p.get("gestionado", True)]
    if propuestas_tags and not gestionadas:
        return {"accion": "redirigir",
                "detalle": "Todos los FWs implicados estan fuera de "
                           "nuestro alcance: redirigir al equipo "
                           "propietario",
                "justificacion": "Tags no gestionados"}

    todos_permitidos = analisis and all(a["permitido"] for a in analisis)
    todas_adecuadas = all(e.get("adecuada") for e in especificidad)
    if todos_permitidos and todas_adecuadas and not gestionadas:
        return {"accion": "ya_permitido",
                "detalle": "Todos los flujos permitidos por reglas "
                           "adecuadas (ver already_open)",
                "justificacion": "Match con reglas afines y no wide"}

    tipos = [(p.get("propuesta") or {}).get("propuesta")
             for p in gestionadas]
    if "ya_cubierto" in tipos and all(
            t in ("ya_cubierto", "fuera_de_alcance") for t in tipos):
        return {"accion": "ya_permitido",
                "detalle": "Cubierto en upcoming (pendiente de "
                           "forceupdate del implementador)",
                "justificacion": "Cobertura total en show-rules"}
    if any(t in ("actualizar_grupo", "actualizar_regla") for t in tipos):
        return {"accion": "reutilizar",
                "detalle": "Aplicar cambios de to_code (actualizacion de "
                           "grupo/regla existente)",
                "justificacion": "Candidatas con afinidad disponibles"}
    if "nueva_regla" in tipos:
        return {"accion": "nueva_regla",
                "detalle": "Aplicar cambios de to_code (regla nueva)",
                "justificacion": "Sin regla/grupo reutilizable adecuado"}
    return {"accion": "revisar",
            "detalle": "Caso no clasificable automaticamente: revision "
                       "manual",
            "justificacion": "Evidencia insuficiente"}


# =========================================================================
# Pasos del pipeline
# =========================================================================
def validar_ar(ar_data):
    """DETERMINISTA (sin LLM). Bloqueos duros: campos ausentes o any.
    Justificacion vacia = AVISO, no denegacion (la decidira un humano)."""
    problemas = [c for c in ("sources", "destinations", "services")
                 if not ar_data.get(c)]
    if problemas:
        return {"admisible": False,
                "motivo": "Faltan campos: %s" % ", ".join(problemas),
                "riesgo": "n/a", "avisos": []}

    srcs = [s.get("ip_address", "") for s in ar_data["sources"]]
    dsts = [d.get("ip_address", "") for d in ar_data["destinations"]]
    srvs = [str(s) for s in ar_data["services"]]
    if any(str(x).lower() in ("any", "0.0.0.0/0") for x in srcs + dsts) \
            or any(s.lower() in ("any", "*") for s in srvs):
        return {"admisible": False,
                "motivo": "any en origen/destino/servicio: no permitido "
                          "por politica",
                "riesgo": "alto", "avisos": []}

    avisos = []
    if not (ar_data.get("description") or "").strip():
        avisos.append("Sin justificacion de negocio en el AR: "
                      "pedir/verificar antes de implementar")
    return {"admisible": True, "motivo": "", "riesgo": "bajo",
            "avisos": avisos}


def analizar_en_playflows(pf, sid, flujo, fw_tags):
    """UNA llamada batcheada (multi-match): la regla EFECTIVA es, por
    definicion de first-match, la primera determinista en orden de
    posicion. pf: instancia de tu PlayflowsAPI."""
    flows = build_flows(
        flujo["sources"], flujo["destinations"], flujo["services"])
    multi = pf.match_flows(sid, flows, fw_tags, multi_match=True)

    resultado = []
    for f in flows:
        deterministas = deterministic(multi.get(f, []))   # ya por posicion
        efectiva = deterministas[0] if deterministas else {}
        accepts = [r for r in deterministas
                   if r.get("action") == "accept"]
        resultado.append({
            "flow": f,
            "permitido": efectiva.get("action") == "accept",
            "regla_efectiva": efectiva,
            "no_permitido_implicit_drop":
                is_implicit_drop(efectiva) if efectiva else False,
            "reglas_accept": accepts,
            "alguna_regla_generica": any(regla_es_generica(r)
                                         for r in accepts),
        })
    return resultado


def rol_del_tag(tag, fw_and_node_info, flujo):
    """origen / destino / ambos: de que lado del flujo es este FW."""
    en_src = any(fw_and_node_info.get(ip, {}).get("firewall_misc") == tag
                 for ip in flujo["sources"])
    en_dst = any(fw_and_node_info.get(ip, {}).get("firewall_misc") == tag
                 for ip in flujo["destinations"])
    if en_src and en_dst:
        return "ambos"
    return "origen" if en_src else ("destino" if en_dst else "desconocido")


def evaluar_especificidad(flujo, analisis, fw_and_node_info):
    """DETERMINISTA (sin LLM): por cada flujo permitido, calcula que % del
    alcance de la regla efectiva usa realmente el flujo. <50% o Wide rule
    -> crear_especifica. Anade rol del FW para matizar (salida en origen)."""
    tokens_ctx = tokens_contexto(fw_and_node_info)
    resultados = []
    for a in analisis:
        if not a.get("permitido"):
            continue
        regla = dict(a.get("regla_efectiva") or {})
        regla["afinidad"] = afinidad_regla(regla, tokens_ctx)
        esp = especificidad_regla(regla, flujo)
        esp["flow"] = a["flow"]
        esp["rol_del_fw"] = rol_del_tag(regla.get("tag", ""),
                                        fw_and_node_info, flujo)
        # en el FW de ORIGEN una regla amplia de salida es aceptable: no
        # forzamos crear_especifica solo por ratio si el rol es origen y la
        # regla no es Wide
        if (esp["recomendacion"] == "crear_especifica"
                and esp["rol_del_fw"] == "origen"
                and not esp["es_wide_rule"]):
            esp["recomendacion"] = "usar_existente"
            esp["adecuada"] = True
            esp["nota"] = ("regla amplia de salida en FW de origen: "
                           "aceptable, control fino en destino")
        resultados.append(esp)
    return resultados


# =========================================================================
# Resumen final: to_code (todo lo que hay que codificar, listo para usar)
# y already_open (reglas que ya permiten flujos + senales de calidad)
# =========================================================================
def _clave_regla(regla, tag, origen):
    """Identidad de una regla para deduplicar. id si existe; si no,
    tag+position (implicit drops sin id no deberian llegar aqui)."""
    rid = regla.get("id")
    if rid:
        return ("id", str(rid))
    return ("pos", tag or "", str(regla.get("position") or ""))


def _compactar_flujos(flujos):
    """Agrupa src/dst/servicio de todos los flujos en un resumen unico.
    Como estos flujos los permite la MISMA regla, en vez de listar cada
    combinacion src x dst x srv, se muestran los conjuntos juntos."""
    srcs, dsts, srvs, ars = set(), set(), set(), set()
    for f in flujos:
        partes = str(f.get("flow", "")).split()
        if len(partes) >= 3:
            srcs.add(partes[0])
            dsts.add(partes[1])
            srvs.add(partes[2])
        if f.get("ar_number"):
            ars.add(f["ar_number"])
    return {
        "ars": sorted(ars),
        "sources": sorted(srcs),
        "destinations": sorted(dsts),
        "services": sorted(srvs),
        "n_flujos": len(flujos),
    }


def construir_resumen(informes, enriquecer=None):
    """to_code: todo lo que hay que codificar.
    already_open: UNA entrada por REGLA que permite flujos (deduplicada por
    id), con la regla COMPLETA (todos sus src/dst/service) y un resumen
    COMPACTO de lo que permite (sources/destinations/services juntos).
    enriquecer(tag, rule_id) -> dict de la regla completa (get_rule_per_tag),
    cacheado para no repetir llamadas API."""
    to_code = []
    reglas_open = {}      # clave_regla -> entrada agrupada
    cache_enriq = {}

    for inf in informes:
        toks = tokens_contexto(inf.get("fw_and_node_info", {}))

        def _registrar(regla, tag, origen, flow, extra):
            clave = _clave_regla(regla, tag, origen)
            if clave not in reglas_open:
                info = {k: regla.get(k)
                        for k in ("id", "position", "section",
                                  "comment", "action", "wideness")}
                # todos los src/dst/service que ya trae la regla
                info["sources"] = (regla.get("src") or {}).get("names") \
                    or (regla.get("src") or {}).get("contents") or []
                info["destinations"] = (regla.get("dst") or {}).get("names") \
                    or (regla.get("dst") or {}).get("contents") or []
                info["services"] = (regla.get("service") or {}).get("names") \
                    or (regla.get("service") or {}).get("contents") or []

                # enriquecer por id una sola vez (cache): completa la regla
                # con TODOS sus src/dst/service/comment si falta info
                rid = regla.get("id")
                falta = (not info.get("comment") or not info["sources"]
                         or not info["destinations"])
                if enriquecer and rid and falta:
                    ck = (tag, rid)
                    if ck not in cache_enriq:
                        try:
                            cache_enriq[ck] = enriquecer(tag, rid) or {}
                        except Exception:            # noqa: BLE001
                            cache_enriq[ck] = {}
                    full = cache_enriq[ck]
                    info["position"] = info.get("position") \
                        or full.get("position")
                    info["comment"] = info.get("comment") \
                        or full.get("comment", "")
                    info["section"] = info.get("section") \
                        or full.get("section")
                    info["wideness"] = info.get("wideness") \
                        or full.get("wideness")
                    info["sources"] = info["sources"] \
                        or full.get("source_names") or full.get("source") \
                        or []
                    info["destinations"] = info["destinations"] \
                        or full.get("destination_names") \
                        or full.get("destination") or []
                    info["services"] = info["services"] \
                        or full.get("service") or []

                reglas_open[clave] = {
                    "tag": tag, "origen": origen, "regla": info,
                    "afinidad": afinidad_regla(regla, toks),
                    "es_wide_rule": (afinidad_regla(regla, toks)
                                     .get("es_wide_rule")),
                    "_flujos_raw": [],
                }
            entrada = reglas_open[clave]
            reg = {"ar_number": inf["ar_number"], "flow": flow}
            reg.update(extra)
            if reg not in entrada["_flujos_raw"]:
                entrada["_flujos_raw"].append(reg)

        # permitido en produccion (match)
        for a in (inf.get("analisis_emea", []) +
                  inf.get("analisis_cis", [])):
            if not a.get("permitido"):
                continue
            regla = a.get("regla_efectiva") or {}
            _registrar(regla, regla.get("tag"), "produccion (match)",
                       a["flow"], {})

        for p in inf.get("propuestas_tags", []):
            # cobertura total en upcoming (regla creada pendiente de push)
            for r in (p.get("reglas_cobertura_total") or []):
                _registrar(r, p.get("tag"), "upcoming (show-rules)",
                           "cobertura total del AR %s" % inf["ar_number"], {})

            # todo lo que hay que codificar
            prop = p.get("propuesta") or {}
            if prop.get("propuesta") in ("actualizar_grupo",
                                         "actualizar_regla",
                                         "nueva_regla") \
                    and prop.get("cambios"):
                lineas = []
                for g in (prop.get("grupos_nuevos") or []):
                    if g.get("nombre"):
                        lineas.append(g["nombre"])
                        lineas += ["    %s" % ip
                                   for ip in (g.get("ips") or [])]
                        lineas.append("")
                lineas += prop["cambios"]
                to_code.append({
                    "ar_number": inf["ar_number"],
                    "fw": p.get("tag"),
                    "tipo": prop.get("propuesta"),
                    "objetivo": prop.get("objetivo"),
                    "grupos_nuevos": prop.get("grupos_nuevos") or [],
                    "cambios": prop.get("cambios"),
                    "riesgos": prop.get("riesgos", ""),
                    "bloque_texto": "\n".join(lineas),
                })

    # compactar: por cada regla, resumen agregado de lo que permite (src,
    # dst, srv juntos) en vez de listar cada combinacion
    salida_open = []
    for e in reglas_open.values():
        raw = e.pop("_flujos_raw")
        e["permite"] = _compactar_flujos(raw)
        salida_open.append(e)

    return to_code, salida_open


# =========================================================================
# Orquestador
# =========================================================================
def procesar_ticket(ticket_id, include_cis=True):
    """Devuelve un informe por AR, listo para revision humana (modo sombra).
    include_cis: pasa aqui el resultado de _user_in_groups(request.user,
    ['emea_netsec']) cuando lo llames desde la view."""
    from serenity import SerenityAPI
    from playflows import PlayflowsAPI
    from rss.models import PlayflowsTag   # ajusta a tu ruta real del modelo

    serenity = SerenityAPI(env="prd")
    ars = sorted(serenity.get_data(ticket_id) or [],
                 key=lambda x: int(x["ar_number"]))

    pf_emea = PlayflowsAPI()
    sid = pf_emea.get_sid()

    pf_cis, sid_cis = None, None
    _tags_cis_vistos = set()

    informes = []
    try:
        for ar_data in ars:
            flujo = {
                "sources": [s["ip_address"] for s in ar_data["sources"]],
                "destinations": [d["ip_address"]
                                 for d in ar_data["destinations"]],
                "services": ar_data["services"],
            }

            # info por nodo, igual que fw_and_node_info en tu view.
            # Cuando tengas el enriquecimiento de Serenity, anade aqui
            # claves extra (p.ej. 'application'): candidate_groups las
            # tokeniza todas automaticamente para el scoring de naming.
            fw_and_node_info = {}
            for ip in flujo["sources"] + flujo["destinations"]:
                info = pf_emea.get_node_name(ip, sid) or {}
                fw_and_node_info[ip] = {
                    "ip_address": info.get("ip_address", ip),
                    "node_normalization":
                        info.get("node_normalization", ""),
                    "firewall_misc":
                        (info.get("firewall_misc") or "").strip(),
                }

            fw_tags = sorted({v["firewall_misc"]
                              for v in fw_and_node_info.values()
                              if v["firewall_misc"]})

            # 1. Admisibilidad
            validacion = validar_ar(ar_data)

            analisis, especificidad = [], []
            analisis_cis, propuestas_tags = [], []
            if validacion.get("admisible"):
                # 2-3. EMEA siempre
                analisis = analizar_en_playflows(pf_emea, sid, flujo,
                                                 fw_tags)
                especificidad = evaluar_especificidad(flujo, analisis,
                                                      fw_and_node_info)

                # 2b. CIS solo si procede (mismo criterio que tu view)
                tags_cis = list(PlayflowsTag.objects.filter(
                    region="cis", tag_name__in=fw_tags)
                    .values_list("tag_name", flat=True))
                _tags_cis_vistos.update(tags_cis)
                if include_cis and tags_cis:
                    if pf_cis is None:
                        pf_cis = PlayflowsAPI(env="cis")
                        sid_cis = pf_cis.get_sid()
                    analisis_cis = analizar_en_playflows(
                        pf_cis, sid_cis, flujo, tags_cis)

                # 4. Candidatas de reutilizacion + propuesta por tag.
                # Cada tag se consulta contra SU entorno (cis vs emea) y se
                # pasan las reglas que ya permiten flujos hermanos del AR.
                necesita_regla = (
                    any(not a["permitido"] for a in analisis + analisis_cis)
                    or any(e.get("recomendacion") == "crear_especifica"
                           for e in especificidad))
                if necesita_regla:
                    tags_cis_set = set(tags_cis)
                    propuestas_tags = []
                    for tag in fw_tags:
                        if tag in tags_cis_set and pf_cis is not None:
                            pf_t, sid_t = pf_cis, sid_cis
                            analisis_t = analisis_cis
                        else:
                            pf_t, sid_t = pf_emea, sid
                            analisis_t = analisis
                        hermanas = [r for a in analisis_t
                                    for r in a["reglas_accept"]
                                    if r.get("tag") == tag]
                        propuestas_tags.append(analizar_candidatas(
                            pf_t, sid_t, tag, flujo, fw_and_node_info,
                            llm_json, reglas_mismo_ar=hermanas,
                            rol_fw=rol_del_tag(tag, fw_and_node_info,
                                               flujo),
                            ticket_id=ticket_id))

            # 5. Decision DETERMINISTA
            decision = decidir_ar(validacion, analisis + analisis_cis,
                                  especificidad, propuestas_tags)
            if validacion.get("avisos"):
                decision["avisos"] = validacion["avisos"]

            informes.append({"ar_number": ar_data["ar_number"],
                             "flujo": flujo,
                             "fw_and_node_info": fw_and_node_info,
                             "validacion": validacion,
                             "analisis_emea": analisis,
                             "analisis_cis": analisis_cis,
                             "especificidad": especificidad,
                             "propuestas_por_tag": propuestas_tags,
                             "decision": decision})

        # enriquecedor: devuelve la regla COMPLETA por id usando
        # get_rule_per_tag, cacheado por tag (1 llamada por tag como mucho).
        # Asi el already_open muestra todos los src/dst/service de la regla.
        _cache_reglas_tag = {}

        def _enriquecer(tag, rule_id):
            usa_cis = pf_cis is not None and tag in _tags_cis_vistos
            pf_e = pf_cis if usa_cis else pf_emea
            sid_e = sid_cis if usa_cis else sid
            if tag not in _cache_reglas_tag:
                try:
                    reglas = pf_e.get_rule_per_tag(sid_e, tag) or []
                except Exception:                    # noqa: BLE001
                    reglas = []
                _cache_reglas_tag[tag] = {
                    str(r.get("comment_id")): r for r in reglas}
            return _cache_reglas_tag[tag].get(str(rule_id), {})

        to_code, already_open = construir_resumen(informes,
                                                  enriquecer=_enriquecer)

        # 6. UN mail por ticket (unica llamada LLM fija), consolidando ARs
        mail_borrador = llm_json(
            MAIL_PROMPT,
            json.dumps({"ticket": ticket_id,
                        "decisiones": [{"ar": i["ar_number"],
                                        "decision": i["decision"]}
                                       for i in informes]},
                       ensure_ascii=False),
            schema_keys=["asunto", "cuerpo"], temperature=0.4)
    finally:
        pf_emea.logout(sid)
        if pf_cis is not None:
            pf_cis.logout(sid_cis)

    return {"ticket_id": ticket_id,
            "informes": informes,
            "to_code": to_code,
            "already_open": already_open,
            "mail_borrador": mail_borrador}


if __name__ == "__main__":
    import sys
    import django

    # bootstrap de Django para ejecucion standalone
    proyecto = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, proyecto)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "bookmark.settings")
    django.setup()

    print(json.dumps(procesar_ticket(sys.argv[1], include_cis=True),
                     indent=2, ensure_ascii=False))
