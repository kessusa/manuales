# -*- coding: utf-8 -*-
"""
AGENTE DE PROPUESTAS DE FLUJOS DE FIREWALL - version consolidada.
Ubicacion: API_cnx/fw_proposal_agent.py (junto a serenity.py y playflows.py)

Pipeline por cada AR del ticket:
  1. Serenity -> datos del AR.
  2. Validacion de admisibilidad (heuristicas + LLM).
  3. Playflows /webapi/1.1/commands:
       a. sin matchandcontinue  -> REGLA EFECTIVA (permitido si/no y por que)
       b. con matchandcontinue  -> TODAS las reglas (analisis de genericidad)
     En EMEA siempre; en CIS solo si hay tags CIS (como en tu view).
  4. Si hace falta regla nueva: where-used para reutilizar grupos existentes.
  5. Decision LLM: ya_permitido | reutilizar | nueva_regla | excepcion | denegar
  6. Borrador de mail (NO se envia: aprobacion humana).

Incorpora lo aprendido: match-flow deprecado -> /commands; streaming SSE para
evitar 504 del gateway; validacion JSON con reintento; fallbacks conservadores;
token por variable de entorno.
"""

import os
import json
import time
import ipaddress
from itertools import product

import requests
import urllib3

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
# Cliente Playflows sobre /webapi/1.1/commands (match-flow esta deprecado)
# =========================================================================
class PlayflowsCommands(object):
    """Envuelve una instancia de tu PlayflowsAPI existente para usar el
    endpoint /commands reutilizando su base_url, sesion y connection_args."""

    def __init__(self, playflows_api):
        self.pf = playflows_api

    def run(self, sid, commands, tags=None):
        payload = {"sid": sid, "commands": list(commands)}
        if tags:
            payload["tags"] = list(tags)
        args = dict(self.pf.connection_args)
        args["json"] = payload
        r = requests.post("%s/webapi/1.1/commands" % self.pf.base_url, **args)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "success":
            raise RuntimeError("Playflows commands fallo: %s" % data)
        return data.get("data", [])

    @staticmethod
    def build_flows(sources, destinations, services):
        return ["%s %s %s" % (s, d, srv) for s, d, srv
                in product(sources, destinations, services)]

    def effective_rules(self, sid, flows, tags):
        """First-match: LA regla que el firewall aplicara a cada flujo."""
        out = {}
        for item in self.run(sid, flows, tags):
            if item.get("type") != "match-flow":
                continue
            out[item["flow"]] = item
        return out

    def all_matches(self, sid, flows, tags):
        """'set matchandcontinue': TODAS las reglas que matchean (incluida
        la implicit drop), para el analisis de genericidad."""
        por_flujo = {}
        for item in self.run(sid, ["set matchandcontinue"] + list(flows),
                             tags):
            if item.get("type") != "match-flow":
                continue
            por_flujo.setdefault(item["flow"], []).append(item)
        for f in por_flujo:
            por_flujo[f].sort(key=lambda r: int(r.get("position") or 10**9))
        return por_flujo

    def where_used(self, sid, objeto):
        return self.run(sid, ["where-used %s" % objeto])

    @staticmethod
    def is_implicit_drop(rule):
        return (rule.get("action") == "drop" and not rule.get("id")
                and "implicit" in (rule.get("comment") or "").lower())

    @staticmethod
    def deterministic(rules):
        """Filtra vpn/auth/nat (match-and-continue)."""
        return [r for r in rules
                if r.get("action") in DETERMINISTIC_ACTIONS]


# =========================================================================
# Heuristicas deterministas (gratis, antes de gastar LLM)
# =========================================================================
def regla_es_generica(regla):
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
POLICY_PROMPT = """Eres un analista de seguridad de red. Evaluas peticiones de
apertura de flujos de firewall segun la politica interna:
- No se permite any-to-any ni servicios 'any'.
- Origen/destino deben ser IPs o redes concretas justificadas.
- Flujos hacia zonas criticas requieren justificacion de negocio explicita.
Devuelve JSON:
{"admisible": true, "motivo": "", "riesgo": "bajo|medio|alto"}"""

ESPECIFICIDAD_PROMPT = """Eres ingeniero de firewalls. Dado un flujo solicitado
y las reglas que YA lo permiten (ordenadas por posicion), decide si la
cobertura es adecuada o viene de reglas demasiado genericas que aconsejan
crear una regla especifica. Devuelve JSON:
{"adecuada": true, "razon": "", "recomendacion": "usar_existente|crear_especifica"}
Maximo 25 palabras por campo de texto."""

DECISION_PROMPT = """Eres el motor de decision de un equipo de seguridad de
red. Con la evidencia dada, decide UNA accion para el AR:
- "ya_permitido": cubierto por reglas adecuadas en todos los flujos.
- "reutilizar": ampliar regla/grupo existente (indica cual en detalle).
- "nueva_regla": proponer regla especifica (src/dst/srv en detalle).
- "excepcion": viola politica pero hay justificacion; tramitar excepcion.
- "denegar": rechazar.
Se conservador: ante dudas, "nueva_regla" o revision antes que bypass amplios.
Devuelve JSON:
{"accion": "", "detalle": "", "justificacion": ""}"""

MAIL_PROMPT = """Redacta un email profesional y conciso en espanol para el
solicitante del ticket explicando la decision sobre su peticion de flujo.
Tono cordial, tecnico pero claro: numero de AR, decision, motivo y proximos
pasos. Devuelve JSON: {"asunto": "", "cuerpo": ""}"""


# =========================================================================
# Pasos del pipeline
# =========================================================================
def validar_ar(ar_data):
    problemas = [c for c in ("sources", "destinations", "services")
                 if not ar_data.get(c)]
    if problemas:
        return {"admisible": False,
                "motivo": "Faltan campos: %s" % ", ".join(problemas),
                "riesgo": "n/a"}
    resumen = {
        "ar_number": ar_data.get("ar_number"),
        "sources": [s.get("ip_address") for s in ar_data["sources"]],
        "destinations": [d.get("ip_address") for d in ar_data["destinations"]],
        "services": ar_data["services"],
        "justificacion": ar_data.get("description", ""),
    }
    return llm_json(POLICY_PROMPT, json.dumps(resumen, ensure_ascii=False),
                    schema_keys=["admisible", "motivo", "riesgo"])


def analizar_en_playflows(pf_cmd, sid, flujo, fw_tags):
    """Regla efectiva + multi-match por flujo, en 2 llamadas batcheadas."""
    flows = PlayflowsCommands.build_flows(
        flujo["sources"], flujo["destinations"], flujo["services"])
    efectivas = pf_cmd.effective_rules(sid, flows, fw_tags)
    multi = pf_cmd.all_matches(sid, flows, fw_tags)

    resultado = []
    for f in flows:
        efectiva = efectivas.get(f, {})
        accepts = [r for r in pf_cmd.deterministic(multi.get(f, []))
                   if r.get("action") == "accept"]
        resultado.append({
            "flow": f,
            "permitido": efectiva.get("action") == "accept",
            "regla_efectiva": efectiva,
            "no_permitido_implicit_drop":
                pf_cmd.is_implicit_drop(efectiva) if efectiva else False,
            "reglas_accept": accepts,
            "alguna_regla_generica": any(regla_es_generica(r)
                                         for r in accepts),
        })
    return resultado


def evaluar_especificidad(flujo, analisis):
    """Solo llama al LLM para flujos permitidos con sospecha de genericidad."""
    dudosos = [a for a in analisis
               if a["permitido"] and a["alguna_regla_generica"]]
    if not dudosos:
        return []
    return [llm_json(
        ESPECIFICIDAD_PROMPT,
        json.dumps({"flujo_solicitado": a["flow"],
                    "reglas_que_lo_permiten": a["reglas_accept"]},
                   ensure_ascii=False),
        schema_keys=["adecuada", "razon", "recomendacion"])
        for a in dudosos]


def buscar_reutilizacion(pf_cmd, sid, flujo):
    out = {}
    for ip in flujo["sources"] + flujo["destinations"]:
        try:
            out[ip] = pf_cmd.where_used(sid, ip)
        except (RuntimeError, requests.RequestException):
            out[ip] = []
    return out


# =========================================================================
# Orquestador
# =========================================================================
def procesar_ticket(ticket_id, include_cis=True):
    """Devuelve un informe por AR, listo para revision humana (modo sombra).
    include_cis: pasa aqui el resultado de _user_in_groups(request.user,
    ['emea_netsec']) cuando lo llames desde la view."""
    from serenity import SerenityAPI
    from playflows import PlayflowsAPI
    # el modelo PlayflowsTag para detectar tags CIS, como en tu view:
    from bookmark.models import PlayflowsTag

    serenity = SerenityAPI(env="prd")
    ars = sorted(serenity.get_data(ticket_id) or [],
                 key=lambda x: int(x["ar_number"]))

    pf_emea = PlayflowsAPI()
    sid = pf_emea.get_sid()
    cmd_emea = PlayflowsCommands(pf_emea)

    pf_cis, sid_cis, cmd_cis = None, None, None

    informes = []
    try:
        for ar_data in ars:
            flujo = {
                "sources": [s["ip_address"] for s in ar_data["sources"]],
                "destinations": [d["ip_address"]
                                 for d in ar_data["destinations"]],
                "services": ar_data["services"],
            }
            # tags de firewall por nodo, como en tu view actual
            node_info = [pf_emea.get_node_name(ip, sid)
                         for ip in flujo["sources"] + flujo["destinations"]]
            fw_tags = sorted({n.get("firewall_misc", "").strip()
                              for n in node_info
                              if n.get("firewall_misc", "").strip()})

            # 1. Admisibilidad
            validacion = validar_ar(ar_data)

            analisis, especificidad, reutilizacion = [], [], {}
            analisis_cis = []
            if validacion.get("admisible"):
                # 2-3. EMEA siempre
                analisis = analizar_en_playflows(cmd_emea, sid, flujo,
                                                 fw_tags)
                especificidad = evaluar_especificidad(flujo, analisis)

                # 2b. CIS solo si procede (mismo criterio que tu view)
                tags_cis = list(PlayflowsTag.objects.filter(
                    region="cis", tag_name__in=fw_tags)
                    .values_list("tag_name", flat=True))
                if include_cis and tags_cis:
                    if pf_cis is None:
                        pf_cis = PlayflowsAPI(env="cis")
                        sid_cis = pf_cis.get_sid()
                        cmd_cis = PlayflowsCommands(pf_cis)
                    analisis_cis = analizar_en_playflows(
                        cmd_cis, sid_cis, flujo, tags_cis)

                # 4. Reutilizacion si algun flujo necesita regla nueva
                necesita_regla = (
                    any(not a["permitido"] for a in analisis + analisis_cis)
                    or any(e.get("recomendacion") == "crear_especifica"
                           for e in especificidad))
                if necesita_regla:
                    reutilizacion = buscar_reutilizacion(cmd_emea, sid, flujo)

            # 5. Decision
            evidencia = {"flujo": flujo, "validacion": validacion,
                         "analisis_emea": analisis,
                         "analisis_cis": analisis_cis,
                         "especificidad": especificidad,
                         "reutilizacion_grupos": reutilizacion}
            decision = llm_json(
                DECISION_PROMPT, json.dumps(evidencia, ensure_ascii=False),
                schema_keys=["accion", "detalle", "justificacion"])

            # 6. Borrador de mail
            mail = llm_json(
                MAIL_PROMPT,
                json.dumps({"ticket": ticket_id,
                            "ar": ar_data["ar_number"],
                            "decision": decision}, ensure_ascii=False),
                schema_keys=["asunto", "cuerpo"], temperature=0.4)

            informes.append({"ar_number": ar_data["ar_number"],
                             "flujo": flujo, "validacion": validacion,
                             "analisis_emea": analisis,
                             "analisis_cis": analisis_cis,
                             "especificidad": especificidad,
                             "reutilizacion": reutilizacion,
                             "decision": decision,
                             "mail_borrador": mail})
    finally:
        pf_emea.logout(sid)
        if pf_cis is not None:
            pf_cis.logout(sid_cis)

    return informes


if __name__ == "__main__":
    import sys
    print(json.dumps(procesar_ticket(sys.argv[1], include_cis=True),
                     indent=2, ensure_ascii=False))
