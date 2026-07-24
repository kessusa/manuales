# -*- coding: utf-8 -*-
import json
import urllib3

from bookmark.settings import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY
from API_cnx.servicenow import ServiceNowAPI
from API_cnx.playflows import PlayflowsAPI

import re
from agent_core import ToolRegistry, LLMClient, IncidentAgent
from tools_playflows import register_playflows_tools

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_network_flow(llm, raw_text):
    """Extrae src_ip/dst_ip/protocol/port del texto del ticket (una sola llamada LLM)."""
    prompt = [
        {"role": "system", "content":
            "You are a data extractor. Return ONLY a valid JSON object, no markdown."},
        {"role": "user", "content":
            f"Extract src_ip, dst_ip, protocol and port from this text:\n{raw_text}\n"
            'Format: {"src_ip": "...", "dst_ip": "...", "protocol": "...", "port": "..."}'},
    ]
    text = llm.chat(prompt).get("content") or ""
    text = re.sub(r"```(?:json)?|```", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def build_context(ticket_number, ticket_info, flow):
    raw_text = (
        f"SHORT_DESCRIPTION: {ticket_info.get('short_description')}\n"
        f"DESCRIPTION: {ticket_info.get('description')}\n"
        f"WORK_NOTES: {' | '.join(n['text'] for n in ticket_info.get('journal_notes', []))}"
    )
    return (f"TICKET: {ticket_number}\n"
            f"TICKET_TEXT: {raw_text}\n"
            f"EXTRACTED_FLOW: {json.dumps(flow)}\n\n"
            "Investigate whether this connectivity issue is caused by a missing "
            "firewall rule. Follow: 1) locate firewall for the destination IP, "
            "2) list rules in that tag, 3) conclude.")


if __name__ == "__main__":
    llm = LLMClient(LLM_BASE_URL, LLM_MODEL, LLM_API_KEY)

    sn_api = ServiceNowAPI()
    sn_token = sn_api.login()
    if not sn_token:
        raise SystemExit("Error de login en ServiceNow.")

    pf_api = PlayflowsAPI(env="emea")

    registry = ToolRegistry()
    register_playflows_tools(registry, pf_api)
    # Mañana: register_elastic_tools(registry, es_client)  y ya está.

    agent = IncidentAgent(llm, registry, max_iters=8)

    ticket_id = "INC13984862"
    ticket_info = sn_api.get_full_incident_details(sn_token, ticket_id)
    if "error" in ticket_info:
        raise SystemExit(f"ServiceNow error: {ticket_info['error']}")

    raw_text = (f"{ticket_info.get('short_description')} "
                f"{ticket_info.get('description')}")
    flow = extract_network_flow(llm, raw_text)
    print(f"[+] Flujo extraído: {flow}")

    result = agent.investigate(build_context(ticket_id, ticket_info, flow))

    print("\n" + "=" * 50)
    print("REPORTE FINAL DEL AGENTE")
    print("=" * 50)
    print(json.dumps(result, indent=2, ensure_ascii=False))
