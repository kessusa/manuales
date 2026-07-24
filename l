# -*- coding: utf-8 -*-
"""
Prueba: ¿soporta tu gateway LLM function calling nativo (formato OpenAI)?
Ejecuta:  python test_function_calling.py
"""
import json
import requests
import urllib3

from bookmark.settings import LLM_BASE_URL, LLM_MODEL, LLM_API_KEY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {"Authorization": f"Bearer {LLM_API_KEY}",
           "Content-Type": "application/json"}

data = {
    "model": LLM_MODEL,
    "temperature": 0,
    "messages": [
        {"role": "user",
         "content": "Find the firewall for IP 10.24.140.99 using the available tool."}
    ],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "get_firewall_for_ip",
                "description": "Returns the firewall/tag associated with an IP.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "IP address"}
                    },
                    "required": ["ip"],
                },
            },
        }
    ],
    "tool_choice": "auto",
}

resp = requests.post(LLM_BASE_URL, headers=headers, json=data, verify=False, timeout=120)

print(f"HTTP {resp.status_code}")
try:
    body = resp.json()
except ValueError:
    print("Respuesta no es JSON:")
    print(resp.text[:2000])
    raise SystemExit(1)

print(json.dumps(body, indent=2, ensure_ascii=False)[:3000])

msg = (body.get("choices") or [{}])[0].get("message", {})
tool_calls = msg.get("tool_calls") or ([msg["function_call"]] if msg.get("function_call") else [])

print("\n" + "=" * 50)
if tool_calls:
    tc = tool_calls[0]
    fn = tc.get("function", tc)
    print("✅ SOPORTA function calling nativo")
    print(f"   Tool llamada: {fn.get('name')}")
    print(f"   Argumentos:   {fn.get('arguments')}")
elif resp.status_code == 200:
    print("⚠️  Respondió 200 pero SIN tool_calls.")
    print("   O ignoró el parámetro 'tools' (no soportado) o decidió responder en texto.")
    print("   Contenido devuelto:")
    print(f"   {msg.get('content')}")
else:
    print("❌ Error del gateway. Si el body menciona 'tools'/'unknown parameter',")
    print("   no está soportado → nos quedamos con el protocolo JSON.")
