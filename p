# -*- coding: utf-8 -*-
"""
Inspeccion del gateway LLM@CIB / PromptGate para el modelo razonador.

1. GET /models (y /models/<id>): metadatos del despliegue, variantes.
2. Una llamada baseline volcando la respuesta cruda: usage detallado,
   campos de message, cabeceras HTTP.
3. Variantes alternativas de "sin razonar" (formatos OpenAI, OpenRouter,
   Anthropic) con la misma tabla de siempre + columna chars.
   Los errores se imprimen completos (r.text) para ver que rechaza vLLM.

Uso (Python 3.7): python llm_gateway_probe.py
"""

import json
import re
import time

import requests
import urllib3

from bookmark.settings import LLM_BASE_URL, LLM_API_KEY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODEL = "qwen3.8-27b-ITG"
HEADERS = {"Authorization": "Bearer {}".format(LLM_API_KEY),
           "Content-Type": "application/json"}

SYSTEM = """You are a WAF analyst. Return ONLY a valid JSON array, no markdown.
One object per signature with fields: signature_id, classification
(attack|false_positive|benign|unknown), attack_confidence (0-100),
recommended_action (allow|block|monitor|investigate|patch), evidence_from_log."""

SIGNATURES = [
    {"signature_id": "a1", "occurrences": 812,
     "waf.rule.id": "942100", "url.path": "/api/login",
     "avi.waf_log.rule_logs.matches.match_element": "ARGS:username",
     "waf.rule.match_value_sample": ["' OR 1=1--", "admin'--"]},
    {"signature_id": "b2", "occurrences": 1054,
     "waf.rule.id": "920350", "url.path": "/health",
     "avi.waf_log.rule_logs.matches.match_element": "REQUEST_HEADERS:Host",
     "waf.rule.match_value_sample": ["10.20.30.40"]},
]
USER = "SIGNATURES\n" + json.dumps(SIGNATURES, ensure_ascii=False, indent=1)

VARIANTS = {
    "baseline":                 {},
    "reasoning_effort=none":    {"reasoning_effort": "none"},
    "reasoning_effort=minimal": {"reasoning_effort": "minimal"},
    "reasoning.enabled=false":  {"reasoning": {"enabled": False}},
    "reasoning.effort=none":    {"reasoning": {"effort": "none"}},
    "thinking.disabled":        {"thinking": {"type": "disabled"}},
    "enable_thinking (top)":    {"enable_thinking": False},
    "extra_body.ctk":           {"extra_body": {"chat_template_kwargs":
                                                {"enable_thinking": False}}},
    "chat_template_kwargs":     {"chat_template_kwargs":
                                 {"enable_thinking": False}},
}


def sep(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


# ---------------------------------------------------------------------------
# 1. /models
# ---------------------------------------------------------------------------
def probe_models():
    sep("1. GET /models")
    base = LLM_BASE_URL.split("/chat/completions")[0]
    for path in ("/models", "/models/" + MODEL):
        url = base + path
        try:
            r = requests.get(url, headers=HEADERS, verify=False, timeout=30)
            print("\n{} -> HTTP {}".format(url, r.status_code))
            try:
                print(json.dumps(r.json(), indent=1, ensure_ascii=False)[:4000])
            except ValueError:
                print(r.text[:1500])
        except Exception as e:
            print("\n{} -> ERROR {}".format(url, e))


# ---------------------------------------------------------------------------
# 2. respuesta cruda baseline
# ---------------------------------------------------------------------------
def body_for(extra):
    body = {"model": MODEL, "stream": False, "temperature": 0,
            "max_tokens": 6000,
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": USER}]}
    body.update(extra)
    return body


def probe_raw():
    sep("2. Respuesta cruda (baseline)")
    r = requests.post(LLM_BASE_URL, headers=HEADERS, json=body_for({}),
                      verify=False, timeout=300)
    print("HTTP", r.status_code)
    print("\n-- headers --")
    for k, v in r.headers.items():
        print("  {}: {}".format(k, v))
    if r.status_code != 200:
        print("\n-- body --\n", r.text[:2000])
        return
    data = r.json()
    print("\n-- top-level keys --\n ", list(data.keys()))
    print("\n-- usage --\n", json.dumps(data.get("usage"), indent=1))
    msg = data["choices"][0]["message"]
    print("\n-- message keys --\n ", list(msg.keys()))
    for k in ("reasoning_content", "reasoning"):
        if k in msg:
            print("\n-- {} (primeros 300) --\n{}".format(k, str(msg[k])[:300]))
    print("\n-- choice keys --\n ", list(data["choices"][0].keys()))
    print("\n-- finish_reason --\n ", data["choices"][0].get("finish_reason"))
    print("\n-- content (primeros 300) --\n", (msg.get("content") or "")[:300])


# ---------------------------------------------------------------------------
# 3. variantes
# ---------------------------------------------------------------------------
def run(extra):
    t0 = time.time()
    try:
        r = requests.post(LLM_BASE_URL, headers=HEADERS, json=body_for(extra),
                          verify=False, timeout=300)
    except Exception as e:
        return {"error": "EXC {}".format(e), "dur": time.time() - t0}
    dur = time.time() - t0
    if r.status_code != 200:
        return {"error": "HTTP {}\n      {}".format(r.status_code,
                                                    r.text[:600].strip()),
                "dur": dur}
    data = r.json()
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    usage = data.get("usage", {})
    details = usage.get("completion_tokens_details") or {}
    clean = re.sub(r"<think>.*?</think>", "", content, flags=re.S)
    clean = clean.replace("```json", "").replace("```", "").strip()
    try:
        ids = sorted(x.get("signature_id") for x in json.loads(clean))
        json_ok = ids == ["a1", "b2"]
    except Exception:
        json_ok = False
    return {"dur": dur,
            "in": usage.get("prompt_tokens"),
            "out": usage.get("completion_tokens"),
            "rsn_tok": details.get("reasoning_tokens"),
            "rsn_field": bool(msg.get("reasoning_content") or msg.get("reasoning")),
            "finish": data["choices"][0].get("finish_reason"),
            "json_ok": json_ok,
            "chars": len(content)}


def probe_variants():
    sep("3. Variantes no-thinking")
    print("{:<26} {:>6} {:>5} {:>6} {:>8} {:>5} {:>7} {:>5} {:>6}".format(
        "variant", "sec", "in", "out", "rsn_tok", "rsn", "finish", "json", "chars"))
    for name, extra in VARIANTS.items():
        res = run(extra)
        if "error" in res:
            print("{:<26} {:>6.1f}  {}".format(name, res["dur"], res["error"]))
            continue
        print("{:<26} {:>6.1f} {:>5} {:>6} {:>8} {:>5} {:>7} {:>5} {:>6}".format(
            name, res["dur"], res["in"], res["out"],
            res["rsn_tok"] if res["rsn_tok"] is not None else "-",
            "Y" if res["rsn_field"] else "-",
            str(res["finish"]),
            "OK" if res["json_ok"] else "FAIL",
            res["chars"]))
    print("\nLectura: out ~= chars/4 -> sin thinking. finish=length -> cortado "
          "por max_tokens. rsn_tok -> tokens de razonamiento contados por vLLM.")


if __name__ == "__main__":
    probe_models()
    probe_raw()
    probe_variants()
