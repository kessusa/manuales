# -*- coding: utf-8 -*-
"""
Test rapido de modelos y modos de razonamiento contra el gateway LLM@CIB.

Para cada (modelo, variante) envia el mismo mini-lote de 2 firmas WAF y mide:
  - duracion
  - tokens de salida (usage) -> si son miles, el thinking sigue activo
  - si el content trae <think> o hay reasoning_content en la respuesta
  - si el JSON devuelto es valido y trae los 2 signature_id

Uso (desde el proyecto, Python 3.7):
    python llm_model_test.py
Ajusta MODELS y VARIANTS a lo que tengas en PromptGate.
"""

import json
import re
import time

import requests
import urllib3

from bookmark.settings import LLM_BASE_URL, LLM_API_KEY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODELS = ["qwen3.8-27b-ITG", "gemma-4-31b", "llama3.3-70b"]

# Cada variante = campos extra que se anaden al body (o al system prompt).
VARIANTS = {
    "baseline":            {},
    "enable_thinking=off": {"chat_template_kwargs": {"enable_thinking": False}},
    "reasoning_effort=low": {"reasoning_effort": "low"},
    "/no_think (prompt)":  {"_prompt_suffix": "\n/no_think"},
}

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

HEADERS = {"Authorization": "Bearer {}".format(LLM_API_KEY),
           "Content-Type": "application/json"}


def run(model, extra):
    system = SYSTEM + extra.get("_prompt_suffix", "")
    body = {"model": model, "stream": False, "temperature": 0,
            "max_tokens": 6000,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": USER}]}
    body.update({k: v for k, v in extra.items() if not k.startswith("_")})

    t0 = time.time()
    r = requests.post(LLM_BASE_URL, headers=HEADERS, json=body,
                      verify=False, timeout=300)
    dur = time.time() - t0
    if r.status_code != 200:
        return {"error": "HTTP {} {}".format(r.status_code, r.text[:120]),
                "dur": dur}

    data = r.json()
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    usage = data.get("usage", {})

    has_think_tag = "<think>" in content
    has_reasoning = bool(msg.get("reasoning_content") or msg.get("reasoning"))
    clean = re.sub(r"<think>.*?</think>", "", content, flags=re.S)
    clean = clean.replace("```json", "").replace("```", "").strip()
    try:
        parsed = json.loads(clean)
        ids = sorted(x.get("signature_id") for x in parsed)
        json_ok = ids == ["a1", "b2"]
    except Exception:
        json_ok = False

    return {"dur": dur,
            "in": usage.get("prompt_tokens"),
            "out": usage.get("completion_tokens"),
            "think_tag": has_think_tag,
            "reasoning_field": has_reasoning,
            "json_ok": json_ok,
            "snippet": clean[:60].replace("\n", " ")}


if __name__ == "__main__":
    print("{:<18} {:<22} {:>6} {:>6} {:>6} {:>5} {:>5} {:>5}  {}".format(
        "model", "variant", "sec", "in", "out", "think", "rsn", "json", "snippet"))
    for model in MODELS:
        for name, extra in VARIANTS.items():
            res = run(model, extra)
            if "error" in res:
                print("{:<18} {:<22} {:>6.1f}  {}".format(
                    model, name, res["dur"], res["error"]))
                continue
            print("{:<18} {:<22} {:>6.1f} {:>6} {:>6} {:>5} {:>5} {:>5}  {}".format(
                model, name, res["dur"], res["in"], res["out"],
                "Y" if res["think_tag"] else "-",
                "Y" if res["reasoning_field"] else "-",
                "OK" if res["json_ok"] else "FAIL",
                res["snippet"]))
