# -*- coding: utf-8 -*-
"""
Analisis LLM de logs WAF (ModSecurity CRS / AVI-NSX ALB) para agilizar
la puesta en produccion del WAF.

Estrategia para miles de filas:
  1. DEDUPLICAR: agrupar filas por 'firma' (rule_id + uri + parametro +
     patron de payload). Miles de eventos -> decenas de firmas unicas.
  2. MAP: analizar firmas en lotes de ~25 por llamada LLM. El LLM devuelve
     SOLO los campos de analisis + signature_id (nunca los originales).
  3. MERGE: propagar el veredicto de cada firma a todas sus filas (pandas).
  4. REDUCE: una llamada final para el resumen ejecutivo, alimentada con
     agregados calculados por pandas (el LLM no cuenta, solo juzga).
  5. CHECKPOINT: resultados parciales a disco por lote (reanudable).

Compatible Python 3.7. Mismo patron que abuse_ip_db.py:
Excel de entrada -> enriquecimiento -> Excel de salida con columnas nuevas.
"""

import os
import json
import re
import time
import hashlib

import pandas as pd
import requests

from bookmark.settings import MEDIA_ROOT  # como en abuse_ip_db.py

# --- LLM gateway interno -------------------------------------------------
LLM_URL = "https://llm.auria.dev.echonet/remote/llm-at-cib/v1/chat/completions"
LLM_API_KEY = os.environ["LLM_AT_CIB_TOKEN"]
LLM_MODEL = "llama3.3-70b"

BATCH_SIZE = 10          # firmas por llamada (504 del gateway con lotes grandes)
MAX_RETRIES = 3
PAYLOAD_TRUNC = 300      # caracteres max de payload por firma en el prompt

ANALYSIS_FIELDS = [
    "classification", "attack_confidence", "false_positive_confidence",
    "risk_level", "attack_type", "security_expert_analysis",
    "evidence_from_log", "why_it_may_be_false_positive", "production_impact",
    "recommended_action", "aviwaf_exception_type", "aviwaf_exception_scope",
    "aviwaf_exception_example", "safe_to_bypass", "code_fix_recommendation",
    "needs_manual_review",
]

SYSTEM_PROMPT = """ROLE
You are a senior cybersecurity analyst specialized in ModSecurity CRS,
AVI/NSX ALB WAF logs and production web application security.

OBJECTIVE
You will receive a JSON array of UNIQUE WAF event signatures (each one
represents N identical/similar events, see "occurrences"). Distinguish real
attacks from false positives and decide what should be blocked, monitored,
investigated, patched, or safely bypassed without putting production at risk.

OUTPUT FORMAT
Return ONLY a valid JSON array. No markdown, no comments, no text outside.
One object per input signature, with EXACTLY these fields:
{
 "signature_id": "<copy from input>",
 "classification": "attack | false_positive | benign | unknown",
 "attack_confidence": 0,
 "false_positive_confidence": 0,
 "risk_level": "low | medium | high | critical",
 "attack_type": "sqli | xss | rce | lfi | rfi | path_traversal | scanner | bot | protocol_violation | command_injection | file_upload | auth_attack | data_exfiltration | unknown | none",
 "security_expert_analysis": "",
 "evidence_from_log": "",
 "why_it_may_be_false_positive": "",
 "production_impact": "",
 "recommended_action": "allow | block | monitor | investigate | patch",
 "aviwaf_exception_type": "url | parameter | cookie | header | rule | none",
 "aviwaf_exception_scope": "global | path-specific | client-specific | none",
 "aviwaf_exception_example": "",
 "safe_to_bypass": false,
 "code_fix_recommendation": "",
 "needs_manual_review": false
}

CLASSIFICATION GUIDANCE
Use "attack" when payload, URI, parameter, user agent, source behavior or
triggered rule strongly indicates malicious activity.
Use "false_positive" when the request appears legitimate but matched a
generic WAF rule.
Use "benign" when there is no meaningful security concern.
Use "unknown" when there is insufficient evidence.

CONFIDENCE SCORING
attack_confidence / false_positive_confidence: 0, 50, 80, 100
(0=no evidence, 50=suspicious/possible, 80=likely, 100=confirmed).

RISK RULES
critical: confirmed exploitation attempt, RCE, data theft, credential attack.
high: clear SQLi, XSS, command injection, path traversal, scanner activity.
medium: suspicious payload, unusual headers, probing, malformed requests.
low: likely benign or false positive.

BYPASS / EXCEPTION RULES
Never recommend a global exception unless the event is clearly benign and the
rule is repeatedly causing safe false positives (check "occurrences").
Prefer the narrowest possible exception: 1. specific URL/path, 2. specific
parameter/cookie/header, 3. specific WAF rule ID, 4. specific client/source
only if trusted. If unsure: safe_to_bypass=false,
recommended_action="investigate", needs_manual_review=true.
Exception examples must be concrete and human readable, e.g.
"Exclude rule 942100 only for parameter 'search' on path '/products/search'".

IMPORTANT RULES
Do not invent missing fields; base the analysis only on the provided data.
If a field is missing, treat it as "not available". If evidence is weak,
classify as "unknown" and require manual review. Be conservative with bypass
recommendations: a bypass must never hide a real attack.
evidence_from_log must cite concrete values (rule id, URI, parameter,
payload, source IP, user agent, status...).
Keep every free-text field under 25 words. Be concise: short factual
sentences, no filler."""


def _llm_json(system, user, retries=MAX_RETRIES):
    """Llamada con validacion JSON + reintento con feedback."""
    headers = {"Authorization": "Bearer %s" % LLM_API_KEY,
               "Content-Type": "application/json"}
    last_err = None
    for attempt in range(retries):
        data = {
            "model": LLM_MODEL, "stream": False, "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        try:
            r = requests.post(LLM_URL, headers=headers, json=data,
                              verify=False, timeout=180)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            clean = content.replace("```json", "").replace("```", "").strip()
            return json.loads(clean)
        except Exception as e:                        # noqa: BLE001
            last_err = str(e)
            user += ("\n\nYour previous answer was invalid (%s). "
                     "Return ONLY the JSON array." % last_err)
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("LLM fallo tras %d intentos: %s" % (retries, last_err))


# --------------------------------------------------------------------------
# 1. Deduplicacion por firma
# --------------------------------------------------------------------------
def _normalize_payload(text):
    """Colapsa valores variables para que eventos 'iguales' compartan firma."""
    t = str(text)[:PAYLOAD_TRUNC]
    t = t.split("?")[0] if t.startswith("/") else t   # URI: fuera query string
    t = re.sub(r"\d+", "<N>", t)                       # numeros
    t = re.sub(r"[0-9a-fA-F]{8,}", "<HEX>", t)         # hashes/ids
    # listas 'a,b,c,...': deduplicar tokens y quedarse con el patron
    if "," in t:
        tokens = [x.strip() for x in t.split(",")]
        t = ",".join(sorted(set(tokens))[:3])
    return t.lower()


def build_signatures(df, sig_columns, extra_context_columns=None,
                     count_column=None):
    """
    sig_columns: columnas que definen la firma, p.ej.
        ['waf.rule.id', 'url.path', 'waf.rule.match_value']
    extra_context_columns: columnas informativas para el LLM (client_ip,
        method...) -> se toma una muestra por firma.
    count_column: si el Excel ya viene pre-agregado (columna 'Count' del
        search visual de AVI), las ocurrencias se SUMAN de ahi.
    Devuelve (df con columna 'signature_id', dict firma -> info).
    """
    extra_context_columns = extra_context_columns or []

    def sig_of(row):
        parts = [_normalize_payload(row.get(c, "")) for c in sig_columns]
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]

    missing = [c for c in sig_columns if c not in df.columns]
    if missing or not sig_columns:
        raise ValueError(
            "Columnas de firma no encontradas: %s. Columnas del Excel: %s"
            % (missing or "(ninguna definida)", list(df.columns)))

    df = df.copy()
    df["signature_id"] = df.apply(sig_of, axis=1)

    # md5('') = d41d8cd98f00... -> firma vacia = columnas mal mapeadas
    empty_sig = hashlib.md5(
        "|".join([""] * len(sig_columns)).encode()).hexdigest()[:12]
    if (df["signature_id"] == empty_sig).all():
        raise ValueError(
            "Todas las firmas estan vacias: las columnas %s existen pero "
            "no tienen contenido. Revisa el Excel." % sig_columns)

    signatures = {}
    for sig_id, grp in df.groupby("signature_id"):
        first = grp.iloc[0]
        occurrences = (int(grp[count_column].fillna(1).sum())
                       if count_column and count_column in grp
                       else int(len(grp)))
        entry = {"signature_id": sig_id,
                 "occurrences": occurrences}
        for c in sig_columns:
            entry[c] = str(first.get(c, ""))[:PAYLOAD_TRUNC]
        for c in extra_context_columns:
            # muestra de hasta 3 valores distintos (contexto sin ruido)
            entry[c + "_sample"] = (
                grp[c].astype(str).dropna().unique()[:3].tolist()
                if c in grp else [])
        signatures[sig_id] = entry
    return df, signatures


# --------------------------------------------------------------------------
# 2. MAP: analisis por lotes con checkpoint
# --------------------------------------------------------------------------
def _analyze_batch(batch, signatures, done):
    """Analiza un lote; si falla (504 del gateway, JSON invalido...) lo parte
    en dos y reintenta recursivamente. Un solo elemento que falle -> manual."""
    user_prompt = ("SIGNATURES\n%s"
                   % json.dumps(batch, ensure_ascii=False, indent=1))
    try:
        results = _llm_json(SYSTEM_PROMPT, user_prompt)
        valid = 0
        for item in results if isinstance(results, list) else []:
            sid = item.get("signature_id")
            if sid in signatures and all(k in item for k in ANALYSIS_FIELDS):
                done[sid] = item
                valid += 1
        # elementos del lote que el LLM no devolvio -> reintento individual
        lost = [s for s in batch if s["signature_id"] not in done]
        if lost and len(batch) > 1:
            for s in lost:
                _analyze_batch([s], signatures, done)
        return valid
    except RuntimeError as e:
        if len(batch) > 1:
            mid = len(batch) // 2
            print("  Lote de %d fallo (%s) -> partiendo en 2"
                  % (len(batch), str(e)[:80]))
            return (_analyze_batch(batch[:mid], signatures, done)
                    + _analyze_batch(batch[mid:], signatures, done))
        print("  Firma %s fallo definitivamente -> revision manual"
              % batch[0]["signature_id"])
        return 0


def analyze_signatures(signatures, checkpoint_path):
    done = {}
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            done = json.load(f)

    pending = [s for sid, s in signatures.items() if sid not in done]
    batches = [pending[i:i + BATCH_SIZE]
               for i in range(0, len(pending), BATCH_SIZE)]

    for n, batch in enumerate(batches, 1):
        valid = _analyze_batch(batch, signatures, done)
        # checkpoint tras cada lote (reanudable)
        with open(checkpoint_path, "w") as f:
            json.dump(done, f)
        print("Lote %d/%d: %d/%d firmas validas"
              % (n, len(batches), valid, len(batch)))

    # las que el LLM no devolvio bien -> revision manual, no inventar
    for sid in signatures:
        if sid not in done:
            done[sid] = {k: "" for k in ANALYSIS_FIELDS}
            done[sid].update({"signature_id": sid,
                              "classification": "unknown",
                              "needs_manual_review": True,
                              "safe_to_bypass": False,
                              "recommended_action": "investigate"})
    return done


# --------------------------------------------------------------------------
# 3. REDUCE: resumen de dataset (pandas cuenta, LLM redacta)
# --------------------------------------------------------------------------
REDUCE_PROMPT = """You are a senior security analyst. You receive aggregated
statistics (computed programmatically, trust them) and the per-signature
verdicts of a WAF log analysis. Produce ONLY valid JSON:
{"summary": "", "critical_findings": [], "patterns": [{"pattern": "",
"risk_level": "", "description": ""}], "rules_causing_false_positives":
[{"rule_id": "", "reason": "", "suggested_exception": ""}],
"recommended_investigation_actions": [], "recommended_waf_policy_changes": [],
"recommended_application_fixes": [], "executive_summary": ""}
Be concrete and conservative; never suggest disabling a rule globally unless
clearly justified."""


def dataset_analysis(df, verdicts, rule_col="waf.rule.id",
                     ip_col="original_client_ip", count_column=None):
    v = pd.DataFrame(verdicts.values())
    merged = df.merge(v, on="signature_id", how="left")

    # peso real de cada fila: Count si existe, si no 1
    w = (merged[count_column].fillna(1)
         if count_column and count_column in merged
         else pd.Series(1, index=merged.index))
    merged["_w"] = w

    stats = {
        "total_events": int(w.sum()),
        "total_rows": int(len(df)),
        "unique_signatures": int(len(verdicts)),
        "by_classification": merged.groupby("classification")["_w"]
            .sum().astype(int).to_dict(),
        "by_risk_level": merged.groupby("risk_level")["_w"]
            .sum().astype(int).to_dict(),
        "top_offenders": (merged[merged["classification"] == "attack"]
                          .groupby(ip_col)["_w"].sum().astype(int)
                          .nlargest(10).to_dict()
                          if ip_col in merged else {}),
        "rules_most_fp": (merged[merged["classification"] == "false_positive"]
                          .groupby(rule_col)["_w"].sum().astype(int)
                          .nlargest(10).to_dict()
                          if rule_col in merged else {}),
    }
    merged = merged.drop(columns=["_w"])
    # solo veredictos relevantes al reduce (ataques + FP), no todo
    interesting = [x for x in verdicts.values()
                   if x.get("classification") in ("attack", "false_positive")]
    user = ("STATS\n%s\n\nVERDICTS\n%s" % (
        json.dumps(stats, ensure_ascii=False),
        json.dumps(interesting[:150], ensure_ascii=False)))
    llm_part = _llm_json(REDUCE_PROMPT, user)
    llm_part.update(stats)          # los numeros SIEMPRE de pandas
    return merged, llm_part


# --------------------------------------------------------------------------
# Orquestador: mismo patron que reputation_ip_report()
# --------------------------------------------------------------------------
# Columnas reales del export "(NETSEC)(WAF) AVI SEARCH VISUAL".
# match_value NO define firma (demasiado variable): va como muestra de
# contexto; la firma es regla + path + elemento que matcheo.
DEFAULT_SIG_COLUMNS = [
    "waf.rule.id",
    "waf.rule.name",
    "url.path",
    "avi.waf_log.rule_logs.matches.match_element",
]
DEFAULT_CONTEXT_COLUMNS = [
    "waf.rule.match_value",
    "original_client_ip",
    "http.request.method",
    "event.action",
    "waf.rule.description",
]


def _clean_headers(df):
    """El export de AVI trae encabezados tipo 'waf.rule.id: Descending'.
    Nos quedamos con el nombre real de la columna."""
    df.columns = [str(c).split(": Descending")[0]
                  .split(": Ascending")[0].strip() for c in df.columns]
    return df


def waf_llm_report(input_file, sig_columns=None, extra_context_columns=None,
                   count_column="Count"):
    df = _clean_headers(pd.read_excel(input_file))

    sig_columns = sig_columns or [
        c for c in DEFAULT_SIG_COLUMNS if c in df.columns]
    if not sig_columns:
        raise ValueError(
            "Ninguna columna de firma encontrada. Columnas del Excel: %s"
            % list(df.columns))
    extra_context_columns = extra_context_columns or [
        c for c in DEFAULT_CONTEXT_COLUMNS if c in df.columns]
    if count_column not in df.columns:
        count_column = None

    df, signatures = build_signatures(
        df, sig_columns, extra_context_columns, count_column)
    print("%d filas -> %d firmas unicas" % (len(df), len(signatures)))

    checkpoint = "%s/avi_iwaf/waf_llm_checkpoint.json" % MEDIA_ROOT
    verdicts = analyze_signatures(signatures, checkpoint)

    merged_df, summary = dataset_analysis(
        df, verdicts, count_column=count_column)

    # columnas nuevas justo despues de las originales, como en tu reporte
    output_file = "%s/avi_iwaf/waf_llm_processed_file.xlsx" % MEDIA_ROOT
    with pd.ExcelWriter(output_file) as writer:
        merged_df.to_excel(writer, sheet_name="events", index=False)
        pd.DataFrame([summary]).to_excel(
            writer, sheet_name="dataset_analysis", index=False)

    os.remove(checkpoint)   # limpieza si todo fue bien
    return output_file, summary
