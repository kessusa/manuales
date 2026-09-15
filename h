# -*- coding: utf-8 -*-
"""
Parche para llm_waf_poc.py:
  1. En _llm_json: reasoning_effort=minimal SOLO para modelos qwen.
  2. analyze_signatures en paralelo (ThreadPoolExecutor) con checkpoint,
     reintento de lotes fallidos como firmas sueltas y backfill a revision
     manual. Python 3.7.

Sustituye en tu fichero el diccionario `data` de _llm_json y la funcion
analyze_signatures completa por lo de aqui. Anade el import y WORKERS
junto a la configuracion.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

WORKERS = 4   # peticiones simultaneas al gateway; baja a 2 si ves 429/503

# ---------------------------------------------------------------------------
# 1. Dentro de _llm_json, en el for attempt in range(retries):
# ---------------------------------------------------------------------------
#     data = {
#         "model": model, "stream": stream, "temperature": 0,
#         "max_tokens": 6000,
#         "messages": [{"role": "system", "content": system},
#                      {"role": "user", "content": user}],
#     }
#     if "qwen" in model.lower():
#         data["reasoning_effort"] = "minimal"   # apaga el thinking en Qwen;
#                                                # en gemma lo ACTIVARIA, por eso solo qwen


# ---------------------------------------------------------------------------
# 2. analyze_signatures completa
# ---------------------------------------------------------------------------
def analyze_signatures(signatures, checkpoint_path, model=None, batch_size=None):
    """Run the LLM over the signatures in parallel batches.

    - Resumes from a JSON checkpoint if the previous run was interrupted.
    - Batches run concurrently (WORKERS threads); vLLM handles concurrency.
    - A batch that fails after retries is re-sent as single signatures
      (also in parallel). Whatever still fails is flagged as
      'unknown' + needs_manual_review instead of being retried forever.
    """
    model = model or LLM_MODEL
    size = batch_size or MODEL_BATCH.get(model, BATCH_SIZE)

    done = {}
    if os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            done = json.load(f)

    pending = [s for sid, s in signatures.items() if sid not in done]
    total = len(signatures)

    def _accept(results):
        """Keep only complete, well-formed verdicts. Returns how many."""
        n = 0
        for item in (results if isinstance(results, list) else []):
            sid = item.get("signature_id")
            if sid in signatures and all(k in item for k in ANALYSIS_FIELDS):
                done[sid] = item
                n += 1
        return n

    def _call(batch):
        prompt = f"SIGNATURES\n{json.dumps(batch, ensure_ascii=False, indent=1)}"
        return _llm_json(SYSTEM_PROMPT, prompt, model=model)

    def _run_round(batches, label):
        """Run a list of batches in parallel. Returns the batches that failed."""
        failed = []
        if not batches:
            return failed
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = {ex.submit(_call, b): b for b in batches}
            for fut in as_completed(futures):
                batch = futures[fut]
                try:
                    valid = _accept(fut.result())
                except RuntimeError as e:
                    print(f"[{label}] batch of {len(batch)} failed: {str(e)[:150]}")
                    failed.append(batch)
                    continue
                # Signatures the model skipped or returned malformed.
                missing = [s for s in batch if s["signature_id"] not in done]
                if missing:
                    failed.append(missing)
                with open(checkpoint_path, "w") as f:
                    json.dump(done, f)
                print(f"[{label}] Progress {len(done)}/{total} "
                      f"(batch: {len(batch)}, valid: {valid})")
        return failed

    # Round 1: normal batches in parallel.
    batches = [pending[i:i + size] for i in range(0, len(pending), size)]
    failed = _run_round(batches, "round1")

    # Round 2: everything that failed, one signature per call, still parallel.
    singles = [[s] for grp in failed for s in grp
               if s["signature_id"] not in done]
    if singles:
        print(f"Retrying {len(singles)} signatures individually")
        _run_round(singles, "round2")

    # Backfill: anything without a valid verdict goes to manual review.
    for sid in signatures:
        if sid not in done:
            done[sid] = {k: "" for k in ANALYSIS_FIELDS}
            done[sid].update({"signature_id": sid,
                              "classification": "unknown",
                              "needs_manual_review": True})
    with open(checkpoint_path, "w") as f:
        json.dump(done, f)
    return done
