# `llm_waf_usecase.py` — guía de estudio

Caso de uso LLM nº 1 de ProdSecHub (ticket EMEAPLAYFLOWS-3681): análisis con IA
de los logs de AVI iWAF. Este documento explica **qué hace cada pieza, qué recibe,
qué devuelve, en qué orden se ejecuta y por qué está hecha así**, para que puedas
validar que todo está como quieres.

---

## 1. Idea general en 30 segundos

```
Excel de AVI (N filas)
   │
   ├─ filas con AbuseIPDB score alto ──► veredicto automático "attack" (SIN LLM)
   │
   └─ resto de filas ──► se agrupan en FIRMAS únicas (dedupe)
                              │
                              ▼
                  LLM analiza cada firma (en batches, 4 en paralelo)
                              │
                              ▼
            el veredicto de cada firma se copia a TODAS sus filas
                              │
                              ▼
      estadísticas + resumen ejecutivo del LLM (paso "reduce", 1 llamada)
                              │
                              ▼
        Excel de 2 hojas: `events` + `dataset_analysis`
```

**El porqué central:** el LLM es lo caro y lo lento. Todo el diseño gira en torno
a llamarlo lo menos posible: primero se descartan las filas que no lo necesitan
(IPs ya conocidas como maliciosas) y luego se deduplican las demás. En tu prueba:
1132 filas → 450 tras el pruning → ~281 firmas. El LLM analiza 281 cosas, no 1132.

---

## 2. Patrón de "caso de uso" (aplica a este y a los futuros)

| Regla | Por qué |
|---|---|
| El `LlmApi` se **inyecta** como parámetro (`llm`), nunca se crea dentro | Los tests pasan un `FakeLlmApi` y no tocan la red. El conector se puede cambiar sin tocar el caso de uso |
| Solo se usan `llm.ask_json()` y `llm.get_model()` | El caso de uso no sabe nada de HTTP, headers ni URLs. Eso es responsabilidad del conector |
| Prompts en **constantes** del módulo | Se revisan y versionan en un solo sitio, no están enterrados en funciones |
| Las funciones devuelven datos o `None` y loguean el error | Misma convención que el resto de `API_cnx`: sin excepciones propias ni capas extra |
| Funciones pequeñas y puras (sin `request`) | Testeables una a una; la vista Django será una capa fina encima |

Uso:

```python
from API_cnx.llm_api import LlmApi
from API_cnx.llm_waf_usecase import waf_llm_report

output_file, summary = waf_llm_report(input_file, LlmApi(), model='default', cleanup_threshold=5.0)
```

---

## 3. Constantes (los "mandos" del módulo)

| Constante | Valor | Qué controla | Por qué ese valor |
|---|---|---|---|
| `OUTPUT_DIR` | `MEDIA_ROOT/avi_iwaf` | Dónde se escribe el Excel y el checkpoint | Misma carpeta que ya usa la sección AVI WAF |
| `WORKERS` | 4 | Llamadas al LLM en paralelo | Acelera x4 sin saturar el gateway (más workers → más 503) |
| `MAX_RETRIES` | 3 | Intentos de una misma llamada si no devuelve JSON válido | Cubre fallos puntuales sin bucles infinitos |
| `RETRY_WAIT` | 10 | Espera entre intentos: 10s, 20s, 30s | Un 503 del gateway necesita tiempo; con 2s reintentaba contra un gateway aún ocupado |
| `DEFAULT_BATCH_SIZE` | 5 | Firmas por llamada si el modelo no está en `MODEL_BATCH` | Valor conservador |
| `MODEL_BATCH` | dict por modelo | Firmas por llamada según el modelo (gemma 4, gpt-oss 6, qwen 6, llama 8) | Sin streaming, cada generación debe acabar antes de `LLM_TIMEOUT`; modelos con más contexto/velocidad admiten más |
| `MAX_TOKENS` | 4000 | Tope de tokens de respuesta por batch | ~300 tokens por veredicto × 8 firmas + margen |
| `PAYLOAD_TRUNC` | 300 | Máx. caracteres de cada valor enviado al LLM | Un payload de 5 KB no aporta más que sus primeros 300 caracteres y dispara el coste |
| `SAMPLE_SIZE` | 3 | Valores de ejemplo por columna de contexto | Da contexto (IPs, match values) sin inflar el prompt |
| `REDUCE_VERDICTS` | 40 | Veredictos que se envían al resumen final | Con 100 veredictos completos (~30k tokens) la llamada superaba los 60s de timeout |
| `REDUCE_MAX_TOKENS` | 1500 | Tope de tokens del resumen | Acota el tiempo de generación |
| `REDUCE_FIELDS` | 6 campos | Campos del veredicto que viajan al resumen | El resumen no necesita `code_fix_recommendation`, etc. |
| `DEFAULT_CLEANUP_THRESHOLD` | 10.0 | Score AbuseIPDB a partir del cual una fila NO va al LLM | Tú lo lanzas con 5.0 |
| `SCORE_COLUMN` / `COUNT_COLUMN` / `IP_COLUMN` | nombres de columna | Columnas especiales del export | Un solo sitio donde cambiarlas |
| `IP_COLUMN_CANDIDATES` | `ip`, `original_client_ip`, `client_ip` | Nombres posibles de la columna IP | El export no siempre la llama igual; se renombra a `ip` |
| `DEFAULT_SIGNATURE_COLUMNS` | `waf.rule.id`, `url.path`, `...match_element` | Qué define una firma | "Misma regla + misma URL + mismo elemento" = mismo tipo de evento |
| `DEFAULT_CONTEXT_COLUMNS` | `ip`, `waf.rule.match_value` | Contexto extra que ve el LLM | Ayudan a decidir pero NO definen la firma (si no, cada IP sería una firma distinta) |
| `RAW_SIGNATURE_COLUMNS` | `waf.rule.id` | Columnas de firma que NO se normalizan | Bug de la PoC: `942100` y `941100` se convertían ambas en `<n>` y se fusionaban |
| `NO_THINK_MODELS` | qwen | Modelos a los que se pasa `reasoning_effort='minimal'` | En PromptGate, Qwen solo desactiva el "thinking" con `minimal` |
| `CLASSIFICATIONS` | attack, false_positive, benign, unknown | Valores válidos | Cualquier otro valor del LLM se corrige a `unknown` + revisión manual |
| `ANALYSIS_DEFAULTS` | 16 campos con su valor por defecto | Esquema del veredicto = columnas nuevas del Excel | Garantiza que todas las filas tienen todas las columnas aunque el LLM omita alguna |
| `SYSTEM_PROMPT` | prompt de la PoC | Rol, objetivo y esquema JSON exacto | Es el que ya daba buenos resultados; las enumeraciones fuerzan valores consistentes |
| `REDUCE_PROMPT` | prompt de la PoC | Instrucción del resumen | Igual que en la PoC |
| `RETRY_FEEDBACK` | texto | Se añade al prompt cuando la respuesta no era JSON | Decirle al modelo qué hizo mal mejora el segundo intento |

---

## 4. Orden de ejecución

`waf_llm_report()` es el orquestador. Llama a todo lo demás en este orden:

| # | Paso | Función | ¿Usa LLM? |
|---|---|---|---|
| 1 | Leer el Excel y normalizar cabeceras | `load_waf_export` | No |
| 2 | Separar filas por score AbuseIPDB | (en el orquestador) | No |
| 3 | Agrupar las filas limpias en firmas | `build_signatures` → `normalize_payload` | No |
| 4 | Analizar firmas en batches paralelos | `analyze_signatures` → `run_batches` → `analyze_batch` → `ask_json_with_retries` → `clean_verdict` | **Sí** |
| 5 | Volcar cada veredicto a sus filas | `merge` (en el orquestador) | No |
| 6 | Veredicto automático para las filas podadas | `annotate_pruned` | No |
| 7 | Estadísticas + resumen ejecutivo | `dataset_analysis` → `build_dataset_stats`, `build_reduce_verdicts` | **Sí (1 llamada)** |
| 8 | Escribir el Excel | `save_waf_llm_report` | No |
| 9 | Borrar (o conservar) el checkpoint | (en el orquestador) | No |

---

## 5. Función por función

### 5.1 Preparación de datos (sin LLM)

#### `load_waf_export(input_file)`
- **Entrada:** ruta a un `.xlsx` o `.csv` exportado del visual search de AVI.
- **Salida:** `DataFrame` con cabeceras limpias y la columna IP renombrada a `ip`.
- **Qué hace:**
  1. Lee con `read_csv` o `read_excel` según la extensión.
  2. Limpia cabeceras: `'waf.rule.id: Descending'` → `'waf.rule.id'`.
  3. Busca la columna IP entre los candidatos; si no hay ninguna, usa la primera columna.
- **Por qué:** AVI añade `: Descending` a las cabeceras. Sin esta limpieza ninguna
  columna de firma coincide (fue el bug de "1 unique signature").

#### `normalize_payload(value)`
- **Entrada:** un valor cualquiera de una celda.
- **Salida:** `str` normalizado (máx. 300 caracteres).
- **Qué hace, en orden:**
  1. `None`/`NaN` → `''`.
  2. Si empieza por `/` (es una URL), quita el query string: `/login?id=1` → `/login`.
  3. Cadenas hex de 8+ caracteres → `<hex>` (tokens, hashes, session ids).
  4. Números → `<n>`: `id=12 or 34` → `id=<n> or <n>`.
  5. Listas con comas: únicas, ordenadas, máx. 3: `b, a, c, d` → `a,b,c`.
- **Por qué:** dos eventos que solo difieren en un id, un token o el orden de una
  lista son el **mismo tipo** de evento. Normalizar es lo que hace que compartan
  firma y el LLM los analice una sola vez. El hex va antes que los números porque
  si no `DEADBEEF1234` quedaría como `DEADBEEF<n>`.

#### `build_signatures(df, signature_columns, context_columns, count_column='Count')`
- **Entrada:** DataFrame de filas limpias + qué columnas definen la firma y cuáles son contexto.
- **Salida:** tupla `(df, signatures)`:
  - `df`: copia con una columna nueva `signature_id`.
  - `signatures`: `{signature_id: {...}}` — lo que se envía al LLM. O **`None`** si el export no tiene ninguna columna de firma.
- **Qué hace:**
  1. Descarta de las listas las columnas que no existen en el export.
  2. Si no queda ninguna columna de firma → `logger.error` listando las columnas reales y devuelve `None`.
  3. Construye la clave de cada fila: valores de las columnas de firma unidos con `|`. `waf.rule.id` va en crudo; el resto pasa por `normalize_payload`.
  4. `signature_id` = primeros 12 caracteres del MD5 de esa clave.
  5. Por cada grupo de filas con el mismo `signature_id` crea la entrada:
     ```json
     {
       "signature_id": "80b7398117c7",
       "occurrences": 37,
       "waf.rule.id": "942380",
       "url.path": "/api/search",
       "avi.waf_log.rule_logs.matches.match_element": "ARGS:q",
       "ip_sample": ["1.1.1.1", "2.2.2.2"],
       "waf.rule.match_value_sample": ["select * from", "..."]
     }
     ```
- **Por qué:**
  - MD5 truncado: id corto, estable entre ejecuciones (necesario para el checkpoint) y barato de copiar en el prompt.
  - `occurrences` suma la columna `Count` (o cuenta filas): el LLM ve si es un evento aislado o masivo.
  - Se normaliza **una vez por valor único**, no por fila: con miles de filas repetidas es mucho más rápido.
  - El guard del paso 2 evita repetir el bug de analizar una única firma vacía en silencio.

#### `annotate_pruned(df_pruned, threshold)`
- **Entrada:** las filas con score ≥ umbral, y el umbral.
- **Salida:** copia del DataFrame con todas las columnas de análisis rellenas: `classification='attack'`, `attack_confidence=100`, `risk_level='high'`, `recommended_action='block'`, `signature_id=''` y una nota explícita *"LLM was NOT used for this row"*.
- **Por qué:** una IP con mala reputación confirmada no necesita opinión del LLM. La nota deja trazabilidad de que el veredicto es automático, y `signature_id=''` permite contarlas después (`rows_pruned_by_score`).

### 5.2 Pasos con LLM

#### `get_model_options(llm, model)`
- **Entrada:** el `LlmApi` y el alias o nombre de modelo (`'default'`, `'reasoner'`, `'llama3.3-70b'`...).
- **Salida:** tupla `(batch_size, options)`; `options` son los kwargs para `ask_json` (`max_tokens`, y `reasoning_effort` si aplica).
- **Por qué:** resuelve el alias al nombre real con `llm.get_model()` y centraliza las particularidades de cada modelo en un único sitio.

#### `ask_json_with_retries(llm, system, prompt, model, options, retries=3)`
- **Entrada:** system prompt, prompt de usuario, modelo y opciones.
- **Salida:** el JSON parseado (`list` o `dict`) o `None` tras 3 fallos.
- **Qué hace:** llama a `llm.ask_json()`. Si devuelve `None` (error HTTP, timeout o JSON inválido), añade `RETRY_FEEDBACK` al prompt, espera 10/20/30s y reintenta.
- **Por qué:** es el único punto por el que pasan TODAS las llamadas al LLM del módulo, así los reintentos y el backoff se definen una sola vez.

#### `analyze_batch(llm, batch, model, options)`
- **Entrada:** lista de firmas (un batch).
- **Salida:** `{signature_id: veredicto_limpio}` **solo con las respuestas válidas** (puede ser `{}`).
- **Qué hace:**
  1. Prompt = `'SIGNATURES\n' + JSON del batch`.
  2. Si el LLM devuelve un objeto en vez de un array, lo acepta igualmente (`{"results": [...]}` o un único veredicto).
  3. Filtra: solo entradas que sean dict y cuyo `signature_id` esté en el batch enviado.
  4. Pasa cada una por `clean_verdict`.
- **Por qué:** el LLM puede inventarse ids, omitir firmas o devolver otra estructura. Esta función nunca falla: simplemente devuelve menos veredictos y las firmas que falten se reintentan después.

#### `clean_verdict(entry)`
- **Entrada:** un veredicto tal como lo devolvió el LLM.
- **Salida:** dict con `signature_id` + exactamente los 16 campos de `ANALYSIS_DEFAULTS`.
- **Qué hace:** descarta campos desconocidos, rellena los que falten o vengan a `null` con su valor por defecto, y si `classification` no es válida la pone en `unknown` con `needs_manual_review=True`.
- **Por qué:** el Excel final necesita un esquema fijo. Nunca se confía a ciegas en la salida de un LLM.

#### `manual_review_verdict(signature_id)`
- **Salida:** veredicto por defecto con `classification='unknown'`, `needs_manual_review=True` y la nota *"LLM analysis failed"*.
- **Por qué:** ninguna fila se queda sin veredicto. Lo que el LLM no pudo resolver queda marcado para un humano en vez de desaparecer.

#### `run_batches(llm, batches, model, options, verdicts, checkpoint_path)`
- **Entrada:** lista de batches y el dict `verdicts`, que se va rellenando (se modifica in situ).
- **Salida:** nada; actualiza `verdicts` y el fichero de checkpoint.
- **Qué hace:** lanza los batches en un `ThreadPoolExecutor` de 4 workers. Según termina cada uno: añade sus veredictos, guarda el checkpoint y loguea el progreso.
- **Por qué:**
  - Hilos y no procesos: el trabajo es esperar respuestas HTTP (I/O), los hilos bastan.
  - `verdicts` solo se modifica en el hilo principal (dentro de `as_completed`), así no hay condiciones de carrera.
  - Checkpoint tras cada batch: si se corta en la firma 250, se retoma desde ahí.

#### `analyze_signatures(llm, signatures, checkpoint_path, model='default', batch_size=None)`
- **Entrada:** todas las firmas.
- **Salida:** `{signature_id: veredicto}` con **una entrada garantizada por cada firma**.
- **Qué hace:**
  1. Carga el checkpoint; las firmas ya analizadas se saltan.
  2. **Ronda 1:** trocea las pendientes en batches (`batch_size` o el del modelo) y las ejecuta en paralelo.
  3. **Ronda 2:** las que sigan sin veredicto se reenvían **de una en una**.
  4. **Fallback:** las que aún falten reciben `manual_review_verdict`.
- **Por qué:** cuando un batch falla, normalmente es por una firma concreta (payload raro que rompe el JSON). Reenviar individualmente aísla la firma problemática y salva las demás.

#### `get_weight(df, count_column)`
- **Salida:** `Series` numérica con los eventos que representa cada fila (columna `Count`, o 1 si no existe).
- **Por qué:** una fila del export puede representar muchos eventos. Todas las estadísticas se ponderan por este peso para contar **eventos**, no filas.

#### `build_dataset_stats(df, verdicts, count_column)`
- **Entrada:** el DataFrame final (con veredictos) y el dict de veredictos.
- **Salida:** dict con `total_events`, `total_rows`, `rows_pruned_by_score`, `signatures_analyzed_by_llm`, `needs_manual_review`, `by_classification`, `by_risk_level`, `by_attack_type` y `top_offenders` (top 10 IPs atacantes).
- **Por qué:** las cifras las calcula **pandas, no el LLM**. Un LLM se equivoca contando; así los números del informe son exactos y el LLM solo los redacta.

#### `build_reduce_verdicts(df, verdicts, count_column)`
- **Salida:** lista con los 40 veredictos `attack` / `false_positive` de más ocurrencias, solo con los campos de `REDUCE_FIELDS` + `occurrences`.
- **Por qué:** el resumen debe hablar de lo que más impacto tiene, y el prompt tiene que caber en el timeout. Los `benign`/`unknown` no aportan al resumen.

#### `dataset_analysis(llm, df, verdicts, model='default', count_column='Count')`
- **Salida:** dict = respuesta del LLM + todas las estadísticas. Siempre devuelve un dict.
- **Qué hace:** prompt = `STATS` + `VERDICTS` → `ask_json_with_retries` con `max_tokens=1500`. Si falla: `{'summary': 'Reduce step failed'}`. Las estadísticas se añaden siempre, falle o no el LLM.
- **Por qué "reduce":** es un map-reduce. *Map* = un veredicto por firma; *reduce* = una visión de conjunto a partir de ellos.

### 5.3 Checkpoint y salida

#### `load_checkpoint(checkpoint_path)` / `save_checkpoint(checkpoint_path, verdicts)`
- **Entrada / salida:** leen y escriben `{signature_id: veredicto}` en `waf_llm_checkpoint.json`. Si no existe o está corrupto, `load` devuelve `{}`.
- **Por qué:** ~281 llamadas tardan minutos y el gateway puede caerse. Sin checkpoint, un fallo al final obliga a repetir y pagar todo.

#### `save_waf_llm_report(df, summary, output_dir)`
- **Salida:** ruta del Excel `waf_llm_processed_<timestamp>.xlsx`.
- **Qué hace:** hoja `events` (todas las filas originales + las columnas de análisis) y hoja `dataset_analysis` (una fila con el resumen; los dicts y listas se serializan a JSON para que quepan en una celda).
- **Por qué está separada del orquestador:** cuando llegue la vista Django, la descarga usará `download_predefined_excel_report` y esta función se sustituye sin tocar la lógica.

### 5.4 Orquestador

#### `waf_llm_report(input_file, llm, model='default', signature_columns=None, context_columns=None, count_column='Count', cleanup_threshold=10.0, batch_size=None, output_dir=OUTPUT_DIR)`
- **Salida:** `(output_file, summary)`, o `(None, None)` si el export no tiene columnas de firma.
- **Paso a paso:**
  1. `load_waf_export`.
  2. Máscara de pruning: `score >= cleanup_threshold`. Si no existe la columna de score, no se poda nada.
  3. `build_signatures` sobre las filas limpias. Si devuelve `None` → corta.
  4. `analyze_signatures`.
  5. `merge` de los veredictos por `signature_id`. Se restaura el índice original con `set_index` porque `merge` lo reinicia.
  6. `concat` con las filas podadas (ya anotadas) + `sort_index()` → el Excel final conserva **el mismo orden que el original**.
  7. `dataset_analysis`.
  8. `save_waf_llm_report`.
  9. Checkpoint: se borra si todo fue bien; **se conserva si el reduce falló**, para que al relanzar solo se repita el resumen (1 llamada en vez de 281).

---

## 6. Qué pasa cuando algo falla

| Fallo | Qué ocurre | Resultado |
|---|---|---|
| El export no tiene columnas de firma | `logger.error` con las columnas reales | `(None, None)`, cero llamadas al LLM |
| Timeout / 503 / JSON inválido en una llamada | Reintento con feedback tras 10s, 20s, 30s | Transparente si se recupera |
| Un batch falla los 3 intentos | Sus firmas pasan a la ronda individual | Se salvan las firmas "sanas" del batch |
| Una firma falla también individualmente | `manual_review_verdict` | Fila marcada `needs_manual_review=True` |
| El LLM inventa un `signature_id` u omite campos | `analyze_batch` lo filtra, `clean_verdict` rellena | Excel siempre con esquema completo |
| El proceso se corta a medias | Checkpoint en disco | Al relanzar continúa donde estaba |
| Falla solo el resumen final | Excel generado con `summary='Reduce step failed'`, checkpoint conservado | Relanzar = solo 1 llamada |

---

## 7. Tests (18, sin red)

`test_llm_waf_usecase.py` usa un `FakeLlmApi` con la misma superficie que el real
(`get_model` + `ask_json`). Cubren: normalización, agrupación en firmas, rule id sin
normalizar, cabeceras `: Descending`, export sin columnas de firma, pruning,
limpieza de veredictos, opciones por modelo, batches, reintento individual +
manual review, checkpoint, reduce recortado y ordenado, fallo del reduce con
checkpoint conservado, y dos ejecuciones end-to-end.

```
python manage.py test API_cnx.test_llm_waf_usecase
```

---

## 8. Checklist para validar que está como quieres

- [ ] ¿Las 3 columnas de `DEFAULT_SIGNATURE_COLUMNS` son las correctas para definir "mismo evento"? ¿Añadirías el método HTTP o el host?
- [ ] ¿`cleanup_threshold` de 5.0 es el corte que quieres para dar una IP por maliciosa sin consultar al LLM?
- [ ] ¿Te vale que el reduce vea solo los 40 veredictos más frecuentes?
- [ ] En tu log, ¿qué N aparece en `retrying N signatures individually`? (Si es alto, gemma no responde el batch completo → `batch_size=1` u otro modelo.)
- [ ] `LLM_TIMEOUT` a 120-180 en `.env`.
- [ ] Quitar `print(message)` de `LlmApi.ask()` y el bloque `__main__` antes del commit.
- [ ] Decidir dónde va la vista (dentro de AVI WAF o pestaña nueva) para el siguiente paso.
