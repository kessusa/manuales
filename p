# Flows to Code — cómo funciona, paso a paso

Fichero: `templates/tools/firewall_components/ticket_proposal_component.html`

Esta guía sigue **un solo ejemplo** de principio a fin: qué datos llegan al template, qué decide cada bloque y qué texto acaba en el portapapeles al pulsar **Copy**.

> Dos piezas no las he visto en código y se describen por cómo se usan en el template:
> el filtro `has_drop` (en `custom_filters.py`) y las líneas del `card-header` de cada AR (~210–260).

---

## 0. Qué problema resuelve

La sección **Flows to Code** lista los flujos que el firewall **bloquea** (acción `drop`) y que, por tanto, hay que abrir. El texto se copia en el formato que se pega en Playflows.

El bug del ticket (ejemplo: ticket 644038) era que la sección salía aunque no hubiera nada que abrir. Se veía el título "Flows to Code" con la tabla vacía. La solución es que la sección **solo se pinte si el AR tiene algún drop**.

---

## 1. Mapa del fichero

| Líneas | Bloque | Qué pinta |
|---|---|---|
| 1–6 | Cabecera | "Show result(s)" y botón de cerrar |
| 8–180 | Resultados por AR | Todas las reglas (accept y drop) de match flow y de CIS |
| 182–204 | Others Considerations | Mensajes de `firewall_policy_list \| generate_messages` |
| ~206–325 | **Flows to Code** | Solo los drops, con botón Copy por fila |
| 327–335 | `<style>` | Muestra el título "Flows to Code" una sola vez |
| 337–393 | `<script>` | Lógica del botón Copy y de los iconos del collapse |

Esta guía trata los bloques de **~206 en adelante**.

---

## 2. Datos de entrada del ejemplo

La vista manda al template una variable `result`: una lista con un elemento por AR del ticket.

```python
result = [
    {
        'ar_number': 100,
        'match_flow_results': [
            {'tag': 'EMEA_FW_A', 'position': 12,
             'source': ('10.0.0.1', 'SRV_APP01'), 'destination': ('10.1.0.5', 'DB01'),
             'service': 'tcp-1521', 'action': 'drop', 'section': 'DB access', 'comment': ''},
            {'tag': 'EMEA_FW_A', 'position': 12,
             'source': ('10.0.0.2', 'SRV_APP02'), 'destination': ('10.1.0.5', 'DB01'),
             'service': 'tcp-1521', 'action': 'drop', 'section': 'DB access', 'comment': ''},
            {'tag': 'EMEA_FW_A', 'position': 30,
             'source': ('10.0.0.3', 'SRV_WEB01'), 'destination': ('10.1.0.9', 'API01'),
             'service': 'tcp-443', 'action': 'accept', 'section': 'Web', 'comment': ''},
            {'tag': 'EMEA_FW_B', 'position': 5,
             'source': ('10.0.0.1', 'SRV_APP01'), 'destination': ('10.1.0.5', 'DB01'),
             'service': 'tcp-1521', 'action': 'drop', 'section': 'Cleanup', 'comment': ''},
        ],
        'cis_result': [],
    },
    {
        'ar_number': 200,
        'match_flow_results': [
            {'tag': 'EMEA_FW_A', 'position': 30,
             'source': ('10.0.0.7', 'SRV_WEB02'), 'destination': ('10.1.0.9', 'API01'),
             'service': 'tcp-443', 'action': 'accept', 'section': 'Web', 'comment': ''},
        ],
        'cis_result': [],
    },
]
```

En el ejemplo, `source` y `destination` son pares de dos valores. El template usa `el.0` y `el.1`: la tabla muestra los dos con una flecha y la copia usa solo `el.0`. Aquí suponemos que son IP → nombre.

Resumen del ejemplo:

- **AR 100**: tres reglas en drop (dos en FW_A posición 12 y una en FW_B posición 5) y una en accept (FW_A posición 30).
- **AR 200**: todo en accept, así que no hay nada que abrir.

---

## 3. Paso 1 — ¿Se pinta la sección para este AR?

```django
<div class="mt-5">
  {% for item in result %}
    {% if item.match_flow_results|has_drop or item.cis_result|has_drop %}
      ... sección Flows to Code de este AR ...
    {% endif %}
  {% endfor %}
</div>
```

El bucle recorre los AR uno a uno. Por su uso aquí, `has_drop` devuelve `True` si la lista tiene alguna regla con `drop`.

| AR | `match_flow_results\|has_drop` | `cis_result\|has_drop` | ¿Se pinta? |
|---|---|---|---|
| 100 | True | False | **Sí** |
| 200 | False | False | **No** |

**Este `if` es el arreglo del ticket.** El AR 200 no genera nada: ni título ni tabla vacía.

---

## 4. Paso 2 — Contenedor y título único

Cada AR que pasa el `if` genera esta estructura:

```html
<div class="flows-to-code-container">
  <div class="card mb-4 shadow-none">
    <div class="section-header-trigger">
      <h6 class="fw-bold">Flows to Code</h6>
    </div>
    ... card-header del AR y tabla ...
  </div>
</div>
```

Con tres AR con drops habría tres títulos "Flows to Code". El CSS (327–335) lo evita:

```css
.section-header-trigger { display: none; }                      /* oculta todos */
.flows-to-code-container .card:first-of-type
    .section-header-trigger { display: block; margin-bottom: 1rem; }  /* menos el primero */
```

Resultado en pantalla:

```
Flows to Code          <- un solo título
[ tarjeta AR 100 ]
[ tarjeta AR ...  ]    <- las siguientes, sin título
```

---

## 5. Paso 3 — La tarjeta de cada AR se abre y se cierra

Cada tarjeta tiene un `card-header` clicable:

```html
<div class="card-header ..." role="button"
     data-bs-toggle="collapse"
     data-bs-target="#flows-collapse-100"
     aria-expanded="false" aria-controls="flows-collapse-100">
```

- Al pulsarlo, Bootstrap abre o cierra el bloque `#flows-collapse-100`, que contiene la tabla.
- `aria-expanded="false"` indica que empieza cerrado.
- El JS (líneas ~388–397) solo cambia el icono:

```javascript
$('.collapse').on('show.bs.collapse', ...)  // fa-chevron-down -> fa-chevron-up
$('.collapse').on('hide.bs.collapse', ...)  // fa-chevron-up   -> fa-chevron-down
```

---

## 6. Paso 4 — De la lista de reglas a las filas de la tabla

Esta es la parte más importante. El template convierte la lista plana de reglas en **una fila por firewall y posición bloqueada**, en tres pasos:

```django
{% regroup item.match_flow_results by tag as match_flows_by_tag %}
{% for tag_group in match_flows_by_tag %}
  {% regroup tag_group.list by position as flows_by_position %}
  {% for position_group in flows_by_position %}
    {% with position_group.list.0 as first_rule %}
      {% if 'drop' in first_rule.action %}
        <tr> ... fila ... </tr>
      {% endif %}
    {% endwith %}
  {% endfor %}
{% endfor %}
```

### 4a. Agrupar por firewall (`regroup ... by tag`)

```
match_flows_by_tag
├── grouper = 'EMEA_FW_A'   list = [regla pos12, regla pos12, regla pos30]
└── grouper = 'EMEA_FW_B'   list = [regla pos5]
```

### 4b. Dentro de cada firewall, agrupar por posición (`regroup ... by position`)

```
EMEA_FW_A
├── grouper = 12   list = [10.0.0.1 drop, 10.0.0.2 drop]
└── grouper = 30   list = [10.0.0.3 accept]
EMEA_FW_B
└── grouper = 5    list = [10.0.0.1 drop]
```

### 4c. Coger la primera regla del grupo y filtrar por drop

`first_rule` es `position_group.list.0`. Todas las reglas de una misma posición tienen la misma acción, sección y comentario, así que la primera sirve de representante.

| Firewall | Posición | `first_rule.action` | ¿Fila? |
|---|---|---|---|
| EMEA_FW_A | 12 | drop | **Sí** |
| EMEA_FW_A | 30 | accept | No |
| EMEA_FW_B | 5 | drop | **Sí** |

Salen **2 filas**.

> **Ojo:** `regroup` solo junta elementos **consecutivos**. Si la lista llegara desordenada (FW_A, FW_B, FW_A), FW_A saldría en dos grupos separados. La lista tiene que venir ordenada por `tag` y `position` desde la vista.

---

## 7. Paso 5 — Rellenar las columnas de cada fila

Dentro de la fila, sources, destinations y services salen de **todas** las reglas del grupo (`position_group.list`), sin duplicados gracias a `unique_items`:

```django
{% for el in position_group.list|unique_items:"source" %}
  {{ el.0 }} <i class="fas fa-long-arrow-alt-right"></i>{{ el.1 }}<br>
{% empty %}-{% endfor %}
```

Para **EMEA_FW_A / posición 12**:

| Columna | Valor mostrado |
|---|---|
| Tag | EMEA_FW_A |
| Source | 10.0.0.1 → SRV_APP01<br>10.0.0.2 → SRV_APP02 |
| Destination | 10.1.0.5 → DB01 (aparece dos veces en los datos, `unique_items` lo deja en una) |
| Port | tcp-1521 |
| Copy | botón |

Si una lista está vacía, `{% empty %}` pinta un guion `-`.

---

## 8. Paso 6 — El div oculto con los datos para copiar

La tabla está formateada para leerla, con flechas, nombres y `<br>`. Para copiar hace falta texto limpio, así que cada fila lleva además un `div` **oculto** (`d-none`):

```django
<button type="button" class="btn btn-sm btn-outline-primary copy-btn"
        data-content-id="to-code-{{ item.ar_number }}-{{ forloop.parentloop.counter }}-{{ forloop.counter }}">
  <i class="far fa-copy me-1"></i>Copy
</button>

<div id="to-code-{{ item.ar_number }}-{{ forloop.parentloop.counter }}-{{ forloop.counter }}" class="d-none">
  <div class="tag-line">{{ tag_group.grouper }}</div>
  <div class="src-section">{% for el in ...source %}<div class="src-line">{{ el.0 }}</div>{% endfor %}</div>
  <div class="dst-section">{% for el in ...destination %}<div class="dst-line">{{ el.0 }}</div>{% endfor %}</div>
  <div class="srv-section">{% for srv in ...service %}<div class="srv-line">{{ srv }}</div>{% endfor %}</div>
</div>
```

**Cómo se forma el id:** `to-code-<AR>-<nº de firewall>-<nº de posición>`

- `forloop.parentloop.counter` es el contador del bucle de firewalls (1, 2…).
- `forloop.counter` es el contador del bucle de posiciones dentro de ese firewall.

| Fila | Firewall (contador) | Posición (contador) | id |
|---|---|---|---|
| FW_A / 12 | 1 | 1 | `to-code-100-1-1` |
| FW_A / 30 | 1 | 2 | *(no se pinta, es accept)* |
| FW_B / 5 | 2 | 1 | `to-code-100-2-1` |

El botón y el div comparten id, y así el JS sabe qué div leer. Los contadores cuentan también las posiciones que no se pintan, por eso los números pueden saltarse alguno. No es un problema: solo importa que sean únicos.

El HTML oculto de la primera fila queda así:

```html
<div id="to-code-100-1-1" class="d-none">
  <div class="tag-line">EMEA_FW_A</div>
  <div class="src-section"><div class="src-line">10.0.0.1</div><div class="src-line">10.0.0.2</div></div>
  <div class="dst-section"><div class="dst-line">10.1.0.5</div></div>
  <div class="srv-section"><div class="srv-line">tcp-1521</div></div>
</div>
```

---

## 9. Paso 7 — Qué hace el JS al pulsar Copy

```javascript
$('.copy-btn').click(function (event) {
    event.stopPropagation();
    const contentId = $(this).data('content-id');                // "to-code-100-1-1"
    const contentElement = document.getElementById(contentId);  // el div oculto

    if (contentElement) {
        let lines = [];
        lines.push(contentElement.querySelector('.tag-line').textContent.trim());

        lines.push('SRC');
        contentElement.querySelectorAll('.src-line').forEach(el => lines.push(el.textContent.trim()));

        lines.push('DST');
        contentElement.querySelectorAll('.dst-line').forEach(el => lines.push(el.textContent.trim()));

        lines.push('SRV');
        contentElement.querySelectorAll('.srv-line').forEach(el => lines.push(el.textContent.trim()));

        const formattedText = lines.join('\n');

        const tempElement = document.createElement('textarea');
        tempElement.value = formattedText;
        document.body.appendChild(tempElement);
        tempElement.select();
        document.execCommand('copy');
        document.body.removeChild(tempElement);

        iziToast.success({position: 'topRight', message: 'Text Copied'});
    }
});
```

Paso a paso con la fila FW_A / 12:

| Paso | Qué hace | Resultado |
|---|---|---|
| 1 | `stopPropagation()` | El clic no sube a elementos padre, así que no abre ni cierra el collapse sin querer |
| 2 | Lee `data-content-id` | `"to-code-100-1-1"` |
| 3 | Busca el div oculto | `<div id="to-code-100-1-1">` |
| 4 | Mete el tag | `["EMEA_FW_A"]` |
| 5 | `SRC` + cada `.src-line` | `[..., "SRC", "10.0.0.1", "10.0.0.2"]` |
| 6 | `DST` + cada `.dst-line` | `[..., "DST", "10.1.0.5"]` |
| 7 | `SRV` + cada `.srv-line` | `[..., "SRV", "tcp-1521"]` |
| 8 | `join('\n')` | Texto con una línea por elemento |
| 9 | textarea temporal + `execCommand('copy')` | Texto en el portapapeles |
| 10 | `iziToast` | Aviso "Text Copied" arriba a la derecha |

---

## 10. Los drops de CIS

Después de los drops de match flow, el mismo bloque repite la lógica con `item.cis_result` (comentario `{# --- CIS FLOWS DROPS --- #}`):

- Mismo `regroup` por tag y por posición, y mismo `if 'drop' in first_rule.action`.
- Mismas columnas y mismo botón.
- La única diferencia es el **prefijo del id**: `to-code-cis-<AR>-<n>-<n>`. Así no choca con los ids del match flow del mismo AR, que pueden tener los mismos contadores.

El JS no distingue entre los dos: lee el `data-content-id` del botón, sea cual sea.

---

## 11. Salida final del ejemplo

### En pantalla

```
Flows to Code
┌───────────────────────────────────────────────────────────────┐
│ AR 100                                                     ▼  │  <- card-header (collapse)
├───────────┬──────────────────────┬───────────────┬──────────┬─┤
│ Tag       │ Source               │ Destination   │ Port     │ │
├───────────┼──────────────────────┼───────────────┼──────────┼─┤
│ EMEA_FW_A │ 10.0.0.1 → SRV_APP01 │ 10.1.0.5 →    │ tcp-1521 │Copy
│           │ 10.0.0.2 → SRV_APP02 │   DB01        │          │ │
├───────────┼──────────────────────┼───────────────┼──────────┼─┤
│ EMEA_FW_B │ 10.0.0.1 → SRV_APP01 │ 10.1.0.5 →    │ tcp-1521 │Copy
│           │                      │   DB01        │          │ │
└───────────┴──────────────────────┴───────────────┴──────────┴─┘

(AR 200 no aparece: no tiene drops)
```

### En el portapapeles

Copy en la fila **EMEA_FW_A**:

```
EMEA_FW_A
SRC
10.0.0.1
10.0.0.2
DST
10.1.0.5
SRV
tcp-1521
```

Copy en la fila **EMEA_FW_B**:

```
EMEA_FW_B
SRC
10.0.0.1
DST
10.1.0.5
SRV
tcp-1521
```

---

## 12. Cosas a tener en cuenta

- **Orden de los datos.** `regroup` necesita la lista ordenada por `tag` y `position`. Si un firewall sale partido en dos grupos, el problema está en el orden con que llega desde la vista.
- **`has_drop` frente al `if` de cada fila.** La sección se abre si `has_drop` es `True`, y cada fila se pinta si la primera regla de su posición es drop. Las dos condiciones deben estar alineadas: si `has_drop` diera `True` en un caso en que ninguna primera regla es drop, saldría el título sin filas, que es el síntoma del ticket.
- **Handler repetido.** Al final del `<script>` hay un segundo `$('.copy-btn').click(function (e) { e.stopPropagation(); })`. El primer handler ya hace `stopPropagation()`, así que este sobra. Se puede quitar en una limpieza, sin cambiar el comportamiento.
- **`execCommand('copy')`** está marcado como obsoleto en los navegadores, pero sigue funcionando y es el patrón que usa el resto del dashboard.

---

## 13. Cómo comprobarlo a mano

1. Abre un ticket con algún AR en drop. Debe salir **un** título "Flows to Code" y una tarjeta por AR con drops.
2. Abre uno con todo en accept (por ejemplo el 644038). **No** debe salir la sección.
3. Pulsa Copy en una fila y pégalo en un editor. El formato debe ser `TAG / SRC / … / DST / … / SRV / …`, con una línea por valor.
4. Pulsar Copy **no** debe abrir ni cerrar la tarjeta.
