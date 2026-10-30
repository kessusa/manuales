# EMEAPLAYFLOWS-3782 — `build_access_request_ports` explicado

Endpoint: `GET /validation-matrix/port/?sn_ticket_id=<ticket>` (Serenity, app `validation_matrix`).
Lo consume FRIDA en ProdSecHub, sección **Ports Details**.

## 1. Idea general

- **Las filas de la respuesta nacen de los Access Requests (AR) del ticket.** Un servicio del AR es siempre una fila, esté o no en la matriz.
- **La matriz (`Port`) solo enriquece.** Si un servicio está cubierto por una fila de la matriz, se añaden sus datos. Si no, `matrix_port` llega a `null` y FRIDA pinta "No info".
- **Siempre 2 consultas**, tenga el ticket los puertos que tenga: una a `AccessRequest` y otra a `Port`.
- El cruce con la matriz usa `annotate` + `Case`/`When`, el patrón habitual del proyecto, con **una anotación por servicio** para que dos servicios dentro del mismo rango no se pisen.

```
AccessRequest ──(query 1)──► servicios del AR ──► claves (protocolo, puerto)
                                                          │
Port ──(query 2: annotate Case/When por servicio)─────────┘
                                                          ▼
                                     respuesta: 1 fila por servicio (+ datos de matriz o null)
```

---

## 2. Datos de ejemplo

### Entrada: Access Requests del ticket `649999`

| ar_number | services |
|---|---|
| AR1 | `TCP_22;TCP_48100` |
| AR2 | `TCP_48200;TCP_23581` |

### Matriz de validación (`Port`)

| id | protocol | port_number | service | category |
|---|---|---|---|---|
| 10 | TCP | `22` | SSH | Admin services |
| 20 | TCP | `48000-49500` | MQSeries | Middleware |

### Petición

```
GET /validation-matrix/port/?sn_ticket_id=649999
```

---

## 3. Código completo

### Imports (`validation_matrix/views.py`)

```python
from collections import defaultdict
from functools import reduce
from operator import or_

from django.db.models import BooleanField, Case, CharField, F, Func, IntegerField, Q, Value, When
from django.db.models.functions import Cast

from utils.util_tools import parse_services
```

### Funciones

```python
def build_access_request_ports(sn_ticket_id):
    """Return every AR service of a ticket, enriched with its matching matrix ports."""
    access_requests = (
        AccessRequest.objects
        .filter(task__sn_ticket_id=sn_ticket_id)
        .order_by('ar_number')
        .values_list('ar_number', 'services')
    )
    ar_services = [
        {'ar_number': ar_number, 'ar_protocol': protocol, 'ar_port_number': port_number}
        for ar_number, services in access_requests
        for protocol, port_number in parse_services(services)
    ]
    ports_by_service = get_matrix_ports_by_service(ar_services)

    rows = []
    for ar_service in ar_services:
        matching_ports = ports_by_service.get(get_service_key(ar_service)) or [None]
        rows.extend({**ar_service, 'matrix_port': matrix_port} for matrix_port in matching_ports)
    return rows


def get_service_key(ar_service):
    """Return the (protocol, port) key of an AR service, or None if the port is not numeric."""
    port_number = ar_service['ar_port_number']
    if not port_number.isdigit():
        return None
    return ar_service['ar_protocol'].upper(), int(port_number)


def get_matrix_ports_by_service(ar_services):
    """Map each AR service key to the matrix ports covering it, in a single query."""
    service_keys = sorted({
        service_key for service_key in map(get_service_key, ar_services) if service_key
    })
    if not service_keys:
        return {}

    match_annotations = {
        f'matches_service_{index}': Case(
            When(
                Q(protocol__iexact=protocol, port_start__lte=port_number, port_end__gte=port_number),
                then=Value(True),
            ),
            default=Value(False),
            output_field=BooleanField(),
        )
        for index, (protocol, port_number) in enumerate(service_keys)
    }
    matrix_ports = (
        Port.objects
        .annotate(
            port_start=Cast(Func(F('port_number'), Value('-'), Value(1),
                                 function='SPLIT_PART', output_field=CharField()), IntegerField()),
            port_end=Cast(Func(F('port_number'), Value('-'), Value(-1),
                               function='SPLIT_PART', output_field=CharField()), IntegerField()),
        )
        .annotate(**match_annotations)
        .filter(reduce(or_, (Q(**{annotation_name: True}) for annotation_name in match_annotations)))
    )

    ports_by_service = defaultdict(list)
    for matrix_port in matrix_ports:
        for index, service_key in enumerate(service_keys):
            if getattr(matrix_port, f'matches_service_{index}'):
                ports_by_service[service_key].append(matrix_port)
    return ports_by_service
```

### Uso en el viewset (sin cambios)

```python
    def list(self, request, *args, **kwargs):
        sn_ticket_id = request.query_params.get('sn_ticket_id')
        if not sn_ticket_id:
            return super().list(request, *args, **kwargs)
        rows = build_access_request_ports(sn_ticket_id)
        return Response(AccessRequestPortSerializer(rows, many=True).data)
```

Sin `sn_ticket_id` el endpoint sigue devolviendo la matriz completa, como antes.

---

## 4. Paso a paso con el ejemplo

### Paso 1 — Leer los AR del ticket (query 1)

```python
access_requests = (
    AccessRequest.objects
    .filter(task__sn_ticket_id=sn_ticket_id)
    .order_by('ar_number')
    .values_list('ar_number', 'services')
)
```

- `filter(task__sn_ticket_id=...)`: solo los AR del ticket pedido.
- `values_list(...)`: trae solo dos columnas, sin instanciar modelos. Ahorra memoria.

**Resultado:**
```python
[("AR1", "TCP_22;TCP_48100"), ("AR2", "TCP_48200;TCP_23581")]
```

### Paso 2 — Una fila por servicio

```python
ar_services = [
    {'ar_number': ar_number, 'ar_protocol': protocol, 'ar_port_number': port_number}
    for ar_number, services in access_requests
    for protocol, port_number in parse_services(services)
]
```

`parse_services` (en `utils/util_tools.py`) parte el texto por `;` y cada servicio por el primer `_`. Si `services` viene vacío o mal formado, no falla.

**Resultado:**
```python
[
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "22"},
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "48100"},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "48200"},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "23581"},
]
```

> Aquí queda fijado el número de filas de la respuesta: **4, las del AR**. La matriz puede añadir filas si un servicio coincide con varias filas suyas, pero nunca quitar ninguna.

### Paso 3 — `get_service_key`: clave comparable

```python
def get_service_key(ar_service):
    port_number = ar_service['ar_port_number']
    if not port_number.isdigit():
        return None
    return ar_service['ar_protocol'].upper(), int(port_number)
```

| Entrada | Salida |
|---|---|
| `{"ar_protocol": "tcp", "ar_port_number": "22"}` | `("TCP", 22)` |
| `{"ar_protocol": "TCP", "ar_port_number": "48100"}` | `("TCP", 48100)` |
| `{"ar_protocol": "ICMP", "ar_port_number": ""}` | `None` |

- Protocolo en mayúsculas para que `tcp` y `TCP` sean la misma clave.
- Puerto como `int` para poder compararlo con rangos.
- Si el puerto no es numérico, `None`: ese servicio no se busca en la matriz, pero **sí sale en la respuesta** con `matrix_port = null`.

### Paso 4 — Claves únicas y ordenadas

```python
service_keys = sorted({
    service_key for service_key in map(get_service_key, ar_services) if service_key
})
if not service_keys:
    return {}
```

- `map(get_service_key, ...)` aplica el paso 3 a cada servicio.
- `{ ... }` es un *set*: si dos AR piden el mismo puerto, se busca una sola vez.
- `if service_key` descarta los `None`.
- `sorted(...)` da un orden fijo, así el índice `0, 1, 2…` de cada clave es estable.
- Si no queda ninguna clave, no se consulta la matriz (se ahorra la query 2).

**Resultado:**
```python
[("TCP", 22), ("TCP", 23581), ("TCP", 48100), ("TCP", 48200)]
#   índice 0     índice 1        índice 2        índice 3
```

### Paso 5 — Inicio y fin de cada fila de la matriz (en PostgreSQL)

```python
port_start=Cast(Func(F('port_number'), Value('-'), Value(1),
                     function='SPLIT_PART', output_field=CharField()), IntegerField()),
port_end=Cast(Func(F('port_number'), Value('-'), Value(-1),
                   function='SPLIT_PART', output_field=CharField()), IntegerField()),
```

`SPLIT_PART(texto, '-', n)` devuelve el trozo `n` al partir por `-`. Con `-1` devuelve el último (PostgreSQL 14+; el proyecto usa 18). `Cast` lo convierte a entero.

| port_number | port_start | port_end |
|---|---|---|
| `22` | 22 | 22 |
| `48000-49500` | 48000 | 49500 |

Un puerto suelto y un rango se tratan igual: "¿está el puerto entre inicio y fin?".

### Paso 6 — Un `Case`/`When` por servicio

```python
match_annotations = {
    f'matches_service_{index}': Case(
        When(
            Q(protocol__iexact=protocol, port_start__lte=port_number, port_end__gte=port_number),
            then=Value(True),
        ),
        default=Value(False),
        output_field=BooleanField(),
    )
    for index, (protocol, port_number) in enumerate(service_keys)
}
```

Genera un diccionario con 4 anotaciones. Para el índice 2, por ejemplo:

```python
'matches_service_2': Case(
    When(Q(protocol__iexact='TCP', port_start__lte=48100, port_end__gte=48100), then=True),
    default=False,
)
```

Equivale en SQL a:

```sql
CASE WHEN UPPER(protocol) = 'TCP' AND port_start <= 48100 AND port_end >= 48100
     THEN TRUE ELSE FALSE END AS matches_service_2
```

`.annotate(**match_annotations)` añade las 4 columnas a cada fila de `Port`:

| Fila | matches_service_0 (22) | _1 (23581) | _2 (48100) | _3 (48200) |
|---|---|---|---|---|
| 10 — SSH `22` | ✅ | ❌ | ❌ | ❌ |
| 20 — MQSeries `48000-49500` | ❌ | ❌ | ✅ | ✅ |

> **Por qué una anotación por servicio y no una sola:** un `Case` devuelve solo el **primer** `When` que se cumple. Con un único `Case` con todos los servicios dentro, la fila 20 se anotaría solo con `48100` y `48200` saldría sin datos de matriz aunque sí está cubierto. Con una columna por servicio, la fila 20 marca los dos.

### Paso 7 — Filtrar las filas útiles (sigue siendo la query 2)

```python
.filter(reduce(or_, (Q(**{annotation_name: True}) for annotation_name in match_annotations)))
```

- Por cada anotación se crea `Q(matches_service_N=True)`.
- `reduce(or_, ...)` las une con OR:
  ```python
  Q(matches_service_0=True) | Q(matches_service_1=True) | Q(matches_service_2=True) | Q(matches_service_3=True)
  ```
- Solo llegan a Python las filas de la matriz con **al menos un ✅**. El resto de la matriz se queda en la base de datos.

**Resultado de la query 2:** filas 10 y 20, cada una con sus 4 columnas `matches_service_*`.

### Paso 8 — Repartir filas de la matriz por servicio (Python, sin consultas)

```python
ports_by_service = defaultdict(list)
for matrix_port in matrix_ports:
    for index, service_key in enumerate(service_keys):
        if getattr(matrix_port, f'matches_service_{index}'):
            ports_by_service[service_key].append(matrix_port)
return ports_by_service
```

- Recorre la tabla del paso 6 y, por cada ✅, añade la fila de la matriz a la lista de ese servicio.
- `getattr(matrix_port, 'matches_service_2')` lee la columna anotada.
- `defaultdict(list)` crea la lista vacía automáticamente la primera vez.

**Resultado:**
```python
{
    ("TCP", 22):    [<Port 10 SSH>],
    ("TCP", 48100): [<Port 20 MQSeries>],
    ("TCP", 48200): [<Port 20 MQSeries>],
}
# ("TCP", 23581) no aparece: ninguna fila de la matriz lo cubre
```

### Paso 9 — Construir la respuesta

```python
rows = []
for ar_service in ar_services:
    matching_ports = ports_by_service.get(get_service_key(ar_service)) or [None]
    rows.extend({**ar_service, 'matrix_port': matrix_port} for matrix_port in matching_ports)
return rows
```

- Vuelve a la lista del **paso 2**: el AR manda.
- `ports_by_service.get(...)` busca las filas de la matriz de ese servicio.
- `or [None]`: si no hay ninguna (o la clave es `None`), crea una fila con `matrix_port = None`. **Ningún servicio del AR se pierde.**
- `{**ar_service, 'matrix_port': ...}` copia los datos del AR y añade la fila de la matriz.
- Si un servicio coincide con 2 filas de la matriz, `extend` genera 2 filas.

**Resultado (antes del serializer):**
```python
[
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "22",    "matrix_port": <Port 10>},
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "48100", "matrix_port": <Port 20>},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "48200", "matrix_port": <Port 20>},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "23581", "matrix_port": None},
]
```

---

## 5. Salida final del endpoint

`AccessRequestPortSerializer` combina los campos de `PortSerializer` (datos de la matriz) con los del AR. Si `matrix_port` es `None`, los campos de la matriz salen a `null`.

> Los nombres de los campos de la matriz son ilustrativos; los reales son los de `PortSerializer`.

```json
[
  {
    "ar_number": "AR1",
    "ar_protocol": "TCP",
    "ar_port_number": "22",
    "protocol": "TCP",
    "port_number": "22",
    "service": "SSH",
    "category": "Admin services"
  },
  {
    "ar_number": "AR1",
    "ar_protocol": "TCP",
    "ar_port_number": "48100",
    "protocol": "TCP",
    "port_number": "48000-49500",
    "service": "MQSeries",
    "category": "Middleware"
  },
  {
    "ar_number": "AR2",
    "ar_protocol": "TCP",
    "ar_port_number": "48200",
    "protocol": "TCP",
    "port_number": "48000-49500",
    "service": "MQSeries",
    "category": "Middleware"
  },
  {
    "ar_number": "AR2",
    "ar_protocol": "TCP",
    "ar_port_number": "23581",
    "protocol": null,
    "port_number": null,
    "service": null,
    "category": null
  }
]
```

En FRIDA, la última fila se pinta con el badge del puerto del AR (`TCP 23581`) y "No info" en los datos de matriz.

---

## 6. Rendimiento

| Aspecto | Antes (`get_queryset` sobre `Port`) | Ahora |
|---|---|---|
| Origen de las filas | Matriz | Access Requests |
| Puertos fuera de la matriz | Se perdían (bug 649094) | Salen con `null` |
| Consultas | 1 por servicio (N+1) | 2 fijas |
| Comparación de rangos | Python, `port_in_range` | PostgreSQL, `SPLIT_PART` + `Case`/`When` |
| 2 servicios en el mismo rango | — | Los dos con datos |
| Filas de matriz cargadas en memoria | Todas | Solo las que cubren algún servicio |

El número de anotaciones `matches_service_*` es el de servicios **distintos** del ticket, que suele ser pequeño.

---

## 7. Tests (`validation_matrix/tests.py`)

Ejecutar: `python manage.py test validation_matrix`

| Caso | Entrada | Esperado |
|---|---|---|
| Puertos fuera de matriz (649094) | `TCP_23581;TCP_23582` | 2 filas, `matrix_port` a `null` |
| Puerto exacto | `TCP_22` | 1 fila con datos de SSH |
| Puerto dentro de rango | `TCP_48100` | 1 fila con datos de MQSeries |
| **Dos servicios en el mismo rango** | `TCP_48100;TCP_48200` | 2 filas, **las dos** con MQSeries |
| Mismo puerto en dos AR | AR1 y AR2 con `TCP_22` | 2 filas, cada una con su `ar_number` |
| Un servicio cubierto por 2 filas de la matriz | `TCP_22` con dos filas SSH | 2 filas |
| `services` vacío o puerto no numérico | `""`, `ICMP_` | No falla; sale con `null` si hay servicio |
| Mayúsculas | `tcp_22` contra `TCP` | Coincide |
| Número de consultas | Varios AR y puertos | `assertNumQueries(2)` |
| Sin `sn_ticket_id` | `GET /validation-matrix/port/` | Matriz completa, como antes |
