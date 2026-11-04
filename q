# EMEAPLAYFLOWS-3782: FRIDA, "Ports Details" con todos los puertos del AR

Documento final del ticket: qué se pedía, qué estaba roto, qué se ha cambiado en **Serenity** y en **ProdSecHub**, y cómo funciona cada pieza paso a paso, con ejemplos de entrada y salida de las funciones y de las variables intermedias.

---

## 0. Qué pedía el ticket

| # | Petición | Dónde se resuelve |
|---|---|---|
| 1 | En **Ports Details**, mostrar **todos** los puertos de los Access Requests (AR), no solo los que están en la matriz de validación | Serenity (`validation_matrix`) + ProdSecHub (plantillas) |
| 2 | Renombrar **Exposition → Exposure** y **Labelling-system → Label-system** | ProdSecHub (plantillas) |
| 3 | Investigar por qué el ticket **649094** no mostraba nada | Serenity + ProdSecHub (`bookmark/views.py`, `API_cnx/serenity.py`) |

---

## 1. Causas raíz encontradas

| Causa | Efecto | Proyecto |
|---|---|---|
| **A.** `PortViewSet.get_queryset` partía de la tabla `Port` (matriz) | Los puertos del AR que no están en la matriz desaparecían. El 649094 (`TCP_23581;TCP_23582`) salía vacío | Serenity |
| **B.** El parseo de `services` con `split('_')` era frágil | Un `services` vacío o sin `_` rompía la petición | Serenity |
| **C.** Una consulta por cada servicio del AR (N+1) | La latencia crecía con el número de puertos | Serenity |
| **D.** URL con doble barra en `get_services`: `//validation-matrix/port` | Serenity respondía 404 (HTML) y el `print(response.json())` daba un 500 | ProdSecHub |
| **E.** `ajax_get_frida_ar_data` hacía `return JsonResponse({})` si **una** IP no tenía workload ni etiquetas | Las IP externas (`EXT`) nunca tienen workload, así que se perdía **todo** el ticket | ProdSecHub |

---

## 2. Mapa de cambios

| Proyecto | Fichero | Cambio |
|---|---|---|
| Serenity | `utils/util_tools.py` | Nueva `parse_services` (movida aquí desde la vista, comentario del PR) |
| Serenity | `validation_matrix/views.py` | `build_access_request_ports`, `get_service_key`, `get_matrix_ports_by_service`; `PortViewSet.list` reescrito |
| Serenity | `validation_matrix/serializers.py` | Nuevo `AccessRequestPortSerializer` |
| Serenity | `validation_matrix/schema.py` | Descripción del endpoint corregida |
| Serenity | `validation_matrix/tests.py` | Tests del endpoint |
| ProdSecHub | `API_cnx/serenity.py` | URL de `get_services` corregida y `print` eliminado |
| ProdSecHub | `bookmark/views.py` | Sin `return JsonResponse({})` en IP sin datos; rama "NO INFO" en `check_all_access_requests` |
| ProdSecHub | `search_components/frida_env_result_component.html` | "No info" en gris en lugar de `None` en rojo |
| ProdSecHub | `search_components/frida_expo_layer_result_component.html` | Igual que el anterior |
| ProdSecHub | `search_components/frida_service_component.html` | Agrupación por AR (`regroup` + `rowspan`) y puerto del AR solo si no está en la matriz |
| ProdSecHub | `templates/global_search.html` | Cabeceras AR / AR port, Exposure, Label-system, `colspan` y limpieza de las `F` sueltas |

---

## 3. Serenity

### 3.1 `utils/util_tools.py`: `parse_services`

```python
def parse_services(services):
    """Return (protocol, port_number) tuples from an AR services value."""
    if not services:
        return []
    if isinstance(services, str):
        services = services.split(';')
    parsed = []
    for service in services:
        protocol, _, port_number = str(service).strip().partition('_')
        if protocol:
            parsed.append((protocol, port_number))
    return parsed
```

**Qué hace, línea a línea:**

| Línea | Qué hace | Por qué |
|---|---|---|
| `if not services: return []` | Si `services` es `None` o `""`, devuelve lista vacía | Antes rompía (causa B) |
| `services.split(';')` | `"TCP_22;UDP_53"` → `["TCP_22", "UDP_53"]` | Un AR puede pedir varios servicios |
| `isinstance(services, str)` | Si ya llega como lista, no la vuelve a partir | Acepta los dos formatos |
| `.strip()` | Quita espacios: `" TCP_22 "` → `"TCP_22"` | Datos heredados con espacios |
| `.partition('_')` | `"TCP_22"` → `("TCP", "_", "22")` | A diferencia de `split`, **nunca** falla: sin `_` devuelve `("ICMP", "", "")` |
| `if protocol:` | Descarta trozos vacíos (`";;"`) | Evita filas basura |

**Ejemplos de entrada y salida:**

| Entrada | Salida |
|---|---|
| `"TCP_22;TCP_48100"` | `[("TCP", "22"), ("TCP", "48100")]` |
| `"UDP_8;UDP_0"` | `[("UDP", "8"), ("UDP", "0")]` |
| `"TCP_6372-6377"` | `[("TCP", "6372-6377")]` |
| `"ICMP"` | `[("ICMP", "")]` |
| `""` / `None` | `[]` |
| `["TCP_443", " udp_53 "]` | `[("TCP", "443"), ("udp", "53")]` |

---

### 3.2 `validation_matrix/views.py`

#### Imports

```python
from collections import defaultdict
from functools import reduce
from operator import or_

from django.db.models import BooleanField, Case, CharField, F, Func, IntegerField, Q, Value, When
from django.db.models.functions import Cast
from rest_framework import mixins
from rest_framework.permissions import DjangoModelPermissions
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from serenity_app.models import AccessRequest
from utils.util_tools import parse_services
from validation_matrix.models import Port
from validation_matrix.schema import PortSchema
from validation_matrix.serializers import AccessRequestPortSerializer
```

#### Código completo

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


class PortViewSet(mixins.ListModelMixin, GenericViewSet):
    queryset = Port.objects.all()
    serializer_class = AccessRequestPortSerializer
    permission_classes = [DjangoModelPermissions]
    schema = PortSchema()
    pagination_class = None

    def list(self, request, *args, **kwargs):
        sn_ticket_id = request.query_params.get('sn_ticket_id')
        if not sn_ticket_id:
            return Response([])
        rows = build_access_request_ports(sn_ticket_id)
        return Response(self.get_serializer(rows, many=True).data)
```

#### Idea general

```
AccessRequest ──(query 1)──► servicios del AR ──► claves (protocolo, puerto)
                                                          │
Port ──(query 2: annotate Case/When por servicio)─────────┘
                                                          ▼
                       respuesta: 1 fila por servicio del AR (+ datos de matriz o null)
```

- **Las filas nacen del AR.** La matriz solo añade datos, nunca quita filas.
- **Siempre 2 consultas**, tenga el ticket los puertos que tenga.
- **Un `Case`/`When` por servicio** (patrón habitual del proyecto), para que dos puertos dentro del mismo rango no se pisen.

#### Datos de ejemplo usados en todo el recorrido

**Access Requests del ticket `649999`:**

| ar_number | services |
|---|---|
| AR1 | `TCP_22;TCP_48100` |
| AR2 | `TCP_48200;TCP_23581` |

**Matriz (`Port`):**

| id | protocol | port_number | service | category |
|---|---|---|---|---|
| 10 | TCP | `22` | SSH | Admin services |
| 20 | TCP | `48000-49500` | MQSeries | Middleware |

**Petición:** `GET /validation-matrix/port/?sn_ticket_id=649999`

---

#### Paso 1: `PortViewSet.list` recibe la petición

```python
sn_ticket_id = request.query_params.get('sn_ticket_id')   # "649999"
if not sn_ticket_id:
    return Response([])
```

| Petición | `sn_ticket_id` | Respuesta |
|---|---|---|
| `/validation-matrix/port/?sn_ticket_id=649999` | `"649999"` | Sigue al paso 2 |
| `/validation-matrix/port/` | `None` | `200 []` |

**Por qué `[]` y no la matriz completa:** el `serializer_class` es ahora `AccessRequestPortSerializer` (comentario del PR), que espera filas con `ar_number` y `matrix_port`, no objetos `Port`. Servir la matriz entera con él daría campos vacíos. El único consumidor es FRIDA y siempre manda el ticket.

**Por qué se mantiene `queryset = Port.objects.all()`:** `DjangoModelPermissions` lo necesita para saber sobre qué modelo comprobar permisos, aunque `list` no lo use.

#### Paso 2: leer los AR del ticket (query 1)

```python
access_requests = (
    AccessRequest.objects
    .filter(task__sn_ticket_id=sn_ticket_id)
    .order_by('ar_number')
    .values_list('ar_number', 'services')
)
```

- `values_list` trae solo dos columnas, sin instanciar modelos: menos memoria.

**Valor de `access_requests`:**
```python
[("AR1", "TCP_22;TCP_48100"), ("AR2", "TCP_48200;TCP_23581")]
```

#### Paso 3: una fila por servicio del AR

```python
ar_services = [
    {'ar_number': ar_number, 'ar_protocol': protocol, 'ar_port_number': port_number}
    for ar_number, services in access_requests
    for protocol, port_number in parse_services(services)
]
```

**Valor de `ar_services`:**
```python
[
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "22"},
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "48100"},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "48200"},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "23581"},
]
```

> Aquí queda fijado el número mínimo de filas de la respuesta: **4, las del AR**.

#### Paso 4: `get_service_key`, clave comparable

| Entrada (`ar_service`) | Salida |
|---|---|
| `{"ar_protocol": "tcp", "ar_port_number": "22"}` | `("TCP", 22)` |
| `{"ar_protocol": "TCP", "ar_port_number": "48100"}` | `("TCP", 48100)` |
| `{"ar_protocol": "ICMP", "ar_port_number": ""}` | `None` |
| `{"ar_protocol": "TCP", "ar_port_number": "6372-6377"}` | `None` |

- Protocolo en mayúsculas: `tcp` y `TCP` son la misma clave.
- Puerto como `int`, para compararlo con rangos.
- Si el puerto no es numérico, `None`: no se busca en la matriz, pero **sí sale en la respuesta** con `matrix_port = None`.

#### Paso 5: claves únicas y ordenadas (`get_matrix_ports_by_service`)

```python
service_keys = sorted({
    service_key for service_key in map(get_service_key, ar_services) if service_key
})
if not service_keys:
    return {}
```

- El `{...}` es un *set*: si dos AR piden el mismo puerto, se busca una sola vez.
- `if service_key` descarta los `None`.
- `sorted` fija el orden, así cada clave tiene un índice estable.
- Sin claves, no hay query 2. Además evita el `TypeError` de `reduce` sobre una lista vacía.

**Valor de `service_keys`:**
```python
[("TCP", 22), ("TCP", 23581), ("TCP", 48100), ("TCP", 48200)]
#  índice 0     índice 1        índice 2        índice 3
```

#### Paso 6: inicio y fin de cada fila de la matriz (en PostgreSQL)

```python
port_start=Cast(Func(F('port_number'), Value('-'), Value(1),
                     function='SPLIT_PART', output_field=CharField()), IntegerField()),
port_end=Cast(Func(F('port_number'), Value('-'), Value(-1),
                   function='SPLIT_PART', output_field=CharField()), IntegerField()),
```

`SPLIT_PART(texto, '-', n)` devuelve el trozo `n`; con `-1`, el último (PostgreSQL 14+, el proyecto usa 18). Todos los `Port.port_number` son `NNN` o `NNN-NNN`.

| `port_number` | `port_start` | `port_end` |
|---|---|---|
| `22` | 22 | 22 |
| `48000-49500` | 48000 | 49500 |

Un puerto suelto y un rango se tratan igual: "¿está el puerto entre inicio y fin?". Van en un `annotate` **separado** del siguiente, porque los `When` necesitan poder referenciar `port_start` y `port_end`.

#### Paso 7: un `Case`/`When` por servicio

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

**Valor de `match_annotations`** (resumido):
```python
{
    'matches_service_0': Case(When(TCP y 22 entre inicio y fin, then=True), default=False),
    'matches_service_1': Case(When(TCP y 23581 ...), ...),
    'matches_service_2': Case(When(TCP y 48100 ...), ...),
    'matches_service_3': Case(When(TCP y 48200 ...), ...),
}
```

SQL equivalente de una anotación:
```sql
CASE WHEN UPPER(protocol) = 'TCP' AND port_start <= 48100 AND port_end >= 48100
     THEN TRUE ELSE FALSE END AS matches_service_2
```

Lo que devuelve la base de datos tras `.annotate(**match_annotations)`:

| Fila | m_0 (22) | m_1 (23581) | m_2 (48100) | m_3 (48200) |
|---|---|---|---|---|
| 10, SSH `22` | ✅ | ❌ | ❌ | ❌ |
| 20, MQSeries `48000-49500` | ❌ | ❌ | ✅ | ✅ |

> **Por qué una anotación por servicio:** un `Case` devuelve solo el **primer** `When` que se cumple. Con un único `Case` con todos los servicios, la fila 20 se anotaría solo con 48100 y el 48200 saldría sin datos aunque está cubierto.

#### Paso 8: filtrar (sigue siendo la query 2)

```python
.filter(reduce(or_, (Q(**{annotation_name: True}) for annotation_name in match_annotations)))
```

`reduce(or_, ...)` construye:
```python
Q(matches_service_0=True) | Q(matches_service_1=True) | Q(matches_service_2=True) | Q(matches_service_3=True)
```

Solo llegan a Python las filas con **algún** ✅: aquí, la 10 y la 20.

#### Paso 9: repartir filas de la matriz por servicio (Python, sin consultas)

```python
ports_by_service = defaultdict(list)
for matrix_port in matrix_ports:
    for index, service_key in enumerate(service_keys):
        if getattr(matrix_port, f'matches_service_{index}'):
            ports_by_service[service_key].append(matrix_port)
```

**Valor de `ports_by_service`:**
```python
{
    ("TCP", 22):    [<Port 10 SSH>],
    ("TCP", 48100): [<Port 20 MQSeries>],
    ("TCP", 48200): [<Port 20 MQSeries>],
}
# ("TCP", 23581) no aparece: ninguna fila de la matriz lo cubre
```

#### Paso 10: construir las filas (aquí se junta lo que está y lo que no está en la matriz)

```python
rows = []
for ar_service in ar_services:
    matching_ports = ports_by_service.get(get_service_key(ar_service)) or [None]
    rows.extend({**ar_service, 'matrix_port': matrix_port} for matrix_port in matching_ports)
return rows
```

- El bucle recorre **`ar_services`** (todo lo que pide el AR), no la matriz.
- `or [None]` es el punto exacto en el que un puerto fuera de la matriz **se queda** en vez de desaparecer.
- Si un servicio coincide con dos filas de la matriz, `extend` genera dos filas.

| Servicio | `ports_by_service.get(...)` | Tras `or [None]` | Fila |
|---|---|---|---|
| AR1 TCP 22 | `[Port 10]` | `[Port 10]` | con SSH |
| AR1 TCP 48100 | `[Port 20]` | `[Port 20]` | con MQSeries |
| AR2 TCP 48200 | `[Port 20]` | `[Port 20]` | con MQSeries |
| AR2 TCP 23581 | `None` | `[None]` | `matrix_port = None` |

**Valor de `rows`:**
```python
[
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "22",    "matrix_port": <Port 10>},
    {"ar_number": "AR1", "ar_protocol": "TCP", "ar_port_number": "48100", "matrix_port": <Port 20>},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "48200", "matrix_port": <Port 20>},
    {"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "23581", "matrix_port": None},
]
```

---

### 3.3 `validation_matrix/serializers.py`: `AccessRequestPortSerializer`

```python
class AccessRequestPortSerializer(serializers.Serializer):
    """One access request service with its matching matrix port, if any."""
    ar_number = serializers.CharField()
    ar_port_number = serializers.CharField(allow_blank=True)
    ar_protocol = serializers.CharField()

    def to_representation(self, instance):
        data = super().to_representation(instance)
        matrix_port = instance.get('matrix_port')
        if matrix_port:
            data.update(PortSerializer(matrix_port).data)
        else:
            data.update(dict.fromkeys(PortSerializer().fields))
        return data
```

| Parte | Qué hace |
|---|---|
| Tres campos `ar_*` | Se leen del diccionario de cada fila. `allow_blank=True` admite el puerto vacío de `ICMP` |
| `super().to_representation(instance)` | Produce `{"ar_number": "AR2", "ar_port_number": "23581", "ar_protocol": "TCP"}` |
| `PortSerializer(matrix_port).data` | Si hay coincidencia, añade los campos de la matriz con el **mismo** serializer de siempre, así ProdSecHub recibe las mismas claves |
| `dict.fromkeys(PortSerializer().fields)` | Si no hay coincidencia, añade todas esas claves a `None` (`null` en JSON). La respuesta tiene siempre la misma forma |

**Entrada → salida:**

```python
# Entrada (una fila de rows)
{"ar_number": "AR2", "ar_protocol": "TCP", "ar_port_number": "23581", "matrix_port": None}
```
```json
// Salida
{"ar_number": "AR2", "ar_port_number": "23581", "ar_protocol": "TCP",
 "port_number": null, "protocol": null, "service": null, "category": null, "...": null}
```

### Respuesta final del endpoint para el ejemplo

> Los campos de matriz mostrados son los principales; los reales son todos los de `PortSerializer` (`sub_category`, `comments`, `exposition`, `replaced_by`, ...).

```json
[
  {"ar_number": "AR1", "ar_port_number": "22",    "ar_protocol": "TCP",
   "port_number": "22",          "protocol": "TCP", "service": "SSH",      "category": "Admin services"},
  {"ar_number": "AR1", "ar_port_number": "48100", "ar_protocol": "TCP",
   "port_number": "48000-49500", "protocol": "TCP", "service": "MQSeries", "category": "Middleware"},
  {"ar_number": "AR2", "ar_port_number": "48200", "ar_protocol": "TCP",
   "port_number": "48000-49500", "protocol": "TCP", "service": "MQSeries", "category": "Middleware"},
  {"ar_number": "AR2", "ar_port_number": "23581", "ar_protocol": "TCP",
   "port_number": null,          "protocol": null,  "service": null,       "category": null}
]
```

**Caso real 649094** (`TCP_23581;TCP_23582`, fuera de la matriz): antes `[]`; ahora dos filas con los datos de matriz a `null`.

---

### 3.4 `validation_matrix/schema.py`

Solo cambia el texto que describe el endpoint en `/docs/`:

```python
        return (
            'This endpoint returns every service of the access requests of a '
            'given flow request ticket, with its validation matrix data when found.'
        )
```

Si se mantiene `Response([])` sin `sn_ticket_id`, conviene añadir que el parámetro es obligatorio para obtener datos.

---

### 3.5 `validation_matrix/tests.py`

Ejecutar: `python manage.py test validation_matrix`

| Caso | Entrada | Esperado |
|---|---|---|
| Puertos fuera de matriz (649094) | `TCP_23581;TCP_23582` | 2 filas, campos de matriz a `null` |
| Puerto exacto | `TCP_22` | 1 fila con SSH |
| Puerto dentro de rango | `TCP_48100` | 1 fila con MQSeries |
| **Dos servicios en el mismo rango** | `TCP_48100;TCP_48200` | 2 filas, **las dos** con MQSeries |
| Mismo puerto en dos AR | AR1 y AR2 con `TCP_22` | 2 filas, cada una con su `ar_number` |
| Servicio cubierto por 2 filas de matriz | `TCP_22` con dos filas SSH | 2 filas |
| `services` vacío o no numérico | `""`, `ICMP` | No falla; `ICMP` sale con `null` |
| Mayúsculas | `tcp_22` contra `TCP` | Coincide |
| Número de consultas | Varios AR y puertos | `assertNumQueries(2)` |
| Sin `sn_ticket_id` | `GET /validation-matrix/port/` | `200` y `[]` |

Esqueleto (ajusta los campos obligatorios de `Task`, `AccessRequest` y `Port` a los modelos reales):

```python
class PortViewSetTests(APITestCase):
    def setUp(self):
        self.client.force_authenticate(user=self.create_user_with_port_view_permission())
        self.task = Task.objects.create(sn_ticket_id='649999')
        Port.objects.create(protocol='TCP', port_number='22', service='SSH')
        Port.objects.create(protocol='TCP', port_number='48000-49500', service='MQSeries')

    def get_ports(self, services):
        AccessRequest.objects.create(task=self.task, ar_number='AR1', services=services)
        response = self.client.get('/validation-matrix/port/', {'sn_ticket_id': '649999'})
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_ports_not_in_matrix_are_returned_with_null_matrix_data(self):
        rows = self.get_ports('TCP_23581;TCP_23582')
        self.assertEqual([row['ar_port_number'] for row in rows], ['23581', '23582'])
        self.assertTrue(all(row['service'] is None for row in rows))

    def test_two_services_in_same_range_both_match(self):
        rows = self.get_ports('TCP_48100;TCP_48200')
        self.assertEqual([row['service'] for row in rows], ['MQSeries', 'MQSeries'])

    def test_without_ticket_returns_empty_list(self):
        response = self.client.get('/validation-matrix/port/')
        self.assertEqual(response.json(), [])
```

---

## 4. ProdSecHub

### 4.1 `API_cnx/serenity.py`: `get_services`

```python
def get_services(self, ticket_id):
    response = requests.get(
        f'{self.base_url}validation-matrix/port/',
        headers=self.headers,
        verify=False,
        params={'sn_ticket_id': ticket_id}
    )
    if response.status_code == 200:
        return response.json()
    return None
```

| | URL generada (`base_url = "http://127.0.0.1:8001/"`) | Resultado |
|---|---|---|
| Antes | `http://127.0.0.1:8001//validation-matrix/port?sn_ticket_id=536238` | 404 HTML → `response.json()` lanza `Expecting value` → 500 |
| Ahora | `http://127.0.0.1:8001/validation-matrix/port/?sn_ticket_id=536238` | 200 JSON |

- Sin barra delante (`base_url` ya acaba en `/`) y con barra al final (ruta real del endpoint).
- Sin `print`: si Serenity falla, el método devuelve `None` y la pantalla muestra "No data Found" en vez de romperse.

---

### 4.2 `bookmark/views.py`: `ajax_get_frida_ar_data`

#### Cambio 1: bucle de orígenes

**Antes:**
```python
src_labels = parse_tag_name(playflows_norm)

if not src_labels:
    return JsonResponse({})

for lbl in src_labels.get('f_labels'):
```

**Ahora:**
```python
src_labels = parse_tag_name(playflows_norm) or {}

for lbl in src_labels.get('f_labels', []):
```

#### Cambio 2: bucle de destinos

```python
dst_labels = parse_tag_name(playflows_norm) or {}

for lbl in dst_labels.get('f_labels', []):
```

**Ejemplo con el 649094** (2 orígenes `EXT`, 1 destino conocido):

| Variable | Antes | Ahora |
|---|---|---|
| `src_labels` para una IP `EXT` | `None` → `return JsonResponse({})` | `{}` |
| `src_labels.get('f_labels', [])` | (no se llegaba) | `[]` → el bucle no hace nada |
| Fila añadida a `ar['ar_content']` | ninguna | `{"ip_address": "x.x.x.x/32", "side": "source"}` |
| Respuesta de la vista | `{}` (pantalla en blanco) | Tabla con las 3 IP |

#### Cambio 3: rama "NO INFO" en `check_all_access_requests`

Justo debajo de `# RULES`, una rama nueva delante; el `if` original pasa a `elif`:

```python
# RULES
if not src.get("f_labels") or not dst.get("f_labels"):  # NO INFO
    env_exception = None
    expo_layer_exception = None
    src_expo_layer = None
    dst_expo_layer = None

elif dst_lab_sys == "iv2" or dst_lab_sys == "iv1" or dst_lab_sys == "playflows":  # DST CIB
    ...
elif dst_lab_sys == "itg" or dst_lab_sys == "itg_iplist":  # DST ITG
    ...
```

- Una pareja con un lado desconocido **no se evalúa**: queda sin resultado, nunca como `OK`.
- Evita llamar a `LabelMapping.get_matching_label(None, ...)` con valores `None`.
- Se reasignan `src_expo_layer` y `dst_expo_layer` porque se inicializan una sola vez antes del bucle; si no, una fila sin datos heredaría las etiquetas de la pareja anterior.

**Ejemplo de fila en `results` para una pareja sin datos:**
```python
{
    "ar": "AR1", "source": "203.0.113.10/32", "destination": "10.20.8.46/32",
    "src_env": None, "dst_env": "PRD",
    "src_expo_layer": None, "dst_expo_layer": None,
    "env_exception": None, "env_explanation": None,
    "expo_layer_exception": None, "expo_layer_explanation": None,
}
```

Con `env_explanation` y `expo_layer_explanation` a `None`, el bucle de resultados marca `env_none_overall = True` y `expo_layer_none_overall = True`, y saltan solos los avisos amarillos de "data missing".

---

### 4.3 `frida_env_result_component.html` y `frida_expo_layer_result_component.html`: "No info"

**Entornos / zonas junto a cada IP:**
```html
<span class="badge badge-sm custom-env me-1">{{ row.src_env|default:"No info" }}</span>
<span class="badge badge-sm custom-env me-1">{{ row.dst_env|default:"No info" }}</span>
```

**Exception Code** (en el de expo/layer, con `row.expo_layer_exception` y `row.expo_layer_explanation`):
```html
{% if row.env_explanation|startswith:"OK" %}
    <span class="badge badge-sm badge-success text-capitalize">{{ row.env_exception }}</span>
{% elif row.env_exception %}
    <span class="badge badge-sm badge-danger text-capitalize">{{ row.env_exception }}</span>
{% else %}
    <span class="badge badge-sm badge-secondary">No info</span>
{% endif %}
```

**Explanation** (conservando el `style` de la celda):
```html
<td style="..."><small>{{ row.env_explanation|default:"No info" }}</small></td>
```

| `env_explanation` | `env_exception` | Se pinta |
|---|---|---|
| `"OK ..."` | `"E00"` | 🟢 `E00` |
| `"Not allowed ..."` | `"E12"` | 🔴 `E12` |
| `None` | `None` | ⚪ `No info` (antes 🔴 `None`) |

Así "no se ha podido comprobar" no se confunde con "incumple".

---

### 4.4 Renombrados (punto 2 del Jira)

Solo cambia el **texto visible**; las claves internas (`exposition`, `labelling_system`) no se tocan, para no necesitar migración ni romper `import_port`.

| Plantilla | Antes | Ahora |
|---|---|---|
| `global_search.html`, `<thead>` de Ports Details y de la tabla de AR | `Exposition` | `Exposure` |
| `global_search.html` / `frida_access_request_component.html`, cabecera | `Labelling-system` | `Label-system` |

---

### 4.5 `search_components/frida_service_component.html` (versión final)

```html
{% regroup result by ar_number as ar_groups %}
{% for group in ar_groups %}
    {% for item in group.list %}
        <tr class="text-nowrap">
            {% if forloop.first %}
                <td rowspan="{{ group.list|length }}" class="fw-normal text-center align-middle">
                    <span class="badge badge-sm badge-outline-secondary">{{ group.grouper|default:'-' }}</span>
                </td>
            {% endif %}
            <td class="fw-normal text-center">
                {% if item.port_number %}
                    -
                {% else %}
                    <span class="badge badge-sm badge-outline-secondary">{{ item.ar_port_number|default:'-' }} - {{ item.ar_protocol|default:'-' }}</span>
                {% endif %}
            </td>
            <td class="fw-normal text-center">{{ item.port_number|default:'-' }}</td>
            <td class="fw-normal text-center">{{ item.protocol|default:'-' }}</td>
            <td class="fw-normal text-center">
                {% if item.service %}
                    <span class="badge badge-sm badge-info">{{ item.service }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center">
                {% if item.category %}
                    <span class="badge badge-sm badge-outline-primary">{{ item.category }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center">
                {% if item.sub_category %}
                    <span class="badge badge-sm badge-outline-secondary">{{ item.sub_category }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center"><small>{{ item.comments|default:'-' }}</small></td>
            <td class="fw-normal text-center">{{ item.exposition|default:'-' }}</td>
            <td class="fw-normal text-center">{{ item.replaced_by|default:'-' }}</td>
            <td class="fw-normal text-center"><small>{{ item.who_needs_to_approve_exception|default:'-' }}</small></td>
            <td class="fw-normal text-center"><small>{{ item.security_policy_document|default:'-' }}</small></td>
        </tr>
    {% endfor %}
{% empty %}
    <tr class="text-nowrap">
        <td colspan="12" class="text-center">
            <small class="fst-italic mb-2">
                <i class="fas fa-exclamation-circle fa-lg pe-1"></i> No data Found !
            </small>
        </td>
    </tr>
{% endfor %}
```

| Parte | Qué hace |
|---|---|
| `regroup result by ar_number` | Agrupa las filas por AR. Solo junta filas **consecutivas**, por eso Serenity las devuelve ordenadas por `ar_number` |
| `forloop.first` + `rowspan` | El AR se pinta una vez y ocupa todas sus filas (mismo patrón que la tabla de chequeos) |
| `{% if item.port_number %} - {% else %} badge` | La columna AR port solo se rellena cuando el puerto **no** está en la matriz. Si está, sus datos ya salen en Port number / Protocol y sería redundante |
| `colspan="12"` | 12 columnas en total |

**Cómo se ve con el ejemplo:**

| AR | AR port | Port number | Protocol | Service | Category |
|---|---|---|---|---|---|
| AR1 | - | 22 | TCP | SSH | Admin services |
| | - | 48000-49500 | TCP | MQSeries | Middleware |
| AR2 | - | 48000-49500 | TCP | MQSeries | Middleware |
| | `23581 - TCP` | - | - | - | - |

> Caso a tener en cuenta: un puerto dentro de un rango (48100 contra `48000-49500`) muestra el rango de la matriz en Port number, no el puerto pedido.

---

### 4.6 `templates/global_search.html`

**`<thead>` de Ports Details** (12 cabeceras, mismo orden que las celdas del componente):
```html
<th scope="col" class="border-0">AR</th>
<th scope="col" class="border-0">AR port</th>
<th scope="col" class="border-0">Port number</th>
<th scope="col" class="border-0">Protocol</th>
<th scope="col" class="border-0">Service</th>
<th scope="col" class="border-0">Category</th>
<th scope="col" class="border-0">Sub category</th>
<th scope="col" class="border-0">Comments</th>
<th scope="col" class="border-0">Exposure</th>
<th scope="col" class="border-0">Replaced by</th>
<th scope="col" class="border-0">Who needs to approve exception</th>
<th scope="col" class="border-0">Security policy document</th>
```

**Fila de carga (`id_service_loader`):** `colspan="12"`.

**Limpieza:** se borraron las dos `F` sueltas (`<tbody id="id_service_loader">F` y `</table>F`).

> Si falta un `<th>` (pasó al añadir la columna AR), las columnas se desplazan: `SSH` aparece bajo Protocol, etc.

---

## 5. Recorrido de extremo a extremo

```
Usuario abre FRIDA ?value=649094
│
├─ ajax_get_frida_ar_data (ProdSecHub)
│    ├─ SerenityAPI.get_access_requests → AR con 2 orígenes EXT + 1 destino
│    ├─ IP EXT sin workload → src_labels = {} (ya no corta con JsonResponse({}))
│    ├─ check_all_access_requests → rama NO INFO → excepciones a None
│    └─ plantillas → IP con "No info", Exception Code gris, avisos amarillos
│
└─ ajax_get_frida_service_data (ProdSecHub)
     ├─ SerenityAPI.get_services → GET validation-matrix/port/?sn_ticket_id=649094
     │    └─ Serenity: build_access_request_ports
     │         query 1: AR → [("AR1", "TCP_23581;TCP_23582")]
     │         query 2: Port + Case/When → sin coincidencias
     │         rows: 2 filas con matrix_port = None
     └─ frida_service_component.html → AR1 | 23581 - TCP | - ...
                                           | 23582 - TCP | - ...
```

| | Antes | Ahora |
|---|---|---|
| Tabla de AR del 649094 | Vacía | 3 IP; las `EXT` con "No info" |
| Chequeos ENV / EXPO-LAYER | Vacíos | Una fila por pareja, "No info" en gris |
| Ports Details del 649094 | "No data Found" | `23581 - TCP` y `23582 - TCP` |
| Consultas en Serenity | 1 por servicio | 2 fijas |

---

## 6. Pruebas y entorno

| Ticket | Qué comprueba |
|---|---|
| 649094 | IP externas sin workload y puertos fuera de matriz (solo en PROD; los puertos se ven tras desplegar Serenity) |
| 536238 | AR con `TCP_5280` fuera de matriz; regresión del chequeo de entorno (`OK` sigue en verde) |
| 635140 | AR con `UDP_8;UDP_0` y `UDP_8116` |
| 601982 | Varios puertos por AR, agrupación con `rowspan`, `TCP_5647` fuera de matriz |
| 618658 | Puertos que sí están en la matriz |

**Cambios temporales de prueba que NO van en el commit:**

- [ ] `bookmark/views.py`, `ajax_get_frida_service_data`: `SerenityAPI(env="stg")` → volver a `env="prod"`. **En la rama del 3881 todavía aparece `env="stg"` (línea ~652): revisar si entró en `main`.**
- [ ] `.env` de ProdSecHub: restaurar `serenity_stg_base_url` (se apuntó a `http://127.0.0.1:8001/`).
- [ ] `NO_PROXY` para localhost, solo en local.
- [ ] Fuera del commit: `Validation_Matrix_for_Scripts.xlsx` y `media/frida/`.

**Comprobación pendiente:** en la rama del 3881, `ajax_get_frida_ar_data` todavía tiene `if not src_labels: return JsonResponse({})` y FRIDA sigue mostrando "Exposition". Confirmar que los cambios de ProdSecHub de las secciones 4.2 a 4.4 están mergeados en `main`.

---

## 7. Fuera de alcance (posibles tickets)

- **`src_labels` / `dst_labels` se calculan una vez por AR**: un segundo origen sin workload hereda las etiquetas del primero. Ya ocurría antes.
- **Prioridad de fuentes de etiquetas** (ServiceNow > DPR > Infoblox > Playflows), planteada por Aurelien.
- **`env` fijo en el código** (`SerenityAPI(env="prod")`): debería salir de la configuración.
- **Orden de los AR en Ports Details**: `order_by('ar_number')` ordena como texto (`AR1, AR10, AR2`). El 3881 ya ordena numéricamente `extra_details`; si se quiere el mismo orden aquí, aplicar la misma clave al construir `ar_services`.

---

## 8. Commit

```
EMEAPLAYFLOWS-3782 Build port details from access requests

- Start from the ticket's access request services instead of the Port
  matrix, so every AR port is returned even when it is not in the matrix
  (matrix data is null in that case).
- Match AR services against the matrix in a single query using annotate
  with one Case/When per service, so services in the same range are not
  collapsed.
- Keep 2 queries per request regardless of the number of ports.
- Return an empty list when sn_ticket_id is not provided.
- Add tests for unmatched ports, same-range services and query count.
```
