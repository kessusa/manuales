# EMEAPLAYFLOWS-3782 · FRIDA: mostrar todos los puertos de los access requests

Rama: `EMEAPLAYFLOWS-3782-display-ports-of-requests`
Proyectos afectados: **Serenity** (API) y **ProdSecHub** (`netsec-dashboard`, pantalla FRIDA)

---

## 1. Qué pedía el ticket

1. En **Ports Details**, mostrar todos los puertos de cada access request (AR), no solo los que coinciden con la matriz de validación. Añadir una columna con el AR, el puerto y el protocolo.
2. Renombrar columnas: **Exposition → Exposure** y **Labelling-system → Label-system**.
3. Investigar el ticket **649094**, que no mostraba nada en FRIDA.

## 2. Causas encontradas

| # | Síntoma | Causa | Dónde |
|---|---|---|---|
| A | Ports Details vacío o incompleto | `PortViewSet.get_queryset` devolvía solo filas de la matriz (`Port`) que coincidían con algún servicio del AR. Un puerto fuera de la matriz desaparecía, y además se perdía a qué AR pertenecía cada fila. | Serenity · `validation_matrix/views.py` |
| B | Riesgo de error 500 | `protocol, port_number = service.split('_')` fallaba si `services` venía vacío, nulo o sin `_`. | Serenity · `validation_matrix/views.py` |
| C | Rendimiento | Una consulta a `Port` por cada servicio de cada AR (N+1). | Serenity · `validation_matrix/views.py` |
| D | URL mal formada | `f'{self.base_url}/validation-matrix/port'` generaba una doble barra (`...echonet//validation-matrix/port`) y no llevaba la barra final del endpoint. | ProdSecHub · `API_cnx/serenity.py` |
| E | Ticket entero en blanco (649094) | `ajax_get_frida_ar_data` hacía `return JsonResponse({})` en cuanto un origen o destino no tenía workload ni etiquetas. Las IP externas (`EXT`) nunca tienen workload, así que se perdía todo el ticket. | ProdSecHub · `bookmark/views.py` |
| F | `None` en rojo, como si fuera un incumplimiento | Los templates pintaban el valor vacío tal cual y con la etiqueta de error. | ProdSecHub · templates `frida_*_result_component.html` |

El 649094 tenía a la vez la causa **A** (sus puertos `23581` y `23582` no están en la matriz) y la causa **E** (orígenes externos sin datos).

---

## 3. Cambios en Serenity

### 3.1 `validation_matrix/serializers.py`

Nuevo serializador que combina los datos del servicio del AR con los de la matriz, si existen.

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

**Por qué:** la respuesta necesita tres datos que `Port` no tiene. Al reutilizar `PortSerializer`, las claves que ya consumía ProdSecHub no cambian; solo se añaden tres nuevas. Si el puerto no está en la matriz, esas claves llegan a `null` en lugar de desaparecer.

### 3.2 `validation_matrix/views.py`

Dos funciones nuevas encima de `PortViewSet` y un `list` que sustituye al antiguo `get_queryset`.

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


def build_access_request_ports(sn_ticket_id):
    """Return every AR service of a ticket with its matrix port data."""
    access_requests = AccessRequest.objects.filter(
        task__sn_ticket_id=sn_ticket_id
    ).order_by('ar_number').values_list('ar_number', 'services')
    matrix_ports = list(Port.objects.all())

    rows = []
    for ar_number, services in access_requests:
        for protocol, port_number in parse_services(services):
            matches = [
                port for port in matrix_ports
                if port_number
                and port.protocol.lower() == protocol.lower()
                and port_in_range(port.port_number, port_number)
            ]
            for matrix_port in matches or [None]:
                rows.append({
                    'ar_number': ar_number,
                    'ar_port_number': port_number,
                    'ar_protocol': protocol,
                    'matrix_port': matrix_port,
                })
    return rows
```

```python
    def list(self, request, *args, **kwargs):
        sn_ticket_id = request.query_params.get('sn_ticket_id')
        if not sn_ticket_id:
            return super().list(request, *args, **kwargs)
        rows = build_access_request_ports(sn_ticket_id)
        return Response(AccessRequestPortSerializer(rows, many=True).data)
```

**Por qué:**

- Se parte de los servicios del AR y la matriz pasa a ser opcional: corrige la causa **A**.
- `partition('_')` y la comprobación de vacío evitan el error de la causa **B**.
- La matriz se carga una vez y se cruza en memoria: de una consulta por servicio a **dos consultas en total** (causa **C**).
- Se mantiene el mismo endpoint, el filtro por `sn_ticket_id`, `port_in_range` y el comportamiento sin parámetro (devuelve la matriz completa). No hay URL nueva ni migración.
- Un puerto que coincide con varias filas de la matriz (por ejemplo, 22/TCP con varios servicios) genera una fila por coincidencia, igual que antes, ahora con su AR.
- La comparación de protocolo ignora mayúsculas: Serenity guarda `TCP_23581` y la matriz puede tener `tcp`.

### 3.3 `validation_matrix/schema.py`

Texto de `get_description` actualizado para que `/docs/` describa la respuesta nueva:

```python
        return (
            'This endpoint returns every service of the access requests of a '
            'given flow request ticket, with its validation matrix data when found.'
        )
```

### 3.4 `validation_matrix/tests.py`

Tres casos: puerto en matriz, puerto fuera de matriz (reproduce el 649094 con `TCP_23581;TCP_23582`) y `services` vacío. Ruta: `/validation-matrix/port/`.

---

## 4. Cambios en ProdSecHub

### 4.1 `API_cnx/serenity.py` · `get_services`

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

**Por qué:** `base_url` ya termina en `/`. La URL anterior generaba una doble barra y omitía la barra final del endpoint (causa **D**). Ahora sigue el mismo patrón que el resto de métodos de la clase. El método ya devolvía el JSON tal cual, así que los tres campos nuevos llegan al template sin más cambios.

### 4.2 `bookmark/views.py` · `ajax_get_frida_ar_data`

**Bucles de orígenes y destinos.** Se eliminan los dos `return JsonResponse({})`:

```python
# Antes
src_labels = parse_tag_name(playflows_norm)

if not src_labels:
    return JsonResponse({})

for lbl in src_labels.get('f_labels'):

# Después
src_labels = parse_tag_name(playflows_norm) or {}

for lbl in src_labels.get('f_labels', []):
```

Lo mismo con `dst_labels`.

**Por qué:** una IP sin datos ya no anula el ticket entero; continúa con un diccionario vacío y se añade a la tabla solo con `ip_address` y `side` (causa **E**).

**`check_all_access_requests`, debajo de `# RULES`.** Rama nueva al principio; el `if` original pasa a `elif`:

```python
# RULES
if not src.get("f_labels") or not dst.get("f_labels"):  # No info
    env_exception = None
    expo_layer_exception = None
    src_expo_layer = None
    dst_expo_layer = None

elif dst_lab_sys == "iv2" or dst_lab_sys == "iv1" or dst_lab_sys == "playflows":  # DST CIB
    ...
```

**Por qué:**

- Una pareja con un lado desconocido **no se evalúa**: queda sin resultado y nunca se marca como `OK`. En una herramienta de validación de seguridad, un falso `OK` es peor que no mostrar nada.
- Evita llamar a `LabelMapping.get_matching_label` y a los modelos de estado con valores `None`.
- `src_expo_layer` y `dst_expo_layer` se reinician porque se declaran fuera del bucle; sin esto, una fila sin datos podría heredar las etiquetas de la pareja anterior en tickets con varios AR.
- Los avisos amarillos del resumen ("data missing") se activan solos, porque la vista ya marca `env_none` y `expo_layer_none` cuando la explicación es `None`.

### 4.3 Templates

**`templates/global_search.html`**

- Ports Details: nueva cabecera `<th scope="col" class="border-0">AR port</th>` como primera columna (11 columnas, coincide con el `colspan="11"` del spinner).
- Cabeceras **Exposition → Exposure** y **Labelling-system → Label-system**, más los textos del resumen ("Exposure & Layer", "Exposure and layer data missing").
- Eliminadas dos letras `F` sueltas que se pintaban encima y debajo de la tabla de puertos.

Solo cambia el texto visible. Los campos `exposition` (modelo `Port` de Serenity y columna del Excel) y `labelling_system` (clave interna) **no se renombran**: evita una migración y no rompe `import_port` ni el JavaScript.

**`search_components/frida_service_component.html`**

Celda nueva al principio de cada fila; el `colspan` del "No data Found" pasa de 10 a 11:

```html
<td class="fw-normal text-center">
    <span class="badge badge-sm badge-outline-primary">{{ item.ar_number|default:'-' }}</span>
    {{ item.ar_port_number|default:'-' }} - {{ item.ar_protocol|default:'-' }}
</td>
```

El resto de celdas ya mostraban `-` con valores `null`.

**`search_components/frida_env_result_component.html`** y **`frida_expo_layer_result_component.html`**

```html
<span class="badge badge-sm custom-env me-1">{{ row.src_env|default:"No info" }}</span>

{% if row.env_explanation|startswith:"OK" %}
    <span class="badge badge-sm badge-success text-capitalize">{{ row.env_exception }}</span>
{% elif row.env_exception %}
    <span class="badge badge-sm badge-danger text-capitalize">{{ row.env_exception }}</span>
{% else %}
    <span class="badge badge-sm badge-secondary">No info</span>
{% endif %}

<td style="..."><small>{{ row.env_explanation|default:"No info" }}</small></td>
```

En el template de exposición y capa, lo mismo con `src_expo_layer`, `dst_expo_layer`, `expo_layer_exception` y `expo_layer_explanation`.

**Por qué:** separa tres estados que antes eran dos: **verde** (cumple), **rojo** (código de excepción real) y **gris "No info"** (no se ha podido evaluar). Así un flujo sin datos deja de parecer un incumplimiento (causa **F**).

---

## 5. Ejemplos de entrada y salida

### 5.1 Endpoint de Serenity · `GET /validation-matrix/port/?sn_ticket_id=<ticket>`

**Entrada: ticket 536238** (STG). AR guardado en Serenity:

```json
{ "ar_number": "AR1", "services": "TCP_5280" }
```

**Salida antes:** el 5280 no está en la matriz.

```json
[]
```

**Salida después:**

```json
[
  {
    "ar_number": "AR1",
    "ar_port_number": "5280",
    "ar_protocol": "TCP",
    "port_number": null,
    "protocol": null,
    "service": null,
    "category": null,
    "sub_category": null,
    "comments": null,
    "exposition": null,
    "replaced_by": null,
    "who_needs_to_approve_exception": null,
    "security_policy_document": null
  }
]
```

**Entrada: ticket 635140** (STG), varios AR:

```json
[
  { "ar_number": "AR1", "services": "TCP_256" },
  { "ar_number": "AR2", "services": "UDP_8;UDP_0" },
  { "ar_number": "AR3", "services": "UDP_8116" }
]
```

**Salida después** (resumida; ningún puerto está en la matriz):

```json
[
  { "ar_number": "AR1", "ar_port_number": "256",  "ar_protocol": "TCP", "port_number": null, "service": null, "...": null },
  { "ar_number": "AR2", "ar_port_number": "8",    "ar_protocol": "UDP", "port_number": null, "service": null, "...": null },
  { "ar_number": "AR2", "ar_port_number": "0",    "ar_protocol": "UDP", "port_number": null, "service": null, "...": null },
  { "ar_number": "AR3", "ar_port_number": "8116", "ar_protocol": "UDP", "port_number": null, "service": null, "...": null }
]
```

**Entrada: puerto que sí está en la matriz** (por ejemplo, 22/TCP, que en la matriz tiene tres filas: SSH admin, SSH prohibido y SFTP).

**Salida después:** tres filas, cada una con los datos de matriz de esa coincidencia y el mismo AR. Esquema (los valores de matriz son ilustrativos):

```json
[
  { "ar_number": "AR1", "ar_port_number": "22", "ar_protocol": "TCP", "port_number": "22", "protocol": "TCP", "service": "<servicio 1 de la matriz>", "...": "..." },
  { "ar_number": "AR1", "ar_port_number": "22", "ar_protocol": "TCP", "port_number": "22", "protocol": "TCP", "service": "<servicio 2 de la matriz>", "...": "..." },
  { "ar_number": "AR1", "ar_port_number": "22", "ar_protocol": "TCP", "port_number": "22", "protocol": "TCP", "service": "<servicio 3 de la matriz>", "...": "..." }
]
```

Antes salían las mismas tres filas, pero sin `ar_number`, `ar_port_number` ni `ar_protocol`.

**Entrada: `services` vacío o nulo**

| | Antes | Después |
|---|---|---|
| `"services": null` | Error 500 en el `split('_')` | `[]` |

### 5.2 Pantalla FRIDA · Ports Details

**Ticket 536238, antes:**

| Port number | Protocol | Service | ... |
|---|---|---|---|
| *No data Found!* | | | |

**Después:**

| AR port | Port number | Protocol | Service | Category | ... | Exposure | ... |
|---|---|---|---|---|---|---|---|
| `AR1` 5280 - TCP | - | - | - | - | - | - | - |

**Ticket 649094, después del despliegue de Serenity** (en PROD tiene `"services": "TCP_23581;TCP_23582"`):

| AR port | Port number | Protocol | Service | ... |
|---|---|---|---|---|
| `AR1` 23581 - TCP | - | - | - | - |
| `AR1` 23582 - TCP | - | - | - | - |

### 5.3 Pantalla FRIDA · Access requests y chequeos (ticket 649094)

**Entrada** (Serenity PROD, `/order/649094/details/`, resumido):

```json
{
  "ar_number": "AR1",
  "sources": ["46.19.253.216/32", "46.19.253.218/32"],
  "src_nodenames": ["EXT", "EXT"],
  "destinations": ["159.95.26.145/32"],
  "dst_nodenames": ["AMER_US_PRD_DMZE_MKT-ETS-FX"],
  "services": "TCP_23581;TCP_23582"
}
```

Los dos orígenes no tienen workload, ni etiquetas de SFM, ni datos en Playflows.

**Antes:** `ajax_get_frida_ar_data` devolvía `{}` y la pantalla mostraba solo las cabeceras de las tres tablas.

**Después:**

Tabla del ticket:

| AR | Side | IP Address | Environment | Exposure | Layer-Tier | Location | ... |
|---|---|---|---|---|---|---|---|
| AR1 | SOURCE | 46.19.253.216/32 | - | - | - | - | - |
| | SOURCE | 46.19.253.218/32 | - | - | - | - | - |
| | DESTINATION | 159.95.26.145/32 | PRD | DMZE | MKT-ETS-FX | AMER_US | - |

Detailed Environment Check Results:

| AR | Source | → | Destination | Exception Code | Explanation |
|---|---|---|---|---|---|
| AR1 | 46.19.253.216/32 `No info` | → | 159.95.26.145/32 `PRD` | `No info` (gris) | No info |
| | 46.19.253.218/32 `No info` | → | 159.95.26.145/32 `PRD` | `No info` (gris) | No info |

Detailed Exposure and Layer Check Results: misma estructura, con `No info` en las etiquetas de zona del origen y en el resultado.

Resumen superior: "Environment data missing" y "Exposure and layer data missing" en amarillo.

**Ticket con datos completos (536238):** sin cambios de comportamiento. El chequeo de entorno sigue mostrando `OK` en verde. Donde la matriz no devuelve código para una pareja con etiquetas conocidas, el `None` rojo pasa a `No info` gris.

---

## 6. Pruebas realizadas

| Prueba | Resultado |
|---|---|
| Endpoint Serenity local (STG) · 635140 | `200`, 4 filas con AR, puerto y protocolo |
| Endpoint Serenity local (STG) · 536238 | `200`, 1 fila `AR1 / 5280 / TCP` con matriz a `null` |
| FRIDA (dev) + Serenity local · 536238 | Ports Details muestra `AR1 5280 - TCP` |
| FRIDA (dev) · 649094 | Access requests y chequeos visibles, IP externas con `-` / `No info` |
| Cabeceras AR port / Exposure / Label-system | Correctas |
| `python manage.py test validation_matrix` | **Pendiente de ejecutar** |

**El 649094 no se puede verificar en Ports Details antes del despliegue:** el ticket solo existe en PROD (que corre el código antiguo) y no en STG (donde corre el código nuevo en local). El caso queda cubierto por el test unitario con `TCP_23581;TCP_23582`.

---

## 7. Despliegue

1. **Serenity primero, ProdSecHub después.** En orden inverso no se rompe nada: la columna "AR port" saldría con guiones hasta que llegue Serenity.
2. Sin migraciones en ninguno de los dos proyectos.

## 8. Checklist antes del commit

**ProdSecHub**

- [ ] `bookmark/views.py`, `ajax_get_frida_service_data`: volver a `SerenityAPI(env="prod")` (se cambió a `stg` solo para probar).
- [ ] `API_cnx/serenity.py`: sin `print` ni `#print`.
- [ ] `.env`: `serenity_stg_base_url` restaurada a su valor original.
- [ ] Fuera del commit: `Validation_Matrix_for_Scripts.xlsx`, `media/frida/` y cualquier `.env`.
- [ ] Revisar con `git diff` que `global_search.html` no conserva las `F` sueltas.

**Serenity**

- [ ] `validation_matrix/views.py`: sin imports sin usar.
- [ ] `python manage.py test validation_matrix` en verde.

## 9. Notas para el equipo

- **Configuración local para probar FRIDA contra un Serenity local:** `serenity_stg_base_url=http://127.0.0.1:8001/` en el `.env` de ProdSecHub, lanzar el `runserver` con `$env:NO_PROXY = "127.0.0.1,localhost"` (si no, el proxy corporativo intercepta la llamada y devuelve su página de bloqueo con un 403), y reiniciar el servidor tras cambiar el `.env`.
- **Base de datos local de ProdSecHub:** si aparece `column "workload.infra_type" must appear in the GROUP BY clause`, a la tabla `workload` local le falta la clave primaria (`ALTER TABLE workload ADD PRIMARY KEY (id);`). No es un fallo del código.
- **Posible ticket aparte:** en `ajax_get_frida_ar_data`, `src_labels` y `dst_labels` se calculan una vez por AR y se reutilizan para todas sus IP, así que un segundo origen sin workload hereda las etiquetas del primero. Ya ocurría antes de este cambio.
- **Posible mejora aparte:** el entorno de `SerenityAPI` está fijado en el código (`env="prod"`) en vez de salir de la configuración.
