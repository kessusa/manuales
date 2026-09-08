# Conector CheckPoint — documentación

Conector para la **Management API de Check Point** en entorno **MDS multi-dominio**.

A diferencia de FortiManager (JSON-RPC contra un único endpoint), Check Point expone
**un endpoint por comando** (`<url>/<command>`). El login es por dominio (el dominio
viaja dentro de `auth_credentials`) y, a partir de ahí, cada llamada lleva el token de
sesión en la cabecera **`X-chkp-sid`**.

Objetivo del conector: saber **qué cambios se van a instalar** en el firewall antes de
lanzar el push, de forma legible para un humano y almacenable en base de datos.

---

## 1. Sesión y base

| Método | Para qué sirve | Por qué es así |
|---|---|---|
| `__init__` | URLs v1/v2, headers, proxies, credenciales y `self._cache` | La caché vive por instancia: como el dashboard crea un `CheckPoint()` por consulta, nunca sirve datos rancios |
| `login(url)` | Abre sesión en el dominio fijado en `auth_credentials` y devuelve el `sid` | Restaura las credenciales en `connection_args` antes de postear. Sin eso, un `logout` previo dejaba `{'sid': ...}` en el json compartido y el siguiente login petaba con `KeyError: 'sid'` |
| `logout(url, sid)` | Cierra la sesión en el servidor | Manda el sid en el **header** (no en el body) y usa args locales para no mutar el estado compartido. Con el sid en el body las sesiones no se cerraban de verdad |
| `wait_for_task(url, sid, task_id)` | Hace polling cada 2 s hasta que la tarea deja de estar `in progress` | `show-changes`, `verify-policy` e `install-policy` son **asíncronos**: devuelven un `task-id`, no los datos |

---

## 2. Resolución de objetos

| Método | Para qué sirve | Por qué es así |
|---|---|---|
| `get_object_details(url, sid, uid)` | Reconstruye la definición completa de cualquier objeto a partir de su uid | Los cambios solo traen `uid` + `type`. Casos especiales: una *access-rule* necesita `show-access-rule` con su **layer**; una *nat-rule* necesita `show-nat-rule` con su **package**, que hay que descubrir. Cacheado por uid |
| `get_all_packages(url, sid)` | Lista de paquetes del dominio, una sola vez por ejecución | Era la llamada más repetida del conector: se pedía por cada regla resuelta |
| `get_layer_packages(url, sid, layer)` | Traduce un layer al paquete o paquetes que lo contienen | Permite trazar cada cambio a su policy package. Un layer puede estar compartido por varios paquetes, por eso devuelve lista |
| `get_group_full(url, sid, uid)` | Devuelve los miembros de un grupo como **objetos completos en una sola llamada** | Es el *bulk* clave: `show-group` / `show-service-group` con `details-level: full` evita el problema N+1 (un grupo de 50 hosts pasa de 51 llamadas a 1) |
| `get_affected_rules(url, sid, uid)` | Reglas que usan un objeto (`where-used`), de forma directa o indirecta | Si cambias un grupo, la regla no "cambia" pero sí queda afectada. El modo `indirect` detecta los grupos anidados. La API no ofrece bulk aquí, así que se cachea por uid |
| `resolve_inline_packages(url, sid, obj)` | Resuelve el paquete desde la definición *inline* (por layer en access, por package uid en NAT) | Necesario cuando el objeto ya no existe y no se puede usar `get_object_details` |

---

## 3. Presentación de la información

### Vista de auditoría (detalle completo)

- `resolve_member`
- `describe_reference`
- `describe_object`

Expanden los grupos recursivamente y muestran toda la información disponible.
Se usan en `get_published_changes`.

### Vista compacta (para base de datos y revisión)

| Método | Para qué sirve |
|---|---|
| `get_names` | Convierte referencias (objetos o uids) en una lista de nombres, sin metadatos |
| `expand_group_members` | Grupo → lista plana de IPs, redes y servicios reales. Recursiva, con protección contra ciclos y apoyada en el bulk |
| `collect_group_members` | Columnas de una regla → `{nombre_grupo: [miembros reales]}` |
| `summarize_object` | Objeto → resumen mínimo según su tipo (access-rule, nat-rule, vpn-community, grupo, host/red) |
| `diff_summaries` | Estado anterior vs. actual → frases en inglés: `"'10.1.2.3' added to source"`, `"rule disabled"`, `"action changed from 'Accept' to 'Drop'"` |
| `format_pending_changes` | Conjunto completo → informe en texto plano listo para pegar como comentario de revisión |

---

## 4. Los dos métodos principales

### `get_published_changes(url, name, from_date, to_date)`

Historial **sesión a sesión** con detalle completo. Vista de auditoría: quién publicó
qué y cuándo, con todos los objetos expandidos.

### `get_pending_changes(url, name, from_date, to_date)`

El **neto pre-push**: qué va a llegar realmente al firewall. Aplana todas las
operaciones de todas las sesiones en un timeline cronológico y las colapsa por uid:

| Secuencia dentro del rango | Resultado |
|---|---|
| creado + borrado | **desaparece** (nunca llega al firewall) |
| creado (± modificado) | un `added` con el estado final |
| modificado N veces | un `modified` con el diff contra **el estado instalado** |
| modificado + revertido | **desaparece** (diff vacío) |
| modificado + borrado | un `deleted` |

Cada registro de salida incluye:

- resumen compacto del objeto
- `changes`: frases legibles con lo que cambió exactamente
- `policy_packages`: paquetes afectados
- `group_members`: expansión real de los grupos referenciados
- `affected_rules`: reglas impactadas (cuando el cambio es sobre un grupo, host o red)
- `sessions`: usuario, comentarios de la publicación y fecha

Los objetos `Implied*` se filtran: Check Point los genera automáticamente al crear una
VPN community (dominios de cifrado, regla implícita) y desaparecen solos al borrarla,
así que solo añadirían ruido al informe.

> **Importante:** `from_date` debe ser la fecha de la última instalación. "Lo que se va
> a instalar" es exactamente "lo publicado desde el último push".

---

## 5. Descubrimientos de la API que explican el código

Cosas que no están en la documentación obvia y que costaron depuración:

- `show-changes` es **asíncrono** y sus cambios cuelgan de `task-details[0].changes`.
- Los objetos `modified` vienen envueltos en `new-object` / `old-object`; los `added`, no.
- **`details-level: 'full'` es obligatorio**: sin él, los objetos borrados y el estado
  anterior de los modificados vienen pelados (solo uid y tipo); con él llega la
  definición completa *inline*.
- Un objeto **borrado no se puede recuperar** con `show-object` (devuelve `None`). De
  ahí el patrón que gobierna los tres bucles: **"por uid si existe, inline si no"**.
- Las reglas NAT **no pertenecen a un layer sino a un package**, y `show-nat-rule`
  exige ese package, que hay que descubrir probando los del dominio.
- `where-used` no tiene variante bulk: solo acepta un objeto por llamada.

---

## 6. Optimizaciones aplicadas

- **Bulk de grupos**: `show-group` con `details-level: full` → 1 llamada por grupo en
  lugar de 1 por miembro.
- **Lista de paquetes cacheada**: se descarga una vez por ejecución en lugar de una vez
  por regla.
- **Caché general**: un único `self._cache` con claves prefijadas (`object:`,
  `group_members:`, `where_used:`, `packages`). Objetos repetidos como `Any` o grupos
  compartidos se resuelven una sola vez.

---

## 7. Flujo de uso completo

```python
obj_mds = CheckPoint()

# 1. Qué se va a instalar (neto, legible, almacenable)
results = obj_mds.get_pending_changes(
    obj_mds.base_url_v1, 'ETS-UK', from_date='2026-08-06'
)

# 2. Informe para revisión humana
print(obj_mds.format_pending_changes(results))

# 3. Tras la aprobación: verify + install
```

---

## 8. Pendientes antes del PR

- [ ] Fusionar con el `checkpoint.py` del proyecto, conservando `get_vpn`,
      `get_domain`, `verify_policy_package` e `install_policy_package`, y
      **sustituyendo `login` y `logout`** por las versiones corregidas.
- [ ] Test que cubra el requisito (el ticket sigue en UNCOVERED).
- [ ] Quitar los `print` de depuración que queden en local.
