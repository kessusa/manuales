# Group Comparator (EMEAPLAYFLOWS-3811): el código explicado desde cero

Este documento recorre **todo el código del comparador**, en el orden en que se ejecuta cuando alguien pulsa **Apply**. Está pensado para alguien que no ha leído código nunca.

Cada pieza sigue el mismo esquema:

- **Para qué sirve**, en una frase.
- **Qué entra** y **qué sale**, con datos de ejemplo.
- **El código, trozo a trozo**: qué hace cada línea.
- **Por qué se hizo así**: la razón de cada decisión y qué se descartó.

Todos los ejemplos de entrada y salida se han obtenido **ejecutando el código** con los datos del ticket, no están escritos a mano.

---

## Índice

0. [Lo mínimo de Python para leer este documento](#0-lo-mínimo-de-python-para-leer-este-documento)
1. [Qué problema resuelve](#1-qué-problema-resuelve)
2. [El ejemplo que seguiremos todo el rato](#2-el-ejemplo-que-seguiremos-todo-el-rato)
3. [El recorrido completo, de un vistazo](#3-el-recorrido-completo-de-un-vistazo)
4. [Dónde están los datos: las dos tablas](#4-dónde-están-los-datos-las-dos-tablas)
5. [Paso 1: la vista recibe la petición](#5-paso-1-la-vista-recibe-la-petición)
6. [Paso 2: cargar los datos (`load_group_maps_by_tag`)](#6-paso-2-cargar-los-datos-load_group_maps_by_tag)
7. [Paso 3: ordenar el árbol de cada firewall (`build_group_map`)](#7-paso-3-ordenar-el-árbol-de-cada-firewall-build_group_map)
8. [Paso 4: comparar todos los firewalls (`compare_group_across_firewalls`)](#8-paso-4-comparar-todos-los-firewalls-compare_group_across_firewalls)
9. [Paso 5: comparar un firewall con la referencia (`diff_group_maps`)](#9-paso-5-comparar-un-firewall-con-la-referencia-diff_group_maps)
10. [Paso 6: los comandos para igualar (`build_alignment_commands`)](#10-paso-6-los-comandos-para-igualar-build_alignment_commands)
11. [Paso 7: pintar la pantalla (las plantillas)](#11-paso-7-pintar-la-pantalla-las-plantillas)
12. [Paso 8: el export a CSV](#12-paso-8-el-export-a-csv)
13. [Casos especiales, con su salida real](#13-casos-especiales-con-su-salida-real)
14. [Resumen final](#14-resumen-final)

---

## 0. Lo mínimo de Python para leer este documento

No hace falta saber programar. Con estas piezas se entiende todo el comparador.

### Variable

Un nombre que guarda un valor, como una etiqueta en una caja.
```python
group_name = 'GECD_FORCE_PROD'      # the box "group_name" holds that text
```

### Función

Un bloque de código con nombre que **recibe datos (entrada)** y **devuelve un resultado (salida)**. Se declara con `def` y devuelve con `return`.
```python
def add_one(number):        # input: number
    return number + 1       # output: number + 1

add_one(4)                  # -> 5
```

### Los cuatro "contenedores" que usa el comparador

| Tipo | Se escribe | Ejemplo | Qué tiene de especial |
|---|---|---|---|
| **Lista** | `[ ]` | `['a', 'b', 'a']` | Mantiene el orden y admite repetidos. |
| **Tupla** | `( )` | `('Grp1', 'Grp 2')` | Como una lista, pero **no se puede modificar** después de crearla. |
| **Conjunto (set)** | `{ }` o `set()` | `{'a', 'b'}` | **Sin repetidos** y **sin orden**. Permite restar, ver más abajo. |
| **Diccionario (dict)** | `{clave: valor}` | `{'FW_1': 3}` | Guarda valores **por nombre** (clave). Se consulta con `d['FW_1']` → `3`. |

### La operación clave: restar conjuntos

Es **el corazón del comparador**. Restar dos conjuntos da "lo que está en el primero y no en el segundo":

```python
firewall  = {'10.3.4.1', '10.9.9.9'}
reference = {'10.3.4.1', '10.3.4.2'}

firewall - reference      # -> {'10.9.9.9'}   left over in the firewall  (ADDED)
reference - firewall      # -> {'10.3.4.2'}   missing from the firewall  (MISSING)
firewall & reference      # -> {'10.3.4.1'}   in both (intersection)
```

### Bucles y condiciones

```python
for fw in ['FW_1', 'FW_2']:     # repeat the block for each element
    print(fw)

if price > 10:                  # run the block only if the condition holds
    print('expensive')

while pending:                  # repeat while the condition still holds
    ...
```

### Lectura de la base de datos (Django)

En Django, cada **tabla** de la BD es una **clase** de Python (un "modelo"), y se consulta así:
```python
PlayflowsTagGroup.objects.filter(name='GECD_FORCE_PROD')
# = SQL: SELECT * FROM pf_tag_group WHERE name = 'GECD_FORCE_PROD'
```
Cada vez que se lee el resultado de un `filter`, Django lanza **una consulta** a la base de datos. Cuantas menos consultas, más rápida la página.

---

## 1. Qué problema resuelve

Un mismo grupo de red (por ejemplo `GECD_FORCE_PROD`) está definido en **muchos firewalls** a la vez. En teoría, todos deberían tener **exactamente el mismo contenido**. En la práctica, alguien añade una IP en un firewall y se olvida de los demás, y los grupos se "desincronizan".

El comparador:

1. Recibe un **grupo** y un **firewall de referencia** (el que consideramos correcto).
2. Busca ese grupo en **todos** los firewalls donde existe.
3. Compara cada uno con la referencia, **incluidos los subgrupos que tenga dentro**.
4. Dice, para cada firewall y cada subgrupo, **qué sobra** (*Added*) y **qué falta** (*Missing*).
5. Genera los **comandos de Playflows** para dejarlo igual que la referencia.
6. Permite **descargarlo en CSV**.

| Palabra | Significado |
|---|---|
| **FW tag** | El nombre de un firewall en Playflows. |
| **Grupo** | Una lista con nombre de IPs, servicios y/u otros grupos. |
| **Subgrupo** | Un grupo que está **dentro** de otro. Puede haber varios niveles. |
| **Miembro** | Un valor final de un grupo: una IP, una red o un servicio. |
| **Referencia** | El firewall elegido en el desplegable. Todo se compara contra él. |
| **Added** | Está en este firewall pero **no** en la referencia: **sobra**. |
| **Missing** | Está en la referencia pero **no** en este firewall: **falta**. |

---

## 2. El ejemplo que seguiremos todo el rato

Es el ejemplo del ticket. El grupo `GECD_FORCE_PROD` contiene dos IPs y dos subgrupos (`Grp1` y `Grp 2`), y existe en tres firewalls:

```
REF_FW (reference)              FW_1                                FW_2
GECD_FORCE_PROD                 GECD_FORCE_PROD                     identical to REF_FW
├─ 10.3.4.1                     ├─ 10.3.4.1
├─ 10.3.4.2                     │                    ← MISSING 10.3.4.2
├─ Grp1                         ├─ Grp1
│  └─ 10.34.55.64               │  └─ 10.34.55.64
└─ Grp 2                        └─ Grp 2
   └─ 10.45.24.23                  ├─ 10.45.24.23
                                   └─ 10.45.24.25   ← ADDED 10.45.24.25
```

Resultado esperado, como en el ticket:

| FW tag | Subgroup | Added value | Missing value |
|---|---|---|---|
| REF_FW | N/A | | |
| FW_1 | N/A | | 10.3.4.2 |
| FW_1 | Grp 2 | 10.45.24.25 | |
| FW_2 | N/A | | |

---

## 3. El recorrido completo, de un vistazo

```
 USER: types GECD_FORCE_PROD, chooses REF_FW, clicks Apply
   │
   │  GET /rss/ajax_load_data_group_comparator/?group_name=GECD_FORCE_PROD&tag_name=REF_FW
   ▼
 ① ajax_load_data_group_comparator        reads the two inputs, checks permissions
   │
   ├─ ② load_group_maps_by_tag            reads the DB: the group tree in every firewall
   │      └─ ③ build_group_map            tidies the tree of one firewall
   │
   ├─ ④ compare_group_across_firewalls    compares every firewall with the reference
   │      ├─ ⑤ diff_group_maps            differences of one firewall, subgroup by subgroup
   │      └─ ⑥ build_alignment_commands   Playflows commands to fix that firewall
   │
   └─ ⑦ render(...component.html)          turns the result into HTML
   ▼
 USER: sees the table · can copy commands · can export CSV (⑧)
```

| Nº | Pieza | ¿Toca la base de datos? |
|---|---|---|
| ① | `ajax_load_data_group_comparator` (vista) | No directamente |
| ② | `load_group_maps_by_tag` | **Sí, es la única** |
| ③ | `build_group_map` | No |
| ④ | `compare_group_across_firewalls` | No |
| ⑤ | `diff_group_maps` | No |
| ⑥ | `build_alignment_commands` | No |
| ⑦ | Plantillas HTML | No |
| ⑧ | Export CSV | Llama a ② |

> **Por qué separado así:** solo una pieza habla con la base de datos. Las demás son "puras": reciben datos y devuelven datos, siempre igual para la misma entrada. Eso tiene tres ventajas:
> 1. Se pueden **probar con tests sin base de datos**, que es rápido y fiable.
> 2. Si mañana se cambia de dónde vienen los datos (por ejemplo, volver a la API de Playflows), **solo se cambia ②**.
> 3. Cada función hace una sola cosa, así que es fácil encontrar un fallo.

---

## 4. Dónde están los datos: las dos tablas

El comparador **no pregunta a Playflows en directo**. Lee dos tablas que rellena el comando `playflows_groups_update` (del ticket 3637, el Group Lookup).

### Tabla `pf_tag_group` (modelo `PlayflowsTagGroup`)

Cada fila es **un grupo dentro de un firewall**. Con el ejemplo:

| id | tag (firewall) | name | content (IPs directas) |
|---|---|---|---|
| 101 | REF_FW | GECD_FORCE_PROD | `['10.3.4.1', '10.3.4.2']` |
| 102 | REF_FW | Grp1 | `['10.34.55.64']` |
| 103 | REF_FW | Grp 2 | `['10.45.24.23']` |
| 201 | FW_1 | GECD_FORCE_PROD | `['10.3.4.1']` |
| 202 | FW_1 | Grp1 | `['10.34.55.64']` |
| 203 | FW_1 | Grp 2 | `['10.45.24.23', '10.45.24.25']` |
| 301 | FW_2 | GECD_FORCE_PROD | `['10.3.4.1', '10.3.4.2']` |
| 302 | FW_2 | Grp1 | `['10.34.55.64']` |
| 303 | FW_2 | Grp 2 | `['10.45.24.23']` |
| 901 | FW_9 | OTHER_GROUP | `['1.1.1.1']` ← otro grupo, no interviene |

Fíjate en dos cosas:
- **El mismo grupo aparece una vez por firewall**, con un `id` distinto (101, 201, 301). Por eso cada fila sabe a qué firewall pertenece.
- `content` solo tiene las **IPs directas** del grupo. Los subgrupos **no** están ahí: van en la otra tabla.

### Tabla `pf_tag_group_children`

Cada fila dice **"el grupo X contiene al grupo Y"**, usando sus `id`:

| from (padre) | to (hijo) | Se lee |
|---|---|---|
| 101 | 102 | GECD_FORCE_PROD (REF_FW) contiene a Grp1 (REF_FW) |
| 101 | 103 | GECD_FORCE_PROD (REF_FW) contiene a Grp 2 (REF_FW) |
| 201 | 202 | GECD_FORCE_PROD (FW_1) contiene a Grp1 (FW_1) |
| 201 | 203 | GECD_FORCE_PROD (FW_1) contiene a Grp 2 (FW_1) |
| 301 | 302 | … |
| 301 | 303 | … |

> **Por qué una tabla aparte para la jerarquía:** un mismo subgrupo puede estar **dentro de varios padres** (en Playflows hay grupos con más de 20 padres). Una columna "padre" en `pf_tag_group` solo permitiría uno. Una tabla de relaciones "muchos a muchos" permite los que haga falta.
>
> **Por qué leer de la BD y no de la API de Playflows:**
> - Es **más rápido**: unas pocas consultas en vez de llamadas HTTP.
> - Es **exacto**: tiene la jerarquía real. La API devolvía el contenido aplanado y una búsqueda por patrón que podía coger otro grupo, como `GECD_FORCE_PROD_BLOCK`.
> - El precio: los datos son los de **la última sincronización**, no los del segundo actual.

---

## 5. Paso 1: la vista recibe la petición

**Para qué sirve:** es la puerta de entrada. Django la ejecuta cuando el navegador pide la URL. Lee lo que ha escrito el usuario, llama a las demás funciones y devuelve el HTML.

| | Ejemplo |
|---|---|
| **Entra** | `GET /rss/ajax_load_data_group_comparator/?group_name=GECD_FORCE_PROD&tag_name=REF_FW` |
| **Sale** | El HTML de la tabla de resultados (apartado 11). |

```python
@login_required
@user_passes_test(user_can_change_firewall)
def ajax_load_data_group_comparator(request):
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `@login_required` | Si el usuario no ha iniciado sesión, no entra. | Seguridad básica. |
| `@user_passes_test(user_can_change_firewall)` | Solo entra quien tenga el permiso de Firewall. | Es el **mismo permiso que el resto de la sección Firewall**, así que no hay que crear uno nuevo. |
| `def ...(request)` | `request` es la petición del navegador, con todo lo que envía. | Así funcionan todas las vistas de Django. |

> Los `@...` se llaman **decoradores**: son "filtros" que se ejecutan **antes** de la función. Si no se cumplen, la función ni se ejecuta.

```python
    group_name = request.GET.get('group_name', '').strip()
    reference_tag = request.GET.get('tag_name', '').strip()
```

| Trozo | Qué hace | Ejemplo |
|---|---|---|
| `request.GET` | Los parámetros que van en la URL después del `?`. | `{'group_name': 'GECD_FORCE_PROD', 'tag_name': 'REF_FW'}` |
| `.get('group_name', '')` | Lee el parámetro. **Si no viene, devuelve `''`** en vez de dar error. | `'GECD_FORCE_PROD'` |
| `.strip()` | Quita espacios al principio y al final. | `'GECD_FORCE_PROD '` → `'GECD_FORCE_PROD'` |

> **Por qué `.strip()`:** en una prueba real llegó el nombre con un espacio al final (copiado de otro sitio), y la búsqueda exacta no lo encontraba.

```python
    group_maps_by_tag = load_group_maps_by_tag(group_name) if group_name and reference_tag else {}
```

Se lee así: *"si hay nombre de grupo **y** hay referencia, carga los datos; si falta alguno, usa un diccionario vacío `{}`"*.

> **Por qué:** si el usuario no ha rellenado los dos campos, no tiene sentido consultar la base de datos.

```python
    firewalls = []
    if reference_tag in group_maps_by_tag:
        firewalls = compare_group_across_firewalls(group_name, reference_tag, group_maps_by_tag)
```

- `group_maps_by_tag` tiene una entrada por cada firewall **donde existe el grupo**.
- Si la referencia **no está** entre ellos (el grupo no existe en ese firewall), no hay contra qué comparar: `firewalls` se queda vacío y la pantalla dirá "not found".
- Si está, compara (apartado 8).

```python
    context = {
        'firewalls': firewalls,
        'differing_count': sum(1 for firewall in firewalls if firewall['differences']),
        'group_name': group_name,
        'reference_tag': reference_tag,
    }
    return render(request, 'tools/firewall_components/group_comparator_component.html', context)
```

- `context` es la **"bolsa" de datos que se pasa a la plantilla HTML**.
- `differing_count` cuenta cuántos firewalls tienen diferencias: suma 1 por cada uno con `differences` no vacío. Con el ejemplo vale **1** (solo FW_1).
- `render(...)` rellena la plantilla con esos datos y devuelve el HTML.

> **Por qué HTML y no JSON:** es la **convención del equipo** para las búsquedas (como `avi_waf_search`). El servidor devuelve el HTML ya hecho, el navegador solo lo pega, y la plantilla se puede probar con tests de Django.

---

## 6. Paso 2: cargar los datos (`load_group_maps_by_tag`)

Es la función más importante y la única que habla con la base de datos.

**Para qué sirve:** dado el nombre de un grupo, encuentra **todos los firewalls** donde existe y, para cada uno, carga ese grupo **y todos sus subgrupos, a cualquier profundidad**.

| | Ejemplo |
|---|---|
| **Entra** | `'GECD_FORCE_PROD'` |
| **Sale** | Un diccionario con el árbol del grupo en cada firewall (ver al final de este apartado). |

### La idea, antes del código: bajar por pisos

Imagina el árbol del grupo como un edificio:

```
piso 0:  GECD_FORCE_PROD                (in REF_FW, FW_1, FW_2)
piso 1:  Grp1, Grp 2                    (in REF_FW, FW_1, FW_2)
piso 2:  (nothing)
```

La función baja **piso a piso** y, en cada piso, trae **todos los firewalls a la vez** con dos consultas:
1. "Dame los grupos de este piso" (`pf_tag_group`).
2. "Dame los hijos de todos ellos" (`pf_tag_group_children`).

Los hijos encontrados forman el siguiente piso. Cuando un piso no tiene hijos, se termina.

> **Por qué por pisos:** la alternativa obvia es ir grupo a grupo: "dame GECD_FORCE_PROD de REF_FW, ahora sus hijos, ahora Grp1 de REF_FW, ahora sus hijos…". Eso es **una consulta por cada grupo y cada firewall** (el famoso problema **"N+1"**). Con 3 grupos × 40 firewalls serían ~240 consultas. Por pisos, son **2 por piso, haya 3 firewalls o 300**.

### 6.1 Preparar los "cajones"

```python
def load_group_maps_by_tag(root_group):
    members_by_tag = defaultdict(lambda: defaultdict(set))
    subgroups_by_tag = defaultdict(lambda: defaultdict(set))
    group_index = {}
    level_queryset = PlayflowsTagGroup.objects.filter(name=root_group)
```

Se crean tres variables vacías donde se irá guardando lo que llegue de la base de datos:

| Variable | Forma | Responde a la pregunta |
|---|---|---|
| `members_by_tag` | `{firewall: {grupo: {IPs}}}` | "En este firewall, ¿qué IPs tiene este grupo?" |
| `subgroups_by_tag` | `{firewall: {grupo: {ids de hijos}}}` | "En este firewall, ¿qué hijos tiene este grupo?" |
| `group_index` | `{id: (firewall, grupo)}` | "¿Qué es el id 203?" → `('FW_1', 'Grp 2')` |

#### ¿Qué es `defaultdict` y por qué se usa?

Un diccionario normal **da error** si pides una clave que no existe:
```python
d = {}
d['REF_FW'].add('10.3.4.1')         # ERROR: KeyError 'REF_FW'
```
Para evitarlo habría que comprobarlo cada vez:
```python
if 'REF_FW' not in d:
    d['REF_FW'] = set()
d['REF_FW'].add('10.3.4.1')
```
`defaultdict(set)` **hace esa comprobación solo**: si la clave no existe, la crea con un `set()` vacío y sigue.
```python
d = defaultdict(set)
d['REF_FW'].add('10.3.4.1')         # 'REF_FW' did not exist -> created as {} -> add
# d = {'REF_FW': {'10.3.4.1'}}
```
Lo que va entre paréntesis (`set`) es **la receta para fabricar el valor vacío**, no el valor en sí.

#### ¿Y el `lambda`?

Aquí hay **dos niveles**: `[firewall][grupo]`. Si falta el firewall, hay que crear **otro diccionario con la misma magia**, y si falta el grupo, un `set` vacío. La receta del primer nivel tiene que ser "fabrica un `defaultdict(set)` nuevo":

| Intento | Resultado |
|---|---|
| `defaultdict(defaultdict(set))` | ❌ Error. Se le pasa **un diccionario ya hecho**, no una receta que se pueda ejecutar. |
| `defaultdict(defaultdict)` | ❌ El segundo nivel no sabe crear `set`, así que da error al añadir IPs. |
| `defaultdict(lambda: defaultdict(set))` | ✅ Correcto. |

`lambda: defaultdict(set)` es **una función mini, sin nombre**, que cada vez que se llama devuelve un `defaultdict(set)` **nuevo**. Equivale a:
```python
def new_group_dict():
    return defaultdict(set)

members_by_tag = defaultdict(new_group_dict)
```
Es importante que sea **nuevo** cada vez, para que cada firewall tenga su propio cajón y no compartan uno.

> **Por qué así:** el código queda corto y no se puede olvidar ninguna comprobación (con dos niveles serían dos `if` por cada fila leída).

#### La primera consulta

```python
    level_queryset = PlayflowsTagGroup.objects.filter(name=root_group)
```
Prepara el **piso 0**: "todas las filas de `pf_tag_group` cuyo nombre sea `GECD_FORCE_PROD`, **en cualquier firewall**".

> Django **todavía no consulta** la base de datos aquí. Lo hará en el momento de leer el resultado, en el bucle siguiente.

### 6.2 El bucle por pisos: leer los grupos del piso

```python
    while True:
        level_ids = []
        for group_id, tag_name, name, content in level_queryset.values_list('id', 'tag__tag_name', 'name', 'content'):
            group_index[group_id] = (tag_name, name)
            members_by_tag[tag_name][name].update(to_hashable(item) for item in content or ())
            level_ids.append(group_id)
        if not level_ids:
            break
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `while True:` | Repite "para siempre" hasta encontrar un `break`. | No sabemos de antemano cuántos pisos tiene el árbol. |
| `level_ids = []` | Lista vacía para los ids de este piso. | Se usarán para pedir sus hijos. |
| `.values_list('id', 'tag__tag_name', 'name', 'content')` | **Aquí se hace la consulta.** Pide solo esas 4 columnas. `tag__tag_name` sigue la relación hasta la tabla de tags y trae el nombre del firewall. | Pedir solo lo necesario gasta menos memoria y es más rápido que traer objetos completos. Y como el nombre del firewall viene en la misma consulta, no hace falta otra. |
| `group_index[group_id] = (tag_name, name)` | Apunta qué es cada id. | Los hijos vendrán como ids y habrá que traducirlos. |
| `members_by_tag[tag_name][name].update(...)` | Guarda las IPs del grupo en su cajón. | Ver tabla siguiente. |
| `level_ids.append(group_id)` | Añade el id a la lista del piso. | |
| `if not level_ids: break` | Si este piso no trajo nada, termina. | Pasa cuando el grupo **no existe** en ningún firewall. |

Detalle de `members_by_tag[tag_name][name].update(to_hashable(item) for item in content or ())`:

| Trozo | Qué hace | Por qué |
|---|---|---|
| `members_by_tag[tag_name][name]` | El cajón de este grupo en este firewall. Se crea solo si no existía (`defaultdict`). | |
| `content or ()` | Si `content` está vacío o es `NULL`, usa una tupla vacía `()`. | Recorrer `None` daría error. |
| `to_hashable(item)` | Convierte cada valor a texto si hace falta (ver 6.5). | Un `set` solo admite valores "simples". |
| `.update(...)` | **Añade** los valores al set, sin borrar lo que ya hubiera. | Si un mismo nombre existe como grupo `ip` y como grupo `service` en un firewall, llegan **dos filas**: con `=` la segunda borraría la primera; con `.update` se juntan. |

**Estado tras leer el piso 0 del ejemplo** (salida real):
```
rows read:  (101, 'REF_FW', 'GECD_FORCE_PROD'), (201, 'FW_1', 'GECD_FORCE_PROD'), (301, 'FW_2', 'GECD_FORCE_PROD')

group_index    = {101: ('REF_FW', 'GECD_FORCE_PROD'),
                  201: ('FW_1',   'GECD_FORCE_PROD'),
                  301: ('FW_2',   'GECD_FORCE_PROD')}

members_by_tag = {'REF_FW': {'GECD_FORCE_PROD': {'10.3.4.1', '10.3.4.2'}},
                  'FW_1':   {'GECD_FORCE_PROD': {'10.3.4.1'}},
                  'FW_2':   {'GECD_FORCE_PROD': {'10.3.4.1', '10.3.4.2'}}}

level_ids      = [101, 201, 301]
```

Fíjate: la fila 901 (`OTHER_GROUP` en FW_9) no aparece, porque no se llama `GECD_FORCE_PROD`.

### 6.3 El bucle por pisos: pedir los hijos

```python
        child_ids = set()
        edges = PlayflowsTagGroup.children.through.objects.filter(
            from_playflowstaggroup_id__in=level_ids
        ).values_list('from_playflowstaggroup_id', 'to_playflowstaggroup_id')
        for parent_id, child_id in edges:
            child_ids.add(child_id)
            subgroups_by_tag[group_index[parent_id][0]][group_index[parent_id][1]].add(child_id)
```

| Línea | Qué hace |
|---|---|
| `child_ids = set()` | Conjunto vacío para los hijos de este piso. |
| `PlayflowsTagGroup.children.through` | Es la tabla `pf_tag_group_children`. Django la crea sola para la relación "muchos a muchos". |
| `.filter(from_playflowstaggroup_id__in=level_ids)` | "Todas las relaciones cuyo padre esté en `[101, 201, 301]`". **Una sola consulta** para todos los firewalls. `__in` = "está en esta lista". |
| `.values_list(...)` | Solo trae parejas `(padre, hijo)`. |
| `child_ids.add(child_id)` | Apunta el hijo para el siguiente piso. |
| `subgroups_by_tag[...][...].add(child_id)` | Apunta "este padre tiene este hijo", en el cajón de su firewall. |

La última línea parece complicada; desmontada con la relación `(101, 102)` queda así:
```python
group_index[101]        # -> ('REF_FW', 'GECD_FORCE_PROD')
group_index[101][0]     # -> 'REF_FW'            (position 0 of the tuple)
group_index[101][1]     # -> 'GECD_FORCE_PROD'   (position 1 of the tuple)

subgroups_by_tag['REF_FW']['GECD_FORCE_PROD'].add(102)
```

**Estado tras el piso 0** (salida real):
```
edges            = [(101, 102), (101, 103), (201, 202), (201, 203), (301, 302), (301, 303)]
child_ids        = {102, 103, 202, 203, 302, 303}
subgroups_by_tag = {'REF_FW': {'GECD_FORCE_PROD': {102, 103}},
                    'FW_1':   {'GECD_FORCE_PROD': {202, 203}},
                    'FW_2':   {'GECD_FORCE_PROD': {302, 303}}}
```

### 6.4 El bucle por pisos: preparar el siguiente piso

```python
        pending_ids = child_ids - group_index.keys()
        if not pending_ids:
            break
        level_queryset = PlayflowsTagGroup.objects.filter(id__in=pending_ids)
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `child_ids - group_index.keys()` | **Resta**: los hijos que **todavía no hemos cargado**. | Si un grupo ya se cargó (porque es hijo de dos padres, o porque hay un **ciclo**: A contiene a B y B contiene a A), no se vuelve a pedir. Sin esto, un ciclo haría que el bucle no terminara nunca. |
| `if not pending_ids: break` | Si no queda nada nuevo, hemos llegado al fondo. | |
| `filter(id__in=pending_ids)` | El siguiente piso son esos ids. Vuelta al principio del `while`. | |

Recorrido completo del ejemplo (salida real):
```
piso 0: reads 101, 201, 301           -> children: 102, 103, 202, 203, 302, 303
piso 1: reads 102..303                -> children: none   -> pending_ids empty -> break
```

**Consultas lanzadas en total (salida real): 4**
```
1. pf_tag_group            WHERE name = 'GECD_FORCE_PROD'
2. pf_tag_group_children   WHERE from_id IN (101, 201, 301)
3. pf_tag_group            WHERE id IN (102, 103, 202, 203, 302, 303)
4. pf_tag_group_children   WHERE from_id IN (102, 103, 202, 203, 302, 303)
```
Con 300 firewalls en vez de 3 seguirían siendo **4**: solo serían filas más largas.

### 6.5 `to_hashable`: la función auxiliar

```python
def to_hashable(value):
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
```

**Para qué sirve:** un `set` solo acepta valores "simples" (textos, números). Si algún elemento de `content` fuera un diccionario, daría error. Esta función lo convierte en texto.

| Entra | Sale | Qué ha pasado |
|---|---|---|
| `'10.3.4.1'` | `'10.3.4.1'` | Ya es texto: se devuelve igual. |
| `{'b': 1, 'a': 2}` | `'{"a": 2, "b": 1}'` | Se convierte a texto JSON con las claves **ordenadas**. |

> **Por qué ordenar las claves:** `{'b':1,'a':2}` y `{'a':2,'b':1}` son el mismo dato escrito en distinto orden. Ordenándolas dan **el mismo texto**, y la comparación no da una falsa diferencia.

### 6.6 Al final: de ids a nombres, y un mapa por firewall

```python
    group_maps_by_tag = {}
    for tag_name, members_by_group in members_by_tag.items():
        subgroups_by_group = {
            parent_name: {group_index[child_id][1] for child_id in child_ids}
            for parent_name, child_ids in subgroups_by_tag[tag_name].items()
        }
        members_by_group = {
            name: members - subgroups_by_group.get(name, set())
            for name, members in members_by_group.items()
        }
        group_maps_by_tag[tag_name] = build_group_map(root_group, members_by_group, subgroups_by_group)
    return group_maps_by_tag
```

Para **cada firewall** (`for tag_name, ... in members_by_tag.items()`):

**1. Cambiar ids de hijos por nombres.**
```python
{102, 103}  ->  {group_index[102][1], group_index[103][1]}  ->  {'Grp1', 'Grp 2'}
```
> **Por qué:** se compara **por nombre**. El `id` de `Grp1` es distinto en cada firewall (102, 202, 302), pero el nombre es el mismo, y eso es lo que importa.

**2. Quitar los nombres de subgrupos de la lista de miembros.**
```python
members - subgroups_by_group.get(name, set())
```
Es una medida defensiva: si en `content` aparecieran también los nombres de los subgrupos, no se contarían dos veces (como IP y como subgrupo). `.get(name, set())` = "los hijos de este grupo o, si no tiene, un conjunto vacío".

**3. Llamar a `build_group_map`** (apartado 7) para dejar el árbol ordenado.

### Salida final de `load_group_maps_by_tag` (real)

```python
{
 'REF_FW': {'GECD_FORCE_PROD': {'members': {'10.3.4.1', '10.3.4.2'}, 'subgroups': {'Grp1', 'Grp 2'}},
            'Grp1':            {'members': {'10.34.55.64'},           'subgroups': set()},
            'Grp 2':           {'members': {'10.45.24.23'},           'subgroups': set()}},
 'FW_1':   {'GECD_FORCE_PROD': {'members': {'10.3.4.1'},              'subgroups': {'Grp1', 'Grp 2'}},
            'Grp1':            {'members': {'10.34.55.64'},           'subgroups': set()},
            'Grp 2':           {'members': {'10.45.24.23', '10.45.24.25'}, 'subgroups': set()}},
 'FW_2':   {... same as REF_FW ...},
}
```
`set()` es un conjunto vacío: ese grupo no tiene subgrupos.

---

## 7. Paso 3: ordenar el árbol de cada firewall (`build_group_map`)

**Para qué sirve:** recibe los miembros y los subgrupos de **un** firewall y construye un diccionario limpio con **solo los grupos que cuelgan del grupo raíz**.

| | Ejemplo (REF_FW) |
|---|---|
| **Entra** | `root_group='GECD_FORCE_PROD'`<br>`members_by_group={'GECD_FORCE_PROD': {...}, 'Grp1': {...}, 'Grp 2': {...}}`<br>`subgroups_by_group={'GECD_FORCE_PROD': {'Grp1', 'Grp 2'}}` |
| **Sale** | `{'GECD_FORCE_PROD': {'members': {...}, 'subgroups': {'Grp1','Grp 2'}}, 'Grp1': {...}, 'Grp 2': {...}}` |

```python
def build_group_map(root_group, members_by_group, subgroups_by_group):
    group_map = {}
    pending = [root_group]
    while pending:
        group_name = pending.pop()
        if group_name in group_map:
            continue
        subgroups = set(subgroups_by_group.get(group_name, ()))
        group_map[group_name] = {
            'members': set(members_by_group.get(group_name, ())),
            'subgroups': subgroups,
        }
        pending.extend(subgroups - group_map.keys())
    return group_map
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `group_map = {}` | El resultado, vacío al principio. | |
| `pending = [root_group]` | Lista de "grupos por visitar". Empieza con la raíz. | |
| `while pending:` | Mientras quede alguno por visitar… | |
| `group_name = pending.pop()` | Saca uno de la lista. | |
| `if group_name in group_map: continue` | Si ya se visitó, se salta (`continue` = "pasa al siguiente"). | Evita repetir trabajo con hijos compartidos y **evita bucles infinitos** si hay ciclos. |
| `.get(group_name, ())` | "Lo que haya para este grupo o, si no hay nada, vacío". | Un grupo sin IPs o sin hijos no da error. |
| `group_map[group_name] = {...}` | Guarda el grupo con sus `members` y sus `subgroups`. | Siempre la **misma forma** para todos los grupos: facilita la comparación posterior. |
| `pending.extend(subgroups - group_map.keys())` | Añade a la lista los hijos que todavía no se han visitado. | |

Recorrido con REF_FW:
```
pending = ['GECD_FORCE_PROD']   -> visits it, adds Grp1 and Grp 2
pending = ['Grp1', 'Grp 2']     -> visits Grp 2 (no children)
pending = ['Grp1']              -> visits Grp1 (no children)
pending = []                    -> end
```

> **Por qué hace falta si ya tenemos los datos:** (1) asegura que solo entran los grupos **que cuelgan de la raíz**; (2) da a todos la **misma forma** `{'members', 'subgroups'}`; (3) protege frente a ciclos. Además, como no toca la base de datos, se puede probar con tests sin BD.

---

## 8. Paso 4: comparar todos los firewalls (`compare_group_across_firewalls`)

**Para qué sirve:** compara **cada** firewall con la referencia y prepara la lista que se verá en pantalla.

| | Ejemplo |
|---|---|
| **Entra** | `'GECD_FORCE_PROD'`, `'REF_FW'` y los mapas del apartado 6. |
| **Sale** | Una lista con un "resumen" por firewall (abajo). |

```python
def compare_group_across_firewalls(root_group, reference_tag, group_maps_by_tag):
    reference_map = group_maps_by_tag[reference_tag]
    firewalls = []
    for fw_tag in sorted(group_maps_by_tag):
        if fw_tag == reference_tag:
            continue
        differences = diff_group_maps(root_group, reference_map, group_maps_by_tag[fw_tag])
        firewalls.append({
            'fw_tag': fw_tag,
            'is_reference': False,
            'differences': differences,
            'added_count': sum(len(row['added_values']) + len(row['added_subgroups']) for row in differences),
            'missing_count': sum(len(row['missing_values']) + len(row['missing_subgroups']) for row in differences),
            'alignment_commands': build_alignment_commands(fw_tag, root_group, differences),
        })
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `reference_map = ...[reference_tag]` | Saca el árbol de la referencia. | Es contra lo que se compara todo. |
| `for fw_tag in sorted(...)` | Recorre los firewalls **en orden alfabético**. | Para que el resultado salga siempre en el mismo orden. |
| `if fw_tag == reference_tag: continue` | Salta la referencia. | No tiene sentido compararla consigo misma. |
| `diff_group_maps(...)` | Diferencias de este firewall (apartado 9). | |
| `'added_count': sum(...)` | **Cuántos** valores sobran en total, sumando IPs y subgrupos de todas las filas. | Es el número de la columna *Added* del resumen. |
| `'missing_count': sum(...)` | Lo mismo con lo que falta. | Columna *Missing*. |
| `'alignment_commands': ...` | Los comandos para arreglarlo (apartado 10). | Botón copiar. |

```python
    firewalls.sort(key=lambda firewall: not firewall['differences'])
```
**Pone primero los firewalls con diferencias.** El truco:
- Una lista vacía `[]` cuenta como "falso", así que `not []` es `True`.
- Una lista con algo cuenta como "verdadero", así que `not [algo]` es `False`.
- Al ordenar, `False` va antes que `True`, y los que **tienen** diferencias quedan **arriba**.
- `sort` conserva el orden alfabético dentro de cada bloque.

> **Por qué:** al usuario le interesan primero los que hay que arreglar. Los idénticos se listan igualmente (lo pide el ticket), pero al final.

```python
    reference = {
        'fw_tag': reference_tag, 'is_reference': True, 'differences': [],
        'added_count': 0, 'missing_count': 0, 'alignment_commands': '',
    }
    return [reference] + firewalls
```
La referencia se añade **siempre la primera**, con la misma forma que los demás, para que la plantilla la trate igual.

**Salida real:**
```python
[
 {'fw_tag': 'REF_FW', 'is_reference': True,  'differences': [],
  'added_count': 0, 'missing_count': 0, 'alignment_commands': ''},

 {'fw_tag': 'FW_1',   'is_reference': False,
  'differences': [ {...root: missing 10.3.4.2...}, {...Grp 2: added 10.45.24.25...} ],
  'added_count': 1, 'missing_count': 1,
  'alignment_commands': 'add to FW_1:GECD_FORCE_PROD 10.3.4.2\nrm from FW_1:Grp 2 10.45.24.25'},

 {'fw_tag': 'FW_2',   'is_reference': False, 'differences': [],
  'added_count': 0, 'missing_count': 0, 'alignment_commands': ''},
]
```

---

## 9. Paso 5: comparar un firewall con la referencia (`diff_group_maps`)

**Para qué sirve:** recorre el árbol grupo a grupo y, en cada uno, calcula qué sobra y qué falta. Devuelve **una fila por cada grupo que tenga alguna diferencia**.

| | Ejemplo |
|---|---|
| **Entra** | `'GECD_FORCE_PROD'`, el mapa de REF_FW y el mapa de FW_1. |
| **Sale** | La lista de diferencias (abajo). |

```python
def diff_group_maps(root_group, reference_map, target_map):
    rows = []
    visited = set()
    pending = deque([(root_group, ())])
    while pending:
        group_name, subgroup_path = pending.popleft()
        if group_name in visited:
            continue
        visited.add(group_name)
```

| Línea | Qué hace | Por qué |
|---|---|---|
| `rows = []` | Aquí irán las filas con diferencias. | |
| `visited = set()` | Grupos ya comparados. | Para no comparar dos veces y no entrar en ciclos. |
| `deque([(root_group, ())])` | Una **cola**: el primero que entra es el primero que sale. Empieza con la raíz y una **ruta vacía** `()`. | Ver el "por qué" al final. |
| `pending.popleft()` | Saca el primero de la cola: `('GECD_FORCE_PROD', ())`. | |

**¿Qué es `subgroup_path`?** El camino desde la raíz hasta el grupo que se está mirando:
- `()` (vacía) → es el propio grupo raíz. En pantalla se muestra **N/A**.
- `('Grp 2',)` → `Grp 2`, que está dentro de la raíz.
- `('L1', 'L2')` → `L2`, que está dentro de `L1`, que está dentro de la raíz.

```python
        reference = reference_map[group_name]
        target = target_map[group_name]
        row = {
            'subgroup_path': subgroup_path,
            'added_values': sorted(target['members'] - reference['members']),
            'missing_values': sorted(reference['members'] - target['members']),
            'added_subgroups': sorted(target['subgroups'] - reference['subgroups']),
            'missing_subgroups': sorted(reference['subgroups'] - target['subgroups']),
        }
```
Aquí está **la resta de conjuntos** del apartado 0. Con el grupo raíz de FW_1:

| Cálculo | Operación | Resultado |
|---|---|---|
| IPs que sobran | `{'10.3.4.1'} - {'10.3.4.1', '10.3.4.2'}` | `[]` |
| IPs que faltan | `{'10.3.4.1', '10.3.4.2'} - {'10.3.4.1'}` | `['10.3.4.2']` |
| Subgrupos que sobran | `{'Grp1','Grp 2'} - {'Grp1','Grp 2'}` | `[]` |
| Subgrupos que faltan | `{'Grp1','Grp 2'} - {'Grp1','Grp 2'}` | `[]` |

`sorted(...)` convierte cada resultado en una **lista ordenada**.

> **Por qué ordenar:** los `set` no tienen orden. Sin `sorted`, las IPs podrían salir cada vez en un orden distinto, en pantalla, en el CSV y en los tests.

```python
        if row['added_values'] or row['missing_values'] or row['added_subgroups'] or row['missing_subgroups']:
            rows.append(row)
```
Solo guarda la fila si hay **alguna** diferencia (`or` = "o"). `Grp1` es igual en los dos y **no genera fila**.

```python
        for child_name in sorted(reference['subgroups'] & target['subgroups']):
            pending.append((child_name, subgroup_path + (child_name,)))
    return rows
```
- `&` es la **intersección**: los subgrupos que existen **en los dos** firewalls. Solo se baja a comparar esos.
- `subgroup_path + (child_name,)` alarga la ruta: `()` pasa a `('Grp 2',)`. La coma de `(child_name,)` es lo que hace que sea una tupla de un elemento.

> **Por qué solo la intersección:** si un subgrupo **falta entero** en un firewall, ya queda apuntado como `missing_subgroups` del padre. Mirar dentro no aporta nada, porque todo su contenido "falta" por definición.

> **Por qué una cola (recorrido "en anchura"):** se comparan primero todos los hijos directos, luego los nietos, y así sucesivamente. Si un subgrupo cuelga de varios padres, se compara **una sola vez** (gracias a `visited`) y con **la ruta más corta**, que es la más fácil de leer.

**Salida real para FW_1:**
```python
[
 {'subgroup_path': (),         'added_values': [],              'missing_values': ['10.3.4.2'],
  'added_subgroups': [],       'missing_subgroups': []},
 {'subgroup_path': ('Grp 2',), 'added_values': ['10.45.24.25'], 'missing_values': [],
  'added_subgroups': [],       'missing_subgroups': []},
]
```
**Salida real para FW_2:** `[]`, sin diferencias.

---

## 10. Paso 6: los comandos para igualar (`build_alignment_commands`)

**Para qué sirve:** convierte las diferencias de un firewall en **comandos de Playflows** que lo dejan igual que la referencia. Es lo que copia el botón de copiar.

| | Ejemplo |
|---|---|
| **Entra** | `'FW_1'`, `'GECD_FORCE_PROD'` y las dos filas del apartado 9. |
| **Sale** | `add to FW_1:GECD_FORCE_PROD 10.3.4.2`<br>`rm from FW_1:Grp 2 10.45.24.25` |

```python
def build_alignment_commands(fw_tag, root_group, differences):
    add_commands = []
    rm_commands = []
    for row in differences:
        group_name = row['subgroup_path'][-1] if row['subgroup_path'] else root_group
        target_group = f'{fw_tag}:{group_name}'
```

| Línea | Qué hace | Ejemplo |
|---|---|---|
| `add_commands`, `rm_commands` | Dos listas separadas: lo que hay que añadir y lo que hay que quitar. | |
| `row['subgroup_path'][-1]` | El **último** grupo de la ruta (`[-1]` = el último). Es el que hay que tocar. | `('Grp 2',)` → `'Grp 2'` |
| `... if row['subgroup_path'] else root_group` | Si la ruta está vacía, el grupo es la raíz. | `()` → `'GECD_FORCE_PROD'` |
| `f'{fw_tag}:{group_name}'` | Construye el texto `FIREWALL:GRUPO`. Las `f'...'` permiten meter variables entre `{}`. | `'FW_1:Grp 2'` |

```python
        for values in (row['missing_subgroups'], row['missing_values']):
            if values:
                add_commands.append(f'add to {target_group} {" ".join(values)}')
        for values in (row['added_subgroups'], row['added_values']):
            if values:
                rm_commands.append(f'rm from {target_group} {" ".join(values)}')
    return '\n'.join(add_commands + rm_commands)
```

| Línea | Qué hace | Por qué |
|---|---|---|
| Lo que **falta** → `add to` | Hay que añadirlo para igualar a la referencia. | |
| Lo que **sobra** → `rm from` | Hay que quitarlo. | |
| `" ".join(values)` | Junta la lista separando con espacios: `['a','b']` → `'a b'`. | Playflows acepta varios valores en un comando. |
| Subgrupos e IPs en comandos **separados** | | Así lo indica la guía de comandos de Playflows. |
| `add_commands + rm_commands` | **Primero todos los `add` y después todos los `rm`**. | Así **ningún grupo se queda vacío** a mitad del proceso. Si un grupo tiene que pasar de `{A}` a `{B}`, primero se añade B y después se quita A. |
| `'\n'.join(...)` | Un comando por línea (`\n` = salto de línea). | Listo para pegar. |

> ⚠️ Los comandos **no se ejecutan solos**: solo se copian. Antes de usarlos en producción conviene probar en DEV que la sintaxis `FW:GRUPO` funciona también con subgrupos y que Playflows acepta las IPs con `/32`.

---

## 11. Paso 7: pintar la pantalla (las plantillas)

**Para qué sirve:** convertir la lista del apartado 8 en la tabla que ve el usuario.

| | |
|---|---|
| **Entra** | El `context` de la vista: `firewalls`, `differing_count`, `group_name`, `reference_tag`. |
| **Sale** | HTML. |

Con el ejemplo, la pantalla queda así:
```
→ Show result(s)                                                        [x]
GECD_FORCE_PROD found on 3 firewalls · 1 differs from REF_FW      [Export CSV]

FW Tag              Status              Added   Missing
REF_FW              Reference             -        -
˅ FW_1  [copy]      2 groups differ        1        1      ← click: shows the detail
    Subgroup    Added value     Missing value
    N/A                         10.3.4.2
    Grp 2       10.45.24.25
FW_2                Identical             -        -
```

Las plantillas usan el lenguaje de Django: `{{ variable }}` escribe un valor y `{% ... %}` es lógica (`if`, `for`).

### 11.1 `group_comparator_component.html`

| Trozo | Qué hace | Por qué |
|---|---|---|
| `{% if firewalls %} ... {% else %}` | Si hay resultados, pinta la tabla; si no, el mensaje "not found". | |
| `{{ firewalls\|length }} firewall{{ firewalls\|length\|pluralize }}` | Cuenta los firewalls y añade la "s" solo si son varios. | "1 firewall" / "3 firewalls". |
| `{% if differing_count %}` | Frase en rojo "N differ from REF_FW" o en verde "all identical". | Resumen de un vistazo. |
| `{% for firewall in firewalls %}` | Una fila por firewall. | |
| `{% if firewall.differences %}` | Con diferencias: fila pulsable + fila oculta con el detalle. Sin diferencias: badge **Reference** o **Identical**. | Tabla compacta: el detalle solo aparece si se pide. |
| `data-bs-toggle="collapse" data-bs-target="#group-comparator-fw-{{ forloop.counter }}"` | Bootstrap 5 muestra u oculta la fila del detalle al hacer clic. `forloop.counter` (1, 2, 3…) hace cada `id` único. | Sin escribir JavaScript propio. |
| `{{ row.subgroup_path\|join:" › "\|default:"N/A" }}` | Convierte la ruta en texto: `('L1','L2')` → `L1 › L2`; vacía → **N/A**. | Como pide el ticket. |
| Botón `group-comparator-copy` + `<textarea class="d-none" readonly>` | El textarea oculto guarda los comandos; el botón los copia. | Se ocultó el textarea porque visible "quedaba feo"; solo se copia. |
| `{% load custom_filters %}` + botón **Export CSV** | Enlace al export (apartado 12). | |

### 11.2 `group_comparator_values.html`

Trozo reutilizable que pinta una celda de valores (*Added value* o *Missing value*):
1. Primero los **subgrupos** enteros, con un badge **Group** para no confundirlos con IPs.
2. Después los **10 primeros** valores.
3. Si hay más, un desplegable **"+N more"** con el resto (`<details>`, nativo del navegador, sin JavaScript).

> **Por qué:** un grupo puede tener cientos de IPs. Así la tabla no se hace enorme, pero no se pierde ningún dato.

### 11.3 El botón de copiar

- Recoge el texto del textarea oculto y lo copia al portapapeles: `navigator.clipboard.writeText(...)`, con `execCommand('copy')` como alternativa si la página no va por HTTPS.
- **`event.stopPropagation()`**: el botón está **dentro** de la fila pulsable. Sin esto, al copiar también se abriría o cerraría el detalle.
- Cambia el icono durante un momento para confirmar que ha copiado.

---

## 12. Paso 8: el export a CSV

**Para qué sirve:** descargar el resultado como CSV, con el formato exacto de la tabla del ticket.

| | Ejemplo |
|---|---|
| **Entra** | Clic en **Export CSV** → `GET /rss/download_csv_stream_report/EXPORT_GROUP_COMPARATOR/?group_name=GECD_FORCE_PROD&tag_name=REF_FW&...` |
| **Sale** | Fichero `Group Comparator [GECD_FORCE_PROD].csv` |

### 12.1 El enlace (en la plantilla)

```django
<a class="btn btn-sm btn-outline-primary"
   href="{% url 'download_csv_stream_report' 'EXPORT_GROUP_COMPARATOR' %}?{% url_replace request 'ajax' False %}">
    <i class="fas fa-file-csv me-1"></i>Export CSV
</a>
```
- `{% url ... %}` construye la dirección del export común de CSV.
- `{% url_replace request 'ajax' False %}` copia los parámetros de la búsqueda actual (`group_name`, `tag_name`) al enlace.

> **Por qué así:** es **exactamente como están hechos todos los demás export** del proyecto (por ejemplo, el de Audit). Mismo punto de entrada, mismos permisos, mismo formato.

### 12.2 La rama nueva en `download_csv_stream_report`

```python
elif model_name == 'EXPORT_GROUP_COMPARATOR':
    group_name = request.GET.get('group_name', '').strip()
    reference_tag = request.GET.get('tag_name', '').strip()
    filename = f'Group Comparator [{group_name}].csv'

    group_maps_by_tag = load_group_maps_by_tag(group_name) if group_name and reference_tag else {}
    firewalls = []
    if reference_tag in group_maps_by_tag:
        firewalls = compare_group_across_firewalls(group_name, reference_tag, group_maps_by_tag)

    def stream_csv():
        pseudo_buffer = Echo()
        writer = csv.writer(pseudo_buffer)
        yield writer.writerow(GROUP_COMPARATOR_CSV_HEADER)
        for row in build_group_comparator_csv_rows(firewalls):
            yield writer.writerow(row)
```
- `download_csv_stream_report` es **una sola función para todos los CSV**. Elige qué exportar por el `model_name`. Esta rama es la del comparador.
- Calcula el resultado **con las mismas funciones que la pantalla**.
  > **Por qué:** así lo que se descarga **siempre coincide** con lo que se ve. No hay una segunda lógica que pueda desincronizarse.
- `stream_csv()` usa `yield`: va **entregando el fichero línea a línea** en vez de montarlo entero en memoria. Es el patrón de todos los CSV del proyecto.

### 12.3 `build_group_comparator_csv_rows`

```python
GROUP_COMPARATOR_CSV_HEADER = ['FW tag', 'Subgroup', 'Added value', 'Missing value']


def build_group_comparator_csv_rows(firewalls):
    for firewall in firewalls:
        if not firewall['differences']:
            yield [firewall['fw_tag'], 'N/A', '', '']
            continue
        for row in firewall['differences']:
            yield [
                firewall['fw_tag'],
                ' > '.join(row['subgroup_path']) or 'N/A',
                ', '.join(row['added_subgroups'] + row['added_values']),
                ', '.join(row['missing_subgroups'] + row['missing_values']),
            ]
```

| Línea | Qué hace | Por qué |
|---|---|---|
| Firewall sin diferencias → una fila vacía | `FW_2,N/A,,` | El ticket pide listar **todos** los firewalls, también los correctos. |
| Con diferencias → una fila por subgrupo | | Es el formato de la tabla del ticket. |
| `' > '.join(...) or 'N/A'` | Ruta como texto; si está vacía, `N/A`. | |
| `', '.join(subgrupos + valores)` | Junta subgrupos e IPs en una celda separada por comas. | Para el ticket, los dos cuentan como "valores". |

> **Por qué una función aparte:** se puede probar con un test sin base de datos ni petición HTTP.

**Salida real (el fichero):**
```
FW tag,Subgroup,Added value,Missing value
REF_FW,N/A,,
FW_1,N/A,,10.3.4.2
FW_1,Grp 2,10.45.24.25,
FW_2,N/A,,
```
Coincide con la tabla del ticket del apartado 2.

> Pequeña incoherencia que conviene igualar: en pantalla la ruta se separa con ` › ` y en el CSV con ` > `. Con un único separador quedaría más limpio.

---

## 13. Casos especiales, con su salida real

### El grupo no existe
- **Entra:** `group_name='NOPE'`.
- **Pasa:** se lanza **1 consulta**, no encuentra nada y `load_group_maps_by_tag` devuelve `{}`.
- **Sale:** la vista no compara y la pantalla muestra "not found".

### El grupo no existe en el firewall de referencia
- `group_maps_by_tag` tiene otros firewalls, pero no la referencia.
- La comprobación `if reference_tag in group_maps_by_tag` es falsa → mensaje "not found on REF_FW".

### Falta un subgrupo entero y sobra una IP
- **Entra:** la referencia `A` contiene `B` y `C`; el firewall contiene solo `B`, y además una IP `9` de más.
- **Salida real de `diff_group_maps`:**
  ```python
  [{'subgroup_path': (), 'added_values': ['9'], 'missing_values': [],
    'added_subgroups': [], 'missing_subgroups': ['C']}]
  ```
- **Comandos reales:**
  ```
  add to FW_X:A C
  rm from FW_X:A 9
  ```
- Fíjate: primero el `add` y después el `rm`. Tampoco se mira dentro de `C`, porque falta entero.

### Ciclo (A contiene a B y B contiene a A)
- **Entra:** `subgroups = {'A': ['B'], 'B': ['A']}`.
- **Salida real de `build_group_map`:**
  ```python
  {'A': {'members': {'1'}, 'subgroups': {'B'}},
   'B': {'members': {'2'}, 'subgroups': {'A'}}}
  ```
- **No se queda colgado:** cuando vuelve a encontrar `A`, ya está en `group_map` y lo salta. El cargador hace lo mismo con `pending_ids`, y la comparación con `visited`.

### Subgrupo con varios padres
- Se carga una vez (`pending_ids` resta lo ya cargado) y se compara una vez (`visited`), por la ruta más corta (gracias a la cola).

### `content` vacío o `NULL`
- `content or ()` → se trata como grupo sin IPs y no da error.

### Mismo nombre como `ip` y como `service` en un firewall
- Llegan dos filas. `.update()` junta sus valores en el mismo cajón.

---

## 14. Resumen final

| Pieza | Entra | Sale | En una frase | Por qué así |
|---|---|---|---|---|
| Vista `ajax_load_data_group_comparator` | URL con `group_name` y `tag_name` | HTML | Puerta de entrada: lee, llama y pinta. | Mismo permiso que Firewall; HTML en servidor (convención del equipo). |
| `load_group_maps_by_tag` | Nombre del grupo | `{firewall: árbol}` | Lee la BD **piso a piso**, todos los firewalls a la vez. | 2 consultas por piso, independientes del nº de firewalls (sin N+1). |
| `to_hashable` | Un valor | Texto | Hace que cualquier valor quepa en un `set`. | Los `set` solo admiten valores simples. |
| `build_group_map` | Miembros + hijos de un FW | Árbol limpio | Deja el árbol de un firewall con forma uniforme. | Solo lo que cuelga de la raíz; a salvo de ciclos. |
| `compare_group_across_firewalls` | Raíz, referencia, mapas | Lista de resúmenes | Compara todos, cuenta y ordena. | Referencia primero, luego los que fallan, luego los idénticos. |
| `diff_group_maps` | Árbol referencia + árbol FW | Filas con diferencias | **Resta de conjuntos** grupo a grupo. | Exacto por subgrupo; una vez por grupo; ruta más corta. |
| `build_alignment_commands` | Diferencias | Texto con comandos | Traduce a `add to` / `rm from`. | `add` antes que `rm` para no vaciar grupos. |
| Plantillas | `context` | Pantalla | Resumen + detalle desplegable + copiar + CSV. | Compacto; "+N more" para listas largas. |
| `build_group_comparator_csv_rows` + rama CSV | Resultado de la comparación | Fichero CSV | Mismo resultado que en pantalla, en formato del ticket. | Reutiliza la lógica; patrón común de exports. |

**La idea entera en tres líneas:**
1. Se lee de la base de datos el árbol del grupo en **todos** los firewalls, con muy pocas consultas.
2. Se compara cada árbol con el de referencia **restando conjuntos**, subgrupo a subgrupo.
3. Se muestra el resultado, con los comandos para arreglarlo y la opción de descargarlo.
