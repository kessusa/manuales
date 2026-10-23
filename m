# Group Comparator (EMEAPLAYFLOWS-3811): cómo funciona, paso a paso

Esta guía explica el código del **Group Comparator** de la sección Firewall de ProdSecHub (`/rss/firewall`). Está pensada para alguien que programa poco: cada parte lleva para qué sirve, cómo funciona y un ejemplo con datos de entrada y de salida.

---

## 1. ¿Qué problema resuelve?

Un mismo grupo de red (por ejemplo `GECD_FORCE_PROD`) puede estar definido en **muchos firewalls**. Todos deberían tener **exactamente el mismo contenido**: las mismas IPs y los mismos subgrupos. Con el tiempo alguien añade una IP en un firewall y se olvida de los demás, y los grupos se desincronizan.

El Group Comparator:

1. Toma un grupo y un firewall de **referencia**, el que consideramos "correcto".
2. Busca ese grupo en **todos** los firewalls donde existe.
3. Compara cada uno con la referencia, **incluyendo los subgrupos**, y dice qué sobra y qué falta.
4. Genera los **comandos de Playflows** que dejan cada firewall igual que la referencia.

---

## 2. Vocabulario mínimo

| Término | Qué significa aquí |
|---|---|
| **FW tag** | Nombre de un firewall en Playflows, p. ej. `EMEA_FR_PRD_DMZE_MKT-AMM-EU`. |
| **Grupo** | Una lista con nombre de IPs, servicios y/o otros grupos. |
| **Subgrupo** | Un grupo que está **dentro** de otro grupo. Puede haber varios niveles. |
| **Miembro (member)** | Un valor "final" de un grupo: una IP (`10.3.4.1/32`), una red, un servicio… |
| **Referencia** | El FW que eliges en el desplegable **Tag Name**. Todo se compara contra él. |
| **Added value** | Está en **este** FW pero **no** en la referencia: le **sobra**. |
| **Missing value** | Está en la **referencia** pero **no** en este FW: le **falta**. |

### Conceptos de Python que aparecen

| Concepto | Ejemplo | Para qué lo usamos |
|---|---|---|
| **Lista** `[]` | `['a', 'b', 'a']` | Valores en orden; admite repetidos. |
| **Conjunto (set)** `{}` | `{'a', 'b'}` | Valores **sin repetir** y sin orden. Sirve para restar: `{'a','b'} - {'a'}` da `{'b'}`, o sea "lo que está en el primero y no en el segundo". |
| **Diccionario (dict)** | `{'clave': 'valor'}` | Guarda cosas por nombre, p. ej. `{'FW_1': ...}`. |
| **Tupla** `()` | `('L1', 'L2')` | Como una lista pero que no se puede modificar. La usamos para guardar rutas. |
| **defaultdict** | `defaultdict(set)` | Un diccionario que crea la entrada vacía solo si no existe. Nos ahorra escribir "si no existe, créala". |
| **deque** | `deque([...])` | Una cola: entra por un lado y sale por el otro (el primero en llegar es el primero en salir). |

> La **resta de conjuntos** es el corazón de la comparación:
> `lo_que_tiene_el_FW - lo_que_tiene_la_referencia` = **lo que sobra (Added)**
> `lo_que_tiene_la_referencia - lo_que_tiene_el_FW` = **lo que falta (Missing)**

---

## 3. El ejemplo que usaremos en toda la guía

Es el ejemplo del ticket. El grupo `GECD_FORCE_PROD` tiene dos subgrupos, `Grp1` y `Grp 2`, y existe en tres firewalls:

```
REF_FW (referencia)               FW_1                              FW_2
GECD_FORCE_PROD                   GECD_FORCE_PROD                   (idéntico a REF_FW)
├─ 10.3.4.1                       ├─ 10.3.4.1
├─ 10.3.4.2                       │                  ← falta 10.3.4.2
├─ Grp1                           ├─ Grp1
│  └─ 10.34.55.64                 │  └─ 10.34.55.64
└─ Grp 2                          └─ Grp 2
   └─ 10.45.24.23                    ├─ 10.45.24.23
                                     └─ 10.45.24.25  ← sobra 10.45.24.25
```

Resultado esperado, como lo pidió Aurelien:

| FW Tag | Subgroup | Added value | Missing value |
|---|---|---|---|
| REF_FW | | | |
| FW_1 | N/A | | 10.3.4.2 |
| FW_1 | Grp 2 | 10.45.24.25 | |

---

## 4. Vista general: los ficheros y el recorrido de una petición

| Fichero | Qué contiene |
|---|---|
| `rss/views.py` (sección Firewall) | Toda la lógica: carga de datos, comparación, comandos y la vista. |
| `templates/tools/firewall_components/group_comparator_component.html` | La tabla de resultados que ve el usuario. |
| `templates/tools/firewall_components/group_comparator_values.html` | Trozo reutilizable que pinta una lista de valores (con el "+N more"). |
| `rss/test_group_comparator.py` | Los tests automáticos. |

Qué pasa cuando pulsas **Apply**:

```
Navegador (Group Name + Tag Name)
   │  GET /rss/ajax_load_data_group_comparator/?group_name=GECD_FORCE_PROD&tag_name=REF_FW
   ▼
ajax_load_data_group_comparator            (la vista: recibe la petición)
   │
   ├─► load_group_maps_by_tag()            (1. lee la BD y monta el árbol de cada FW)
   │       └─► build_group_map()           (   ordena el árbol de un FW)
   │
   ├─► compare_group_across_firewalls()    (2. compara cada FW con la referencia)
   │       ├─► diff_group_maps()           (   diferencias grupo a grupo)
   │       └─► build_alignment_commands()  (   comandos de Playflows para igualar)
   │
   └─► render(...component.html)           (3. devuelve el HTML de la tabla)
   ▼
Navegador (muestra la tabla dentro de la pestaña)
```

Las funciones que **no** tocan la base de datos (`build_group_map`, `diff_group_maps`, `build_alignment_commands` y `compare_group_across_firewalls`) son "puras": con la misma entrada dan siempre la misma salida. Por eso se pueden probar con tests sin base de datos.

---

## 5. De dónde salen los datos: las tablas del Group Lookup (EMEAPLAYFLOWS-3637)

No consultamos Playflows en directo. Leemos las tablas que rellena el comando `playflows_groups_update`. Esto hace que la respuesta sea rápida, pero los datos son los de **la última sincronización**.

**`pf_tag_group`** (modelo `PlayflowsTagGroup`): un grupo dentro de un firewall.

| Campo | Ejemplo | Significado |
|---|---|---|
| `id` | `101` | Identificador único de la fila. |
| `tag` | → `REF_FW` | Firewall al que pertenece (enlace a `PlayflowsTag`). |
| `name` | `GECD_FORCE_PROD` | Nombre del grupo. |
| `type` | `ip` | `ip`, `service` o `unknown`. |
| `content` | `["10.3.4.1", "10.3.4.2", "Grp1", "Grp 2"]` | Contenido directo del grupo. |
| `children` | → `Grp1`, `Grp 2` | Sus subgrupos (relación muchos-a-muchos). |

**`pf_tag_group_children`**: la tabla intermedia de `children`. Cada fila dice "el grupo X contiene al grupo Y":

| from_playflowstaggroup_id (padre) | to_playflowstaggroup_id (hijo) |
|---|---|
| 101 (`GECD_FORCE_PROD` en REF_FW) | 102 (`Grp1` en REF_FW) |
| 101 (`GECD_FORCE_PROD` en REF_FW) | 103 (`Grp 2` en REF_FW) |

---

## 6. El código, función a función

### 6.1 `to_hashable(value)`

**Para qué sirve:** los conjuntos de Python solo aceptan valores "simples" (textos, números…), no diccionarios. Si en `content` hay algún elemento que es un diccionario, esta función lo convierte en texto para poder compararlo.

```python
def to_hashable(value):
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
```

- Si ya es texto, lo devuelve tal cual.
- Si no, lo convierte a texto JSON con las claves **ordenadas**. Así `{'b':1,'a':2}` y `{'a':2,'b':1}` dan el mismo texto y cuentan como iguales.

| Entrada | Salida |
|---|---|
| `'10.3.4.1'` | `'10.3.4.1'` |
| `{'b': 1, 'a': 2}` | `'{"a": 2, "b": 1}'` |

---

### 6.2 `load_group_maps_by_tag(root_group)`: leer la base de datos

**Para qué sirve:** dado el nombre de un grupo, encuentra **todos los firewalls** donde existe y, para cada uno, carga ese grupo **y todos sus subgrupos**, en todos los niveles.

**Entrada:** `'GECD_FORCE_PROD'`

**Salida:** un diccionario con un "mapa de grupos" por firewall:

```python
{
    'REF_FW': { ...árbol de GECD_FORCE_PROD en REF_FW... },
    'FW_1':   { ...árbol de GECD_FORCE_PROD en FW_1... },
    'FW_2':   { ...árbol de GECD_FORCE_PROD en FW_2... },
}
```

#### Cómo funciona: por niveles

Imagina el árbol del grupo como pisos de un edificio: el grupo raíz es el piso 0, sus subgrupos el piso 1, los subgrupos de estos el piso 2… La función baja **piso a piso** y en cada piso trae **todos los firewalls a la vez**.

```python
level_queryset = PlayflowsTagGroup.objects.filter(name=root_group)
```
**Piso 0:** pide a la BD todas las filas de `pf_tag_group` cuyo nombre sea `GECD_FORCE_PROD`, en cualquier firewall.

```python
while True:
    level_ids = []
    for group_id, tag_name, name, content in level_queryset.values_list('id', 'tag__tag_name', 'name', 'content'):
        group_index[group_id] = (tag_name, name)
        members_by_tag[tag_name][name].update(to_hashable(item) for item in content or ())
        level_ids.append(group_id)
```
Para cada grupo encontrado en este piso:
- `group_index` apunta qué es cada `id`: `101 → ('REF_FW', 'GECD_FORCE_PROD')`. Más tarde lo usamos para traducir ids a nombres.
- `members_by_tag` guarda su contenido: `members_by_tag['REF_FW']['GECD_FORCE_PROD'] = {'10.3.4.1', '10.3.4.2', 'Grp1', 'Grp 2'}`.
- `content or ()` evita un error si `content` está vacío (`None`).
- Se usa `.update(...)` en vez de `=` porque un mismo nombre puede existir dos veces en un FW (una como `ip` y otra como `service`), y así se juntan.

```python
    if not level_ids:
        break
```
Si en este piso no hay nada (por ejemplo, el grupo no existe en ningún FW), terminamos.

```python
    child_ids = set()
    edges = PlayflowsTagGroup.children.through.objects.filter(
        from_playflowstaggroup_id__in=level_ids
    ).values_list('from_playflowstaggroup_id', 'to_playflowstaggroup_id')
    for parent_id, child_id in edges:
        child_ids.add(child_id)
        subgroups_by_tag[group_index[parent_id][0]][group_index[parent_id][1]].add(child_id)
```
Pide a `pf_tag_group_children` **todos los hijos** de los grupos de este piso, en una sola consulta. Cada fila `(padre, hijo)` se apunta en `subgroups_by_tag`, por ejemplo `subgroups_by_tag['REF_FW']['GECD_FORCE_PROD'] = {102, 103}`.

```python
    pending_ids = child_ids - group_index.keys()
    if not pending_ids:
        break
    level_queryset = PlayflowsTagGroup.objects.filter(id__in=pending_ids)
```
- `pending_ids` son los hijos que **todavía no hemos cargado**. Restando los ya vistos evitamos bucles infinitos si un grupo se contiene a sí mismo indirectamente.
- Si no queda ninguno, hemos llegado al fondo del árbol.
- Si quedan, el siguiente piso es "esos ids", y vuelta a empezar.

#### Al final: pasar de ids a nombres

```python
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
```
Para cada firewall:
1. Cambia los ids de los hijos por sus nombres: `{102, 103}` pasa a ser `{'Grp1', 'Grp 2'}`.
2. **Quita los subgrupos de la lista de miembros.** En `content`, `Grp1` y `Grp 2` aparecen mezclados con las IPs, y no queremos contarlos dos veces. Queda `{'10.3.4.1', '10.3.4.2'}`.
3. Llama a `build_group_map` para dejarlo ordenado.

#### ¿Por qué es eficiente?

Hace **2 consultas por piso**, una de grupos y otra de relaciones, da igual que el grupo esté en 3 firewalls o en 300. En el ejemplo, con 2 pisos, son 4 consultas en total. Lo contrario, una consulta por grupo y por firewall, es el famoso problema "N+1" y sería muchísimo más lento.

---

### 6.3 `build_group_map(root_group, members_by_group, subgroups_by_group)`: ordenar el árbol de un FW

**Para qué sirve:** toma los miembros y los subgrupos de un firewall y construye un diccionario limpio con **solo los grupos que cuelgan del grupo raíz**.

**Entrada** (para REF_FW):
```python
root_group = 'GECD_FORCE_PROD'
members_by_group = {
    'GECD_FORCE_PROD': ['10.3.4.1', '10.3.4.2'],
    'Grp1': ['10.34.55.64'],
    'Grp 2': ['10.45.24.23'],
}
subgroups_by_group = {'GECD_FORCE_PROD': ['Grp1', 'Grp 2']}
```

**Salida:**
```python
{
    'GECD_FORCE_PROD': {'members': {'10.3.4.1', '10.3.4.2'}, 'subgroups': {'Grp1', 'Grp 2'}},
    'Grp1':            {'members': {'10.34.55.64'},          'subgroups': set()},
    'Grp 2':           {'members': {'10.45.24.23'},          'subgroups': set()},
}
```

**Cómo funciona:**
```python
group_map = {}
pending = [root_group]                     # lista de grupos por visitar; empezamos por la raíz
while pending:
    group_name = pending.pop()             # saca uno
    if group_name in group_map:            # si ya lo visitamos, lo saltamos (evita bucles)
        continue
    subgroups = set(subgroups_by_group.get(group_name, ()))
    group_map[group_name] = {
        'members': set(members_by_group.get(group_name, ())),
        'subgroups': subgroups,
    }
    pending.extend(subgroups - group_map.keys())   # apunta sus hijos para visitarlos después
return group_map
```
`.get(group_name, ())` significa "dame lo que haya y, si no hay nada, una lista vacía". Así un grupo sin IPs o sin hijos no da error.

---

### 6.4 `diff_group_maps(root_group, reference_map, target_map)`: comparar un FW con la referencia

**Para qué sirve:** recorre el árbol grupo a grupo y, en cada uno, calcula qué sobra y qué falta. Devuelve **una fila por cada grupo que tenga alguna diferencia**.

**Entrada:** el mapa de REF_FW (la referencia) y el mapa de FW_1.

**Salida:**
```python
[
    {'subgroup_path': (),         'added_values': [],              'missing_values': ['10.3.4.2'],
     'added_subgroups': [],       'missing_subgroups': []},
    {'subgroup_path': ('Grp 2',), 'added_values': ['10.45.24.25'], 'missing_values': [],
     'added_subgroups': [],       'missing_subgroups': []},
]
```

Qué significa cada campo:

| Campo | Significado |
|---|---|
| `subgroup_path` | Ruta desde el grupo raíz hasta el grupo con diferencias. `()` vacía = el propio grupo raíz (en pantalla, **N/A**). `('L1', 'L2')` = `L2`, que está dentro de `L1`. |
| `added_values` | IPs o servicios que **sobran** en este FW. |
| `missing_values` | IPs o servicios que **faltan** en este FW. |
| `added_subgroups` | Subgrupos enteros que **sobran**. |
| `missing_subgroups` | Subgrupos enteros que **faltan**. |

**Cómo funciona:**
```python
rows = []
visited = set()
pending = deque([(root_group, ())])        # cola: (grupo, ruta hasta él)
while pending:
    group_name, subgroup_path = pending.popleft()   # saca el primero de la cola
    if group_name in visited:
        continue
    visited.add(group_name)
```
Usa una **cola** (`deque`): primero el grupo raíz, luego todos sus hijos, luego los nietos… Recorrerlo así ("en anchura") garantiza que, si un subgrupo cuelga de varios padres, lo comparamos **una sola vez** y con la ruta más corta.

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
Aquí está la **resta de conjuntos** del apartado 2. Con el grupo raíz:
- FW_1 tiene `{'10.3.4.1'}` y la referencia `{'10.3.4.1', '10.3.4.2'}`.
- Sobra: `{'10.3.4.1'} - {'10.3.4.1','10.3.4.2'}` → `{}` (nada).
- Falta: `{'10.3.4.1','10.3.4.2'} - {'10.3.4.1'}` → `{'10.3.4.2'}`.

`sorted(...)` convierte el resultado en una lista ordenada, para que siempre salga en el mismo orden.

```python
    if row['added_values'] or row['missing_values'] or row['added_subgroups'] or row['missing_subgroups']:
        rows.append(row)
```
Solo guarda la fila si hay **alguna** diferencia. `Grp1` es igual en los dos FW y no genera fila.

```python
    for child_name in sorted(reference['subgroups'] & target['subgroups']):
        pending.append((child_name, subgroup_path + (child_name,)))
return rows
```
`&` es la **intersección**: los subgrupos que existen **en los dos** FW. Solo bajamos a comparar esos. Si un subgrupo falta entero, ya se ha apuntado en `missing_subgroups` del padre y no tiene sentido mirar dentro. La ruta crece añadiendo el nombre del hijo: `()` → `('Grp 2',)`.

---

### 6.5 `build_alignment_commands(fw_tag, root_group, differences)`: los comandos para igualar

**Para qué sirve:** convierte las diferencias de un FW en **comandos de Playflows** que lo dejan igual que la referencia. Es lo que copia el botón 📋.

**Entrada:** `'FW_1'`, `'GECD_FORCE_PROD'` y las dos filas del apartado 6.4.

**Salida** (un texto con un comando por línea):
```
add to FW_1:GECD_FORCE_PROD 10.3.4.2
rm from FW_1:Grp 2 10.45.24.25
```

**Reglas que sigue**, según la guía de comandos de Playflows (sintaxis larga con POLICYTAGNAME):

| Situación | Comando |
|---|---|
| Algo **falta** (Missing) | `add to <FW>:<GRUPO> valor1 valor2 ...` |
| Algo **sobra** (Added) | `rm from <FW>:<GRUPO> valor1 valor2 ...` |

```python
for row in differences:
    group_name = row['subgroup_path'][-1] if row['subgroup_path'] else root_group
    target_group = f'{fw_tag}:{group_name}'
```
- El grupo que hay que tocar es el **último** de la ruta (`[-1]`). Si la ruta está vacía, es el grupo raíz.
- `f'{fw_tag}:{group_name}'` construye el texto `FW_1:Grp 2`.

```python
    for values in (row['missing_subgroups'], row['missing_values']):
        if values:
            add_commands.append(f'add to {target_group} {" ".join(values)}')
    for values in (row['added_subgroups'], row['added_values']):
        if values:
            rm_commands.append(f'rm from {target_group} {" ".join(values)}')
return '\n'.join(add_commands + rm_commands)
```
- `" ".join(values)` junta la lista separando con espacios: `['10.0.0.1', '10.0.0.2']` → `'10.0.0.1 10.0.0.2'`.
- Subgrupos e IPs van en **comandos separados**, como en la guía.
- **Primero todos los `add` y después los `rm`.** Así ningún grupo se queda vacío a mitad del proceso.
- `'\n'.join(...)` pone cada comando en una línea.

Ejemplo más completo:

| Entrada (diferencias) | Salida |
|---|---|
| Raíz: sobra `10.0.0.9`, faltan `10.0.0.1 10.0.0.2` y el subgrupo `GRP_A` | `add to FW_1:GECD_FORCE_PROD GRP_A` |
| `L1 › L2`: sobra el subgrupo `GRP_B`, falta `10.0.0.3` | `add to FW_1:GECD_FORCE_PROD 10.0.0.1 10.0.0.2` |
| | `add to FW_1:L2 10.0.0.3` |
| | `rm from FW_1:GECD_FORCE_PROD 10.0.0.9` |
| | `rm from FW_1:L2 GRP_B` |

> ⚠️ **Antes de usarlos en producción**, prueba en un FW de DEV: (1) que `FW:GRUPO` también funcione para meter o quitar subgrupos; (2) que Playflows acepte las IPs con `/32`; (3) que, si falta un subgrupo entero, ese subgrupo ya exista en el FW destino (si no, hay que crearlo antes).

---

### 6.6 `compare_group_across_firewalls(root_group, reference_tag, group_maps_by_tag)`: el resumen de todos los FW

**Para qué sirve:** junta todo. Compara **cada** firewall con la referencia y prepara la lista que se pinta en pantalla.

**Entrada:** `'GECD_FORCE_PROD'`, `'REF_FW'` y los mapas de REF_FW, FW_1 y FW_2.

**Salida:**
```python
[
    {'fw_tag': 'REF_FW', 'is_reference': True,  'differences': [],
     'added_count': 0, 'missing_count': 0, 'alignment_commands': ''},

    {'fw_tag': 'FW_1',   'is_reference': False, 'differences': [ ...las 2 filas del 6.4... ],
     'added_count': 1, 'missing_count': 1,
     'alignment_commands': 'add to FW_1:GECD_FORCE_PROD 10.3.4.2\nrm from FW_1:Grp 2 10.45.24.25'},

    {'fw_tag': 'FW_2',   'is_reference': False, 'differences': [],
     'added_count': 0, 'missing_count': 0, 'alignment_commands': ''},
]
```

**Cómo funciona:**
```python
reference_map = group_maps_by_tag[reference_tag]
firewalls = []
for fw_tag in sorted(group_maps_by_tag):          # recorre los FW por orden alfabético
    if fw_tag == reference_tag:                   # la referencia no se compara consigo misma
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
- `added_count` y `missing_count` son los **números del resumen**: cuántos valores sobran y faltan en total, sumando todas las filas.

```python
firewalls.sort(key=lambda firewall: not firewall['differences'])
```
Ordena para que los FW **con diferencias salgan primero** y los idénticos al final. Truco: `not []` es `True` y `not [algo]` es `False`. Como `False` va antes que `True` al ordenar, los que tienen diferencias quedan arriba. El orden alfabético se mantiene dentro de cada bloque.

```python
reference = {'fw_tag': reference_tag, 'is_reference': True, ...}
return [reference] + firewalls
```
La referencia se pone siempre la **primera**.

---

### 6.7 `ajax_load_data_group_comparator(request)`: la vista

**Para qué sirve:** es la "puerta de entrada". Django la ejecuta cuando el navegador pulsa **Apply**. Lee lo que ha escrito el usuario, llama a las funciones anteriores y devuelve el HTML.

```python
@login_required                                  # solo usuarios con sesión iniciada
@user_passes_test(user_can_change_firewall)      # y con permiso sobre firewall
def ajax_load_data_group_comparator(request):
    group_name = request.GET.get('group_name', '').strip()
    reference_tag = request.GET.get('tag_name', '').strip()
```
- Lee los dos parámetros de la URL: `?group_name=GECD_FORCE_PROD&tag_name=REF_FW`.
- `.strip()` quita espacios sobrantes (en una prueba llegó `GECD_FORCE_PROD ` con un espacio al final).

```python
    group_maps_by_tag = load_group_maps_by_tag(group_name) if group_name and reference_tag else {}
    firewalls = []
    if reference_tag in group_maps_by_tag:
        firewalls = compare_group_across_firewalls(group_name, reference_tag, group_maps_by_tag)
```
- Si falta algún dato, ni consulta la BD.
- Si el grupo **no existe en el FW de referencia**, `firewalls` queda vacío y la pantalla mostrará "Group X was not found on Y".

```python
    context = {
        'firewalls': firewalls,
        'differing_count': sum(1 for firewall in firewalls if firewall['differences']),
        'group_name': group_name,
        'reference_tag': reference_tag,
    }
    return render(request, 'tools/firewall_components/group_comparator_component.html', context)
```
`context` es la "bolsa" de datos que se pasa a la plantilla HTML. `differing_count` cuenta cuántos FW tienen diferencias, para la frase de arriba.

**Ejemplo de entrada y salida:**

| | |
|---|---|
| **Entrada (URL)** | `GET /rss/ajax_load_data_group_comparator/?group_name=GECD_FORCE_PROD&tag_name=REF_FW` |
| **Salida (context)** | `firewalls` = la lista del 6.6, `differing_count` = `1`, `group_name` = `'GECD_FORCE_PROD'`, `reference_tag` = `'REF_FW'` |
| **Salida (pantalla)** | La tabla HTML del apartado 7. |

---

## 7. Las plantillas HTML: lo que ve el usuario

### 7.1 `group_comparator_component.html`

Con el ejemplo, la pantalla queda así:

```
GECD_FORCE_PROD found on 3 firewalls · 1 differs from REF_FW

┌──────────────────┬─────────────────┬───────┬─────────┐
│ FW Tag           │ Status          │ Added │ Missing │
├──────────────────┼─────────────────┼───────┼─────────┤
│ REF_FW           │ [Reference]     │   -   │    -    │
│ ˅ FW_1  [📋]      │ [2 groups differ]│   1   │    1    │  ← clic: se despliega
│   ┌───────────────────────────────────────────────┐  │
│   │ Alignment commands                            │  │
│   │ add to FW_1:GECD_FORCE_PROD 10.3.4.2          │  │
│   │ rm from FW_1:Grp 2 10.45.24.25                │  │
│   ├──────────┬───────────────┬────────────────────┤  │
│   │ Subgroup │ Added value   │ Missing value      │  │
│   │ N/A      │               │ 10.3.4.2           │  │
│   │ Grp 2    │ 10.45.24.25   │                    │  │
│   └──────────┴───────────────┴────────────────────┘  │
│ FW_2             │ [Identical]     │   -   │    -    │
└──────────────────┴─────────────────┴───────┴─────────┘
```

Partes importantes de la plantilla:

| Trozo | Qué hace |
|---|---|
| `{% if firewalls %} ... {% else %}` | Si hay resultados pinta la tabla; si no, el mensaje "not found" o "No data". |
| `{{ firewalls\|length }}` y `pluralize` | Cuenta los FW y pone la "s" del plural ("1 firewall" / "3 firewalls"). |
| `{% for firewall in firewalls %}` | Una fila por FW. |
| `{% if firewall.differences %}` | Si tiene diferencias: fila pulsable + fila oculta con el detalle. Si no: badge **Reference** o **Identical**. |
| `data-bs-toggle="collapse" data-bs-target="#group-comparator-fw-N"` | Bootstrap 5: al hacer clic en la fila, muestra u oculta la fila con ese `id`. `forloop.counter` (1, 2, 3…) hace que cada `id` sea único. |
| `{{ row.subgroup_path\|join:" › "\|default:"N/A" }}` | Convierte la ruta `('L1','L2')` en `L1 › L2`. Si está vacía, escribe **N/A**. |
| `<textarea ... readonly>{{ firewall.alignment_commands }}</textarea>` | Muestra los comandos para revisarlos. |
| Botón `group-comparator-copy` | El botón 📋 que copia los comandos. |

### 7.2 `group_comparator_values.html`

Pinta una celda de valores, usada en *Added value* y en *Missing value*:
1. Primero los **subgrupos** enteros, con un badge **Group** para no confundirlos con IPs.
2. Luego los **10 primeros** valores (`slice:":10"`).
3. Si hay más de 10, un desplegable **"+N more"** con el resto (`<details>`, nativo del navegador, sin JavaScript).

| Entrada | Salida |
|---|---|
| 15 IPs | Las 10 primeras + `+5 more` (al pulsarlo aparecen las otras 5). |
| subgrupo `Grp 2` | `[Group] Grp 2` |

### 7.3 El script del botón copiar

Está al final de `group_comparator_component.html`:

```javascript
$(document).off('click.groupComparatorCopy').on('click.groupComparatorCopy', '.group-comparator-copy', function (event) {
    event.stopPropagation();
    ...
});
```
- `.off(...).on(...)`: cada vez que pulsas Apply el HTML se vuelve a cargar. Primero se quita el manejador anterior para no copiar dos veces.
- `event.stopPropagation()`: el botón está **dentro** de la fila pulsable. Sin esto, al copiar también se abriría o cerraría el detalle.
- `navigator.clipboard.writeText(...)`: la forma moderna de copiar. Solo funciona en HTTPS o en `localhost`.
- El bloque alternativo (`execCommand('copy')` con un `<textarea>` temporal) cubre el caso de que el hub vaya por HTTP sin TLS.
- `show_copied()`: cambia el icono 📋 por ✔ durante 1,5 segundos para confirmar la copia.

---

## 8. Casos especiales que el código ya contempla

| Caso | Qué pasa |
|---|---|
| El grupo **no existe** en el FW de referencia | Mensaje "Group X was not found on Y". |
| Un FW es **idéntico** a la referencia | Sale con el badge **Identical**, al final de la lista. |
| **Falta un subgrupo entero** | Sale como un valor con badge **Group** en el padre y no se mira dentro. Cuenta como 1 en los totales. |
| Un subgrupo cuelga de **varios padres** | Se compara una sola vez (con la ruta más corta). |
| Un grupo se contiene a sí mismo (**ciclo**) | No se queda colgado: los grupos ya visitados se saltan. |
| `content` vacío o `NULL` | Se trata como un grupo sin miembros. |
| Mismo nombre como `ip` y como `service` en un FW | Se juntan bajo ese nombre. |
| Listas muy largas | 10 visibles + "+N more". |

---

## 9. Los tests (`rss/test_group_comparator.py`)

Un test es un programa que comprueba automáticamente que el código hace lo que debe. Se ejecutan con:

```bash
python manage.py test rss.test_group_comparator
```

| Grupo de tests | Qué comprueban | ¿Usa BD? |
|---|---|---|
| `GroupComparatorLogicTests` | El ejemplo del ticket, el orden (diferentes antes que idénticos), subgrupo que falta, rutas anidadas, ciclos y subgrupos compartidos. | No |
| `GroupComparatorAlignmentCommandTests` | Que los comandos salen bien formados, `add` antes que `rm`, y vacíos si no hay diferencias. | No |
| `GroupComparatorTemplateTests` | Que la pantalla muestra el resumen, los badges, `N/A`, el "+N more", el badge "Group", el botón de copiar y el mensaje "not found". | No |
| `GroupComparatorDatabaseTests` | Crea el ejemplo del ticket en `pf_tag_group` y comprueba la carga real, que **solo hace 4 consultas** y que un grupo inexistente devuelve vacío. | Sí (BD de test temporal) |

Si todo va bien, la salida termina en `OK`. Si algo falla, el test dice qué esperaba y qué obtuvo.

> Los tests crean `PlayflowsTag` solo con `tag_name`. Si en el modelo real hay más campos obligatorios (por ejemplo `region`), hay que añadirlos en `create_tree` y `setUpTestData`.

---

## 10. Resumen en una frase por pieza

| Pieza | En una frase |
|---|---|
| `to_hashable` | Convierte cualquier valor en algo que se pueda meter en un conjunto. |
| `load_group_maps_by_tag` | Lee de la BD el grupo y todos sus subgrupos, en todos los FW a la vez, piso a piso. |
| `build_group_map` | Deja ordenado el árbol de un FW: cada grupo con sus miembros y sus subgrupos. |
| `diff_group_maps` | Compara un FW con la referencia grupo a grupo, restando conjuntos. |
| `build_alignment_commands` | Traduce las diferencias a comandos `add to` / `rm from` de Playflows. |
| `compare_group_across_firewalls` | Hace lo anterior para todos los FW y prepara el resumen ordenado. |
| `ajax_load_data_group_comparator` | Recibe el clic en Apply, llama a todo y devuelve la tabla HTML. |
| `group_comparator_component.html` | Pinta el resumen, el detalle desplegable y el botón de copiar. |
| `group_comparator_values.html` | Pinta una lista de valores con el "+N more". |
