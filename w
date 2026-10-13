# EMEAPLAYFLOWS-3637 — Global Search "Group lookup"

## 1. Goal

Add a **Group lookup** search type to Global Search. Given a playflows group name, it shows the
group's own IPs and, recursively, every nested subgroup with its own IPs (N levels).

- Target tag: `APAC_SG_PRD_DMZA_CORPWM` (region `apac`). EMEA tags were used only for testing.
- Access: restricted to users holding the permission `rss.view_groups_lookup`
  (`apac_netsec`, plus `admin` and `emea_netsec_mgmt`, which receive every permission).

---

## 2. Why the first implementation was replaced

| Problem | Effect | Fix |
|---|---|---|
| `get_groups_with_content` flattened nested groups into the parent's `content` | The hierarchy was lost before reaching the DB; no view could rebuild the tree | API returns `ips`, `services` and `subgroups` as separate keys |
| Subgroups resolved by **name matching** at read time | Not deterministic: the same name exists as address and service group, and the type changes between syncs | Explicit parent → child relation in the DB |
| First design: `PlayflowsTagGroupLink` + `PlayflowsTagGroupRelation` (`pf_tag_group_relation`) | Review (Oumaima): too many intermediate models, groups not scoped per tag | `tag` FK + `children` M2M on `PlayflowsTagGroup` |
| Reviewer proposal `parent = ForeignKey('self')` | Playflows data is a **DAG**, not a tree: some groups have 21+ parents (proved with SQL) | `ManyToManyField('self', symmetrical=False)` |
| DEV DB restored from a dump without PKs, uniques or sequences | Duplicated ids, `MultipleObjectsReturned`, inserts colliding with existing ids | DB remediation (section 8), needed per environment |

---

## 3. Changes by file

### 3.1 `API_cnx/playflows.py` — `get_groups_with_content`

Returns one entry per group with **direct** members only (no recursion, no flattening):

```python
{
    'NS-PVR_INET_MGMT_NETWORKS': {'type': 'ip', 'ips': [], 'services': [], 'subgroups': ['NS-PVR_FR_MGMT', 'NS-PVR_UK_MGMT']},
    'NS-PVR_FR_MGMT':            {'type': 'ip', 'ips': ['10.10.1.0/24'], 'services': [], 'subgroups': []},
    'NS-PVR_UK_MGMT':            {'type': 'ip', 'ips': ['10.20.1.10/32', '10.20.1.11/32'], 'services': [], 'subgroups': []},
}
```

A pure container (only subgroups, no IPs) is typed `ip`, not `service`. This was the cause of a
parent group being stored as `service` and disappearing from the lookup.

### 3.2 `rss/models.py` — `PlayflowsTagGroup`

```python
class PlayflowsTagGroup(models.Model):
    tag = models.ForeignKey('PlayflowsTag', on_delete=models.CASCADE, null=True, blank=True,
                            related_name='groups')
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50)
    content = models.JSONField(default=list)            # direct members only
    resolved_content = models.JSONField(default=list)   # direct + nested members (flattened at sync time)
    children = models.ManyToManyField('self', symmetrical=False, related_name='parents', blank=True)

    class Meta:
        db_table = 'pf_tag_group'
        constraints = [
            models.UniqueConstraint(fields=['tag', 'name', 'type'], name='uniq_pf_tag_group_tag_name_type'),
        ]
```

- **Removed:** `PlayflowsTagGroupLink` (`pf_tag_group_link`) and `PlayflowsTagGroupRelation`.
- `tag` is `null=True` so the `AddField` does not violate the FK on the ~96k existing rows.
- `resolved_content` keeps consumers of the flattened list (the playflows tag modal) working with
  zero extra queries.

### 3.3 Migrations (`rss`)

- One new migration: FK `tag`, M2M `children`, `UniqueConstraint`, `resolved_content`.
- The DEV chain was broken (a `0002_code_devqualification_*` referenced by `master`'s `0003` was
  never committed). Already-present operations were **faked**, genuinely pending ones applied.
- Read-only helper `utils/db_scripts/check_pending_migration.py` classifies each operation of the
  leaf migration as `ALREADY IN DB` / `PENDING` / `CHECK MANUALLY` before faking anything.

### 3.4 `rss/management/commands/playflows_groups_update.py`

Usage:

```
python manage.py playflows_groups_update --tag-name <TAG> --region <region>
python manage.py playflows_groups_update --all --region <region>
```

Per tag, inside one `transaction.atomic()`:

1. Upsert groups indexed by `(name, type)` with `bulk_create` / `bulk_update(batch_size=500)`;
   rows are only updated if `content` or `resolved_content` changed (**idempotent**).
2. Delete stale groups (no longer returned by playflows for that tag).
3. Rebuild the `children` edges of the tag from scratch with one `bulk_create(ignore_conflicts=True)`.
4. `resolved_content` computed in memory by `flatten_group_members` (cycle guard + per-tag cache,
   so a subgroup shared by 21 parents is resolved once). No DB queries.

Other fixes:

- `if not result` guard after the API call (`'NoneType' object has no attribute 'items'`).
- `--tag-name` uses `get_or_create(tag_name=..., region=...)`.
- Every run is logged in `TaskUpdateDate` (`task_date`): `running` → `success` / `failed`,
  with one message per tag (`info` / `warning` / `error`). Written outside the per-tag
  transactions so a rollback never erases the execution record.
- Debug `print`/`stdout.write` removed.

Why flatten at sync time and not in the view: the sync runs scheduled with nobody waiting; the
alternative (resolving in the modal) cost 2 extra queries and up to 100–200 ms on every open,
pagination and filter in large tags. Only cost: some duplicated IPs in `pf_tag_group` (a few MB).

### 3.5 `bookmark/views.py` — `group_lookup_search` (Global Search section)

```python
GROUP_LOOKUP_TARGET_TAG = 'APAC_SG_PRD_DMZA_CORPWM'
GROUP_LOOKUP_TARGET_REGION = 'apac'
GROUP_LOOKUP_TEMPLATE = 'search_components/group_lookup_component.html'


@login_required
@user_passes_test(user_can_view_global_search)
def group_lookup_search(request):
    """Render a playflows group of the target tag with its nested subgroups and IPs."""
    if not user_can_view_group_lookup(request.user):
        return render(request, GROUP_LOOKUP_TEMPLATE, {
            'error': 'Group lookup is only available for APAC users',
        }, status=403)

    group_name = request.GET.get('q_search', '').strip()
    if not group_name:
        return render(request, GROUP_LOOKUP_TEMPLATE, {'error': 'No search term provided'})

    root_group = get_group_lookup_root(group_name)
    if root_group is None:
        return render(request, GROUP_LOOKUP_TEMPLATE, {
            'error': f'Group "{group_name}" not found or not linked to {GROUP_LOOKUP_TARGET_TAG}',
        })

    hierarchy = build_group_node(root_group, load_group_children_map(root_group.id))
    return render(request, GROUP_LOOKUP_TEMPLATE, {'hierarchy': hierarchy})
```

- `get_group_lookup_root`: one query, root by name **inside the target tag**, `type='ip'`.
- `load_group_children_map`: BFS over the `children` through table, **one query per level**
  (not per group), with depth limit and visited set → no N+1, safe with cycles.
- `build_group_node`: builds the tree **in memory** from that map; a group reached twice in the
  same branch is not expanded again (cycle guard).
- Permission is checked inside the view and returns a rendered **403** instead of
  `@user_passes_test`, which would answer the AJAX call with a 302 to the login page.
- The view is stateless; query count depends on tree depth, not on the number of groups.

### 3.6 `bookmark/urls.py`

Inside the Global Search block, same style as the other AJAX searches (no trailing slash):

```python
path('group_lookup_search', views.group_lookup_search, name='group_lookup_search'),
```

### 3.7 Permissions

- `bookmark/permissions.py`

  ```python
  def user_can_view_group_lookup(user):
      return user.has_perm('rss.view_groups_lookup')
  ```

  The first version used `has_module_perms(...)`, which expects an **app label**, so it always
  returned `False` for non-superusers (302 for APAC users). Codename is `view_groups_lookup`
  (plural), not `view_group_lookup`.

- Permission created **manually from the UI** (`/accounts/new-permission/`), as the rest of the
  project's permissions: Name `Can use Group Lookup`, Codename `view_groups_lookup`,
  Content Type `rss | playflowstaggroup`.

- `rss/management/commands/ldap_user.py` (review comment "missing ldap_user config"): added inside
  the shared `amer_netsec` / `apac_netsec` branch, after the existing loop, so only APAC gets it
  and the validated base list is untouched:

  ```python
  if team == 'apac_netsec':
      team_obj.permissions.add(*permissions.filter(codename='view_groups_lookup'))
  ```

  A separate `elif team == 'apac_netsec'` was dead code (the previous branch already caught it).

### 3.8 Templates and JS

- `templates/includes/navbar.html`: the option is only rendered with the same criterion as the view.

  ```django
  {% if perms.rss.view_groups_lookup %}
      <option class="dropdown-item" value="group_lookup" data-placeholder="Group lookup.."
              {% if request.GET.type == "group_lookup" %} selected {% endif %}>Group lookup</option>
  {% endif %}
  ```

- `templates/search_components/group_lookup_component.html` (new): error message or the tree.
- `templates/search_components/group_lookup_node.html` (new): recursive include, one node per level.
- `templates/global_search.html`: new `group_lookup` branch that injects the **server-rendered
  HTML** (team convention: search views render HTML, not JSON, like `avi_waf_search`);
  `xhr.status === 403` shows `xhr.responseText` instead of "Internal Server Error";
  every other branch hides `#main-group-lookup-search`, and the Group lookup branch hides the five
  FRIDA sections (`#main-frida-ar-section`, `#main-frida-port-section`,
  `#main-frida-env-result-section`, `#main-frida-expo-layer-result-section`,
  `#main-frida-result-section`).
- `pf_tag_modal_details.html` (playflows tag modal): Source/Destination Groups were empty because
  the template still used `link.group.name`; now `group.name` and `group.resolved_content`.

---

## 4. Usage examples

### 4.1 Sync (input → output)

```
> python manage.py playflows_groups_update --tag-name APAC_SG_PRD_DMZA_CORPWM --region apac

Processing tag: APAC_SG_PRD_DMZA_CORPWM
Successfully processed 1163 groups for tag APAC_SG_PRD_DMZA_CORPWM (0 stale removed)

Task 412 finished with status: success
```

Second run (idempotency): same output, no new rows, `resolved_content` untouched.

```sql
SELECT id, name, status, message FROM task_date
WHERE name = 'playflows_groups_update' ORDER BY id DESC LIMIT 1;
```

| id | name | status | message |
|---|---|---|---|
| 412 | playflows_groups_update | success | `[{"level": "info", "tag": null, "detail": "region=apac"}, {"level": "info", "tag": "APAC_SG_PRD_DMZA_CORPWM", "detail": "1163 groups processed, 0 stale removed"}]` |

Error case (API down): the run ends `failed` with
`{"level": "error", "tag": null, "detail": "Failed to connect to Playflows API"}`.

### 4.2 Lookup (input → output)

**Input:** Global Search → type `Group lookup` → `NS-PVR_INET_MGMT_NETWORKS`

```
GET /group_lookup_search?q_search=NS-PVR_INET_MGMT_NETWORKS   → 200
```

**Context passed to the template (`hierarchy`):**

```python
{
    'group_name': 'NS-PVR_INET_MGMT_NETWORKS',
    'ips': [],
    'subgroups': [
        {'group_name': 'NS-PVR_FR_MGMT', 'ips': ['10.10.1.0/24'], 'subgroups': []},
        {'group_name': 'NS-PVR_UK_MGMT', 'ips': ['10.20.1.10/32', '10.20.1.11/32'], 'subgroups': []},
    ],
}
```

**Rendered result:**

```
NS-PVR_INET_MGMT_NETWORKS
├── NS-PVR_FR_MGMT
│   └── 10.10.1.0/24
└── NS-PVR_UK_MGMT
    ├── 10.20.1.10/32
    └── 10.20.1.11/32
```

Searching a subgroup directly (`NS-PVR_UK_MGMT`) renders it as the root.

**Other responses:**

| Input | Status | Message |
|---|---|---|
| `q_search=` (empty) | 200 | No search term provided |
| `q_search=DOES_NOT_EXIST` | 200 | Group "DOES_NOT_EXIST" not found or not linked to APAC_SG_PRD_DMZA_CORPWM |
| User without `view_groups_lookup` | 403 | Group lookup is only available for APAC users (option not visible in the navbar) |

---

## 5. Tests (`rss/tests.py`)

```
python manage.py test rss
```

- `flatten_group_members`: nested members at any depth + cycle (`parent → child → grandchild → parent`).
- Sync: groups/edges created; second run creates nothing (idempotency); stale groups removed;
  container group typed `ip`; same name as `ip` and `service` stored as two rows;
  `TaskUpdateDate` ends `success`, and `failed` when the API returns `None`.
- View: tree with nested subgroups; subgroup as root; not found; empty term;
  user without permission → 403; tests run with an `apac_user` holding the permission,
  not a superuser, so they exercise the real rule.
- Permission: `user_can_view_group_lookup` true with `view_groups_lookup`, false without it.

---

## 6. Performance

- Lookup: 1 query for the root + 1 per tree level; no N+1, tree built in memory.
- Modal: reads `resolved_content`, 0 extra queries.
- Sync: flat number of queries per tag (bulk ops), flattening in memory;
  `batch_size` keeps memory and statement size bounded.

---

## 7. Deployment checklist (STG first, never scripts against PROD)

1. DB remediation on the target environment if it comes from a dump (section 8).
2. `python manage.py migrate rss` (review `migrate --plan` first: only this ticket's operations).
3. Create the permission from `/accounts/new-permission/` (Name `Can use Group Lookup`,
   Codename `view_groups_lookup`, Content Type `rss | playflowstaggroup`).
4. `python manage.py ldap_user` and check:

   ```sql
   SELECT g.name, p.codename
   FROM auth_group g
   JOIN auth_group_permissions gp ON gp.group_id = g.id
   JOIN auth_permission p ON p.id = gp.permission_id
   WHERE p.codename = 'view_groups_lookup';
   ```

   Expected: `apac_netsec`, `admin`, `emea_netsec_mgmt`.
5. `python manage.py playflows_groups_update --tag-name APAC_SG_PRD_DMZA_CORPWM --region apac`
   (twice: the second run must not create rows).
6. Validate with an APAC user (option visible, tree OK) and a non-APAC user (option hidden, 403
   if the URL is called directly).
7. Add the Group lookup entry to the "?" help (`help_guide.html`), as requested in the ticket.

---

## 8. DB remediation (only for environments restored from a dump)

Not code, but a prerequisite: dedupe rows by `ctid`, `ADD PRIMARY KEY`, `ADD CONSTRAINT UNIQUE`
and `setval` of the sequences on `pf_tag`, `pf_tag_group` and related tables. Run it only after
confirming the connection is **not** PROD.

```sql
SELECT setval(pg_get_serial_sequence('pf_tag_group', 'id'), (SELECT MAX(id) FROM pf_tag_group));
```
