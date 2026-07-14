# =============================================================
# EMEAPLAYFLOWS-3554 - Alcance de IPS / APP Control por firewall
# =============================================================
# 1) Helper reutilizable (ponlo en utils/util_tools.py o similar)
# -------------------------------------------------------------

IPS_APP_SCOPE_PATTERNS = (
    'DMZI_APPL',
    'DMZI_PRES_BASTION',
    'CORE_MKT-ETS',
    'CORE_WIN',
    'CAMPUS',
    'HVD',
    'PETAL',
    'DMZI_PRES_WIFI',
    'EMEA_FR_DEV_CORE',
)

# *DMZE cuenta, salvo estas variantes
DMZE_EXCLUDED = ('DMZE_MKT', 'DMZE_COLO')


def requires_ips_app_control(tag_name, technology):
    """
    True si el firewall (tag) entra en el alcance de las columnas
    'Rules need IPS', 'Rules have IPS', 'Rules need APP Control'
    y 'Rules have APP Control'.

    Regla del ticket: techno == FORTINET y el nombre contiene alguno
    de los patrones, o contiene DMZE pero no DMZE_MKT / DMZE_COLO.
    """
    if not technology or technology.upper() != 'FORTINET':
        return False

    name = (tag_name or '').upper()

    if any(pattern in name for pattern in IPS_APP_SCOPE_PATTERNS):
        return True

    if 'DMZE' in name and not any(exc in name for exc in DMZE_EXCLUDED):
        return True

    return False


# -------------------------------------------------------------
# 2) Integración en playflows_audit.py -> handle(), dentro de
#    "for item in tag_list:" (justo antes de las queries de IPS)
# -------------------------------------------------------------

"""
in_ips_scope = requires_ips_app_control(item.tag_name, item.technology)

if in_ips_scope:
    # ... deja tal cual tus queries actuales:
    # count_rules_with_ips_profile, count_rules_need_ips,
    # count_rules_need_and_have_ips, count_rules_with_app_control,
    # count_rules_need_app_control, count_rules_need_and_have_app_control
    # (y sus equivalentes _infra_)
    pass
else:
    count_rules_with_ips_profile = None
    count_rules_need_ips = None
    count_rules_need_and_have_ips = None
    count_rules_with_app_control = None
    count_rules_need_app_control = None
    count_rules_need_and_have_app_control = None

    count_infra_rules_with_ips_profile = None
    count_infra_rules_need_ips = None
    count_infra_rules_need_and_have_ips = None
    count_infra_rules_with_app_control = None
    count_infra_rules_need_app_control = None
    count_infra_rules_need_and_have_app_control = None
"""

# En el dict `data` no cambia nada: los None se guardan y el front
# los pinta como "NA" (if value is None -> 'NA').
# OJO: los campos correspondientes de PlayflowsTagAudit deben ser
# null=True (IntegerField(null=True, blank=True)) + makemigrations.


# -------------------------------------------------------------
# 3) Nueva estadística: Firewalls vs IPS
#    (acumular dentro del bucle y guardar/insertar al final)
# -------------------------------------------------------------

"""
# antes del for:
fw_should_and_have_ips = 0
fw_should_and_not_have_ips = 0

# dentro del for, cuando in_ips_scope es True:
if in_ips_scope:
    if count_rules_with_ips_profile and count_rules_with_ips_profile > 0:
        fw_should_and_have_ips += 1
    else:
        fw_should_and_not_have_ips += 1

# despues del for: guardalo donde te venga mejor, p.ej. en Mongo
# junto al resto del audit, o en un modelo nuevo:
stats = {
    'region': region,
    'firewalls_should_have_ips_and_have': fw_should_and_have_ips,
    'firewalls_should_have_ips_and_not_have': fw_should_and_not_have_ips,
    'created_date': timezone.now(),
}
# collection_handle.insert_one(stats)  # o coleccion propia de stats
"""
