from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction

from API_cnx.illumio import IllumioAPI
from rss.models import Label, LabelGroup, IpList, Service, Ruleset, Rule, RuleContent, Workload, ServiceContent, \
    TaskUpdateDate


class Command(BaseCommand):
    help = 'Update Illumio Ruleset data from API to local database'

    def add_arguments(self, parser):
        parser.add_argument('--region', type=str, default='emea')
        parser.add_argument('--infra', type=str, default='iv1')

    def handle(self, *args, **options):
        region = options['region']
        infra = options['infra']
        created_at = timezone.now()

        # Task instance for auditing / tracking the update process
        task_instance = TaskUpdateDate.objects.create(name='illumio_ruleset', created_at=created_at)
        obj_illumio = IllumioAPI(env=region, infra_type=infra)

        rulesets = obj_illumio.get_rule_sets()

        # FIX 1 (critico): si get_rule_sets() devuelve None/vacio, abortamos AQUI.
        # Evita el crash de len(None) y, sobre todo, evita que la limpieza de abajo
        # corra con inventarios vacios y marque TODO como deleted=True (dashboard vacio).
        if not rulesets:
            task_instance.message = {
                'region': region, 'infra': infra, 'total': 0,
                'error': 'get_rule_sets() devolvio None/vacio - abortado sin limpieza',
            }
            task_instance.finish_at = timezone.now()
            task_instance.save()
            self.stdout.write(self.style.ERROR(
                'get_rule_sets() no devolvio datos. Abortado SIN limpieza para no borrar datos validos.'
            ))
            return

        task_instance.message = {'region': region, 'infra': infra, 'total': len(rulesets)}

        # --- Inventarios "vivos" de esta pasada (base de la limpieza por inventario) ---
        rulesets_vivos = set()
        rules_vivas = set()
        rule_contents_vivos = set()

        # FIX 2: contador de fallos de get_rule, para decidir si es seguro podar RuleContent.
        get_rule_failures = 0

        for ruleset_data in rulesets:
            rs_id = ruleset_data.get('ruleset_identifier')
            if rs_id:
                rulesets_vivos.add(rs_id)

            rules = ruleset_data.pop('rules', [])

            # 1. Sync Ruleset
            ruleset_obj, _ = Ruleset.objects.update_or_create(
                ruleset_identifier=rs_id,
                region=region,
                infra_type=infra,
                defaults={
                    'name': ruleset_data.get('name'),
                    'description': ruleset_data.get('description'),
                    'status': ruleset_data.get('status'),
                    'updated_at': timezone.now(),
                    'deleted': False,
                },
            )

            if not rules:
                continue

            for item in rules:
                rule_id = item.get('rule_identifier')
                if rule_id:
                    rules_vivas.add(rule_id)  # visto en el listado (independiente de get_rule)

                # 2. Detalle de la regla. Lo pedimos FUERA de la transaccion para no tener
                #    la transaccion abierta durante la llamada HTTP. Si falla, conservamos
                #    lo que la regla ya tuviera y lo contamos (FIX 2).
                rule_detail = obj_illumio.get_rule(rs_id, rule_id)
                if not rule_detail:
                    get_rule_failures += 1
                    continue

                providers = rule_detail.pop('providers', [])
                consumers = rule_detail.pop('consumers', [])
                services = rule_detail.pop('services', [])

                # Solo las ESCRITURAS van dentro de la transaccion (consistencia por regla)
                with transaction.atomic():
                    # 3. Update or Create de la regla
                    rule_instance, _ = Rule.objects.update_or_create(
                        rule_identifier=rule_id,
                        region=region,
                        infra_type=infra,
                        ruleset=ruleset_obj,
                        defaults={
                            'status': rule_detail.get('status'),
                            'description': rule_detail.get('description'),
                            'updated_at': timezone.now(),
                            'deleted': False,
                        },
                    )

                    # 4. CONSUMERS (limpiar y reconstruir para reflejar Illumio exacto)
                    rule_instance.consumers.clear()
                    if consumers:
                        for consumer in consumers:
                            # label con get_or_create (igual que en providers, para no perder
                            # la referencia si el label aun no se importo y por consistencia).
                            label_obj = None
                            if consumer.get('label'):
                                label_obj, _ = Label.objects.get_or_create(
                                    label_identifier=consumer['label'],
                                    region=region, infra_type=infra,
                                    defaults={'updated_at': timezone.now(), 'deleted': False},
                                )
                            workload_obj = Workload.objects.filter(
                                workload_identifier=consumer.get('workload'),
                                region=region, infra_type=infra,
                            ).first() if consumer.get('workload') else None
                            ip_list_obj = IpList.objects.filter(
                                ipList_identifier=consumer.get('ip_list'),
                                region=region, infra_type=infra,
                            ).first() if consumer.get('ip_list') else None
                            label_group_obj = LabelGroup.objects.filter(
                                label_group_identifier=consumer.get('label_group'),
                                region=region, infra_type=infra,
                            ).first() if consumer.get('label_group') else None

                            rc_instance, _ = RuleContent.objects.update_or_create(
                                region=region, infra_type=infra,
                                actors=consumer.get('actor'),
                                labels=label_obj,
                                workloads=workload_obj,
                                ip_lists=ip_list_obj,
                                label_groups=label_group_obj,
                                defaults={'updated_at': timezone.now(), 'deleted': False},
                            )
                            rule_instance.consumers.add(rc_instance)
                            rule_contents_vivos.add(rc_instance.id)

                    # 5. PROVIDERS (limpiar y reconstruir)
                    rule_instance.providers.clear()
                    if providers:
                        for provider in providers:
                            label_obj = None
                            if provider.get('label'):
                                label_obj, _ = Label.objects.get_or_create(
                                    label_identifier=provider['label'],
                                    region=region, infra_type=infra,
                                    defaults={'updated_at': timezone.now(), 'deleted': False},
                                )
                            workload_obj = Workload.objects.filter(
                                workload_identifier=provider.get('workload'),
                                region=region, infra_type=infra,
                            ).first() if provider.get('workload') else None
                            ip_list_obj = IpList.objects.filter(
                                ipList_identifier=provider.get('ip_list'),
                                region=region, infra_type=infra,
                            ).first() if provider.get('ip_list') else None
                            label_group_obj = LabelGroup.objects.filter(
                                label_group_identifier=provider.get('label_group'),
                                region=region, infra_type=infra,
                            ).first() if provider.get('label_group') else None

                            rc_instance, _ = RuleContent.objects.update_or_create(
                                region=region, infra_type=infra,
                                actors=provider.get('actor'),
                                labels=label_obj,
                                workloads=workload_obj,
                                ip_lists=ip_list_obj,
                                label_groups=label_group_obj,
                                defaults={'updated_at': timezone.now(), 'deleted': False},
                            )
                            rule_instance.providers.add(rc_instance)
                            rule_contents_vivos.add(rc_instance.id)

                    # 6. SERVICES (limpiar y reconstruir)
                    rule_instance.services.clear()
                    if services:
                        for service in services:
                            if service.get('service_identifier'):
                                # Servicio con nombre (catalogo): update_or_create para refrescar nombre/descr.
                                service_obj, _ = Service.objects.update_or_create(
                                    service_identifier=service.get('service_identifier'),
                                    region=region, infra_type=infra,
                                    defaults={
                                        'name': service['name'].replace(' ', '_') if service.get('name') else None,
                                        'description': service.get('description'),
                                        'updated_at': timezone.now(),
                                        'deleted': False,
                                    },
                                )
                            else:
                                # Servicio inline (port/range). to_port en el lookup -> single y rango
                                # son filas distintas.
                                proto = service.get('proto')
                                srv_content_instance, _ = ServiceContent.objects.update_or_create(
                                    region=region, infra_type=infra,
                                    port=service.get('port'),
                                    to_port=service.get('to_port'),
                                    proto=proto,
                                    proto_letter='TCP' if proto == 6 else 'UDP' if proto == 17 else proto,
                                    defaults={'updated_at': timezone.now(), 'deleted': False},
                                )
                                # FIX 3: reusar el wrapper anonimo por contenido en vez de crear
                                # uno nuevo cada pasada (evita acumular wrappers huerfanos).
                                service_obj = Service.objects.filter(
                                    name__isnull=True, region=region, infra_type=infra,
                                    content=srv_content_instance,
                                ).first()
                                if service_obj is None:
                                    service_obj = Service.objects.create(region=region, infra_type=infra)
                                service_obj.content.add(srv_content_instance)

                            rule_instance.services.add(service_obj)

        finish_at = timezone.now()

        # --- LIMPIEZA FINAL (por inventario) ---
        # Marcamos deleted=True lo que NO aparecio en Illumio en esta pasada.
        # Ruleset y Rule: por identificador visto en el listado -> robusto ante fallos de get_rule.
        Ruleset.objects.filter(region=region, infra_type=infra).exclude(
            ruleset_identifier__in=rulesets_vivos
        ).update(deleted=True)

        Rule.objects.filter(region=region, infra_type=infra).exclude(
            rule_identifier__in=rules_vivas
        ).update(deleted=True)

        # FIX 2: RuleContent solo se poda si NO hubo fallos de get_rule. Si los hubo, no
        # conocemos el contenido real de esas reglas y podriamos borrar consumers/providers
        # validos; se podara en una pasada limpia.
        if get_rule_failures == 0:
            RuleContent.objects.filter(region=region, infra_type=infra).exclude(
                id__in=rule_contents_vivos
            ).update(deleted=True)
        else:
            self.stdout.write(self.style.WARNING(
                f'{get_rule_failures} regla(s) sin detalle (get_rule fallo). '
                f'Se OMITE la poda de RuleContent para no borrar datos validos.'
            ))

        task_instance.finish_at = finish_at
        task_instance.message = {
            'region': region,
            'infra': infra,
            'total': len(rulesets),
            'get_rule_failures': get_rule_failures,
        }
        task_instance.save()

        self.stdout.write(self.style.SUCCESS(
            f'illumio_ruleset OK | region={region} infra={infra} | '
            f'rulesets={len(rulesets)} fallos_get_rule={get_rule_failures}'
        ))
