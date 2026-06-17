from datetime import date, timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from API_cnx.illumio import IllumioAPI
from rss.models import Label, LabelGroup, IpList, Service, Ruleset, Rule, RuleContent, Workload, ServiceContent, \
    IpAddress, Ven, Interface, TaskUpdateDate


# illumio_ruleset
class Command(BaseCommand):
    help = 'Update Illumio Ruleset data'

    def add_arguments(self, parser):
        parser.add_argument('--region', type=str, default='emea')
        parser.add_argument('--infra', type=str, default='iv1')

    def handle(self, *args, **options):
        region = options['region']
        infra = options['infra']

        created_at = timezone.now()

        task_instance = TaskUpdateDate.objects.create(name=f'illumio_ruleset', created_at=created_at)

        # Define Illumio object
        obj_illumio = IllumioAPI(env=region, infra_type=infra)

        rulesets = obj_illumio.get_rule_sets()

        # ============================================================================
        # FALLO 4 — len(rulesets) y limpieza con rulesets vacio/None
        #   ANTES: hacias  task_instance.message = {... 'total': len(rulesets)}
        #          directamente. Si get_rule_sets() devuelve None -> len(None) revienta.
        #          Y si devolvia [] (vacio), el 'if rulesets:' saltaba el procesado PERO
        #          la limpieza del final SI corria -> como nada se refresco, marcaba TODO
        #          como deleted=True -> dashboard vacio.
        #   FIX:   si no hay rulesets, abortamos AQUI, sin tocar len() ni la limpieza.
        # ============================================================================
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

        # ============================================================================
        # FALLO 2 (parte 1) — preparamos los conjuntos de "visto en esta pasada".
        #   Son la base de la limpieza SEGURA del final (ver FALLO 2 parte 2).
        # ============================================================================
        seen_ruleset_ids = set()
        seen_rule_ids = set()
        seen_content_ids = set()
        get_rule_failures = 0

        for ruleset in rulesets:
            seen_ruleset_ids.add(ruleset.get('ruleset_identifier'))
            rules = ruleset.pop('rules')

            ruleset_obj, _ = Ruleset.objects.update_or_create(
                ruleset_identifier=ruleset.get('ruleset_identifier'),
                region=region,
                infra_type=infra,
                defaults={
                    'name': ruleset.get('name'),
                    'description': ruleset.get('description'),
                    'status': ruleset.get('status'),
                    'updated_at': timezone.now(),
                    'deleted': False
                }
            )

            if not rules:
                continue

            for item in rules:
                seen_rule_ids.add(item.get('rule_identifier'))

                rule_instance, created = Rule.objects.get_or_create(
                    rule_identifier=item.get('rule_identifier'),
                    region=region,
                    infra_type=infra,
                    ruleset=ruleset_obj,
                    defaults={
                        'updated_at': timezone.now(),
                        'deleted': False
                    }
                )

                # ====================================================================
                # FALLO 1 — el gate  'if created:'  (ESTE ES EL GORDO)
                #   ANTES: todo el detalle (get_rule + consumers/providers/services)
                #          vivia dentro de 'if created:'. Eso significa:
                #            a) las reglas que YA existian (created=False) NUNCA se
                #               reprocesaban -> nunca recibian el to_port (por eso solo
                #               lo veias en los rulesets nuevos), y
                #            b) su 'updated_at' no se refrescaba -> la limpieza del final
                #               (FALLO 2) las marcaba deleted=True -> desaparecian.
                #          Solo "funcionaba" en BD vacia, donde todo es created=True.
                #   FIX:   QUITAMOS el gate. Ahora se reprocesa cada regla (nueva y
                #          existente), asi se rellena el to_port en lo viejo y se refresca
                #          'updated_at'. (El motivo por el que existia el gate -evitar
                #          wrappers duplicados- lo arreglamos en FALLO 3, no con el gate.)
                #
                #   >>> Lo unico que hay que hacer aqui es BORRAR la linea 'if created:'
                #       y sacar un nivel de indentacion todo el bloque de abajo. <<<
                # ====================================================================

                # # Get rule info
                # FALLO 5 (parte 1) — get_rule sin proteccion.
                #   ANTES: rule = obj_illumio.get_rule(...) a pelo. Sin gate, esto corre
                #          para TODAS las reglas; si una falla (timeout/None), antes ni se
                #          contaba. Necesitamos contar fallos para la limpieza segura.
                #   FIX:   envolvemos en try/except y contamos el fallo. Si falla, NO
                #          tocamos consumers/providers/services de esa regla (se conservan
                #          los que ya tenia) y saltamos al siguiente.
                try:
                    rule = obj_illumio.get_rule(
                        ruleset.get('ruleset_identifier'),
                        item.get('rule_identifier'),
                    )
                except Exception as exc:
                    rule = None
                    self.stdout.write(self.style.WARNING(
                        f'get_rule fallo para {item.get("rule_identifier")}: {exc}'
                    ))

                if not rule:
                    get_rule_failures += 1
                    continue

                providers = rule.pop('providers', [])
                consumers = rule.pop('consumers', [])
                services = rule.pop('services', [])

                rule_instance, _ = Rule.objects.update_or_create(
                    rule_identifier=rule.get('rule_identifier'),
                    region=region,
                    infra_type=infra,
                    ruleset=ruleset_obj,
                    defaults={
                        'status': rule.get('status'),
                        'description': rule.get('description'),
                        'updated_at': timezone.now(),
                        'deleted': False
                    }
                )

                # # Consumers
                # ====================================================================
                # FALLO 3 (parte 1) — .add() en vez de .set()
                #   ANTES: por cada consumer hacias rule_instance.consumers.add(...).
                #          Sin gate, reprocesando cada pasada, .add() nunca quita los
                #          enlaces viejos: si una regla pierde un consumer en Illumio, el
                #          enlace antiguo se queda. Con .set() la regla refleja EXACTO lo
                #          que hay ahora en Illumio.
                #   FIX:   acumulamos en una lista y hacemos .set() al final del bloque.
                # ====================================================================
                consumer_contents = []
                if consumers:
                    for consumer in consumers:
                        # FALLO 5 (parte 2) — Label.objects.get() en consumers.
                        #   ANTES: usabas Label.objects.get(...). Si el label no existe
                        #          lanza DoesNotExist -> peta y (si hay try/except por
                        #          regla) salta el resto de ESA regla (consumers Y
                        #          providers) -> su RuleContent no se refresca -> la
                        #          limpieza lo borra. Los providers ya usaban get_or_create.
                        #   FIX:   get_or_create, igual que en providers (no tumba la regla).
                        if consumer.get('label'):
                            label_obj, _ = Label.objects.get_or_create(
                                label_identifier=consumer['label'],
                                region=region,
                                infra_type=infra,
                                defaults={'updated_at': timezone.now(), 'deleted': False},
                            )
                        else:
                            label_obj = None

                        if consumer.get('workload'):
                            try:
                                workload_obj = Workload.objects.get(
                                    workload_identifier=consumer.get('workload'),
                                    region=region,
                                    infra_type=infra,
                                )
                            except Exception:
                                workload_obj = None
                        else:
                            workload_obj = None

                        if consumer.get('ip_list'):
                            try:
                                ip_list_obj = IpList.objects.get(
                                    ipList_identifier=consumer['ip_list'],
                                    region=region,
                                    infra_type=infra
                                )
                            except Exception:
                                ip_list_obj = None
                        else:
                            ip_list_obj = None

                        # FALLO 5 (parte 3) — LabelGroup.objects.get() (consumers Y providers)
                        #   ANTES: .get() sin try -> si falta el label_group, peta la regla.
                        #   FIX:   try/except -> None.
                        if consumer.get('label_group'):
                            try:
                                label_group_obj = LabelGroup.objects.get(
                                    label_group_identifier=consumer['label_group'],
                                    region=region,
                                    infra_type=infra
                                )
                            except Exception:
                                label_group_obj = None
                        else:
                            label_group_obj = None

                        rule_content_instance, _ = RuleContent.objects.update_or_create(
                            region=region, infra_type=infra,
                            actors=consumer.get('actor'),
                            labels=label_obj,
                            workloads=workload_obj,
                            ip_lists=ip_list_obj,
                            label_groups=label_group_obj,
                            defaults={
                                'updated_at': timezone.now(),
                                'deleted': False
                            },
                        )
                        seen_content_ids.add(rule_content_instance.id)   # FALLO 2: marcar visto
                        consumer_contents.append(rule_content_instance)  # FALLO 3: acumular
                rule_instance.consumers.set(consumer_contents)           # FALLO 3: .set() (antes .add() en el bucle)

                # # Providers
                provider_contents = []
                if providers:
                    for provider in providers:
                        if provider.get('label'):
                            label_obj, _ = Label.objects.get_or_create(
                                label_identifier=provider['label'],
                                region=region,
                                infra_type=infra,
                                defaults={
                                    'updated_at': timezone.now(),
                                    'deleted': False
                                },
                            )
                        else:
                            label_obj = None

                        if provider.get('workload'):
                            try:
                                workload_obj = Workload.objects.get(
                                    workload_identifier=provider.get('workload'),
                                    region=region, infra_type=infra,
                                )
                            except Exception:
                                workload_obj = None
                        else:
                            workload_obj = None

                        if provider.get('ip_list'):
                            try:
                                ip_list_obj = IpList.objects.get(
                                    ipList_identifier=provider['ip_list'],
                                    region=region, infra_type=infra
                                )
                            except Exception:
                                ip_list_obj = None
                        else:
                            ip_list_obj = None

                        # FALLO 5 (parte 3, providers) — mismo arreglo del label_group.
                        if provider.get('label_group'):
                            try:
                                label_group_obj = LabelGroup.objects.get(
                                    label_group_identifier=provider['label_group'],
                                    region=region, infra_type=infra,
                                )
                            except Exception:
                                label_group_obj = None
                        else:
                            label_group_obj = None

                        rule_content_instance, _ = RuleContent.objects.update_or_create(
                            region=region,
                            infra_type=infra,
                            actors=provider.get('actor'),
                            labels=label_obj,
                            workloads=workload_obj,
                            ip_lists=ip_list_obj,
                            label_groups=label_group_obj,
                            defaults={
                                'updated_at': timezone.now(),
                                'deleted': False
                            },
                        )
                        seen_content_ids.add(rule_content_instance.id)   # FALLO 2: marcar visto
                        provider_contents.append(rule_content_instance)  # FALLO 3: acumular
                rule_instance.providers.set(provider_contents)           # FALLO 3: .set() (antes .add())

                # # Services
                service_objs = []
                if services:
                    for service in services:
                        if service.get('service_identifier'):
                            service_obj, _ = Service.objects.get_or_create(
                                service_identifier=service.get('service_identifier'),
                                region=region, infra_type=infra,
                                defaults={
                                    'name': service['name'].replace(' ', '_') if service.get('name') else None,
                                    'description': service.get('description'),
                                    'updated_at': timezone.now(),
                                    'deleted': False
                                },
                            )
                        else:
                            # to_port ya lo tenias bien aqui (en el lookup), eso se queda igual.
                            proto = service.get('proto')
                            srv_content_instance, _ = ServiceContent.objects.update_or_create(
                                region=region, infra_type=infra,
                                port=service.get('port'),
                                to_port=service.get('to_port'),
                                proto=proto,
                                proto_letter='TCP' if proto == 6 else 'UDP' if proto == 17 else proto,
                                defaults={
                                    'updated_at': timezone.now(),
                                    'deleted': False
                                },
                            )
                            # ============================================================
                            # FALLO 3 (parte 2) — Service.objects.create() cada vez
                            #   ANTES: para cada servicio inline hacias siempre
                            #          Service.objects.create(...) -> sin gate, eso crea un
                            #          wrapper anonimo NUEVO en cada pasada -> wrappers
                            #          duplicados acumulandose. (Por esto se metio el gate
                            #          en su dia; pero el gate rompia otras cosas.)
                            #   FIX:   reutilizamos el wrapper anonimo por contenido; solo
                            #          creamos uno si no existe.
                            # ============================================================
                            service_obj = Service.objects.filter(
                                name__isnull=True,
                                region=region,
                                infra_type=infra,
                                content=srv_content_instance,
                            ).first()
                            if service_obj is None:
                                service_obj = Service.objects.create(region=region, infra_type=infra)
                            service_obj.content.add(srv_content_instance)

                        service_objs.append(service_obj)                 # FALLO 3: acumular
                rule_instance.services.set(service_objs)                 # FALLO 3: .set() (antes .add())

        finish_at = timezone.now()

        # ============================================================================
        # FALLO 2 (parte 2) — LA LIMPIEZA (el otro fallo gordo)
        #   ANTES (lo que tenias):
        #       Rule.objects.filter(region, infra).exclude(
        #           updated_at__date__range=[created_at.date(), finish_at.date()]
        #       ).update(deleted=True)
        #       ... y lo mismo para RuleContent y Ruleset.
        #
        #   POR QUE FALLA: marca deleted=True TODO lo que no se haya refrescado HOY.
        #     - Con el gate (FALLO 1), lo existente no se refrescaba -> lo borraba entero.
        #     - Aun sin gate, cualquier regla cuyo get_rule falle esa pasada no se refresca
        #       -> la borra por error (consumers/providers desaparecen poco a poco).
        #
        #   FIX: podar por "lo que NO ha aparecido en Illumio esta pasada", no por fecha:
        #     - Ruleset y Rule: por identificador visto (viene del listado de
        #       get_rule_sets, NO depende de get_rule) -> un fallo de detalle no borra una
        #       regla que sigue existiendo.
        #     - RuleContent: por id visto, y SOLO si no hubo fallos de get_rule (si los
        #       hubo, no conocemos el contenido real de esas reglas -> no podamos, para no
        #       borrar consumers/providers validos; se podara en una pasada limpia).
        #
        #   IMPORTANTE: esto SIGUE respetando el historico. Lo que de verdad ya no esta en
        #   Illumio se marca deleted=True (historico). Lo que sigue estando se queda
        #   deleted=False. No se borra fisicamente nada.
        # ============================================================================
        Ruleset.objects.filter(region=region, infra_type=infra).exclude(
            ruleset_identifier__in=seen_ruleset_ids
        ).update(deleted=True)

        Rule.objects.filter(region=region, infra_type=infra).exclude(
            rule_identifier__in=seen_rule_ids
        ).update(deleted=True)

        if get_rule_failures == 0:
            RuleContent.objects.filter(region=region, infra_type=infra).exclude(
                id__in=seen_content_ids
            ).update(deleted=True)
        else:
            self.stdout.write(self.style.WARNING(
                f'{get_rule_failures} regla(s) sin detalle (get_rule fallo). '
                f'Se OMITE la poda de RuleContent para no borrar consumers/providers validos.'
            ))

        task_instance.finish_at = finish_at
        task_instance.message = {
            'region': region,
            'infra': infra,
            'total': len(rulesets),
            'get_rule_failures': get_rule_failures,
        }
        task_instance.save()
