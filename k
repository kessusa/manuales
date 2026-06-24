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
        task_instance.message = {'region': region, 'infra': infra, 'total': len(rulesets) if rulesets else 0}

        # Inventarios "vivos" de esta pasada (base de la limpieza por inventario)
        rulesets_vivos = set()
        rules_vivas = set()
        rule_contents_vivos = set()
        get_rule_failures = 0

        if rulesets:
            for ruleset in rulesets:
                rules = ruleset.pop('rules', [])

                rulesets_vivos.add(ruleset.get('ruleset_identifier'))

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

                if rules:
                    for item in rules:
                        rules_vivas.add(item.get('rule_identifier'))

                        # # Get rule info
                        rule = obj_illumio.get_rule(ruleset.get('ruleset_identifier'), item.get('rule_identifier'))

                        if rule:
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
                                    'ruleset': ruleset_obj,
                                    'region': region,
                                    'infra_type': infra,
                                    'updated_at': timezone.now(),
                                    'deleted': False
                                }
                            )

                            # # Consumers
                            rule_instance.consumers.clear()
                            if consumers:
                                for consumer in consumers:
                                    if consumer.get('label'):
                                        label_obj, _ = Label.objects.get_or_create(
                                            label_identifier=consumer['label'],
                                            region=region,
                                            infra_type=infra,
                                            defaults={
                                                'updated_at': timezone.now(),
                                                'deleted': False
                                            },
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
                                        except:
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
                                        except:
                                            ip_list_obj = None
                                    else:
                                        ip_list_obj = None

                                    if consumer.get('label_group'):
                                        try:
                                            label_group_obj = LabelGroup.objects.get(
                                                label_group_identifier=consumer['label_group'],
                                                region=region,
                                                infra_type=infra
                                            )
                                        except:
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
                                    rule_instance.consumers.add(rule_content_instance)
                                    rule_contents_vivos.add(rule_content_instance.id)

                            # # Providers
                            rule_instance.providers.clear()
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
                                                region=region,
                                                infra_type=infra,
                                            )
                                        except:
                                            workload_obj = None
                                    else:
                                        workload_obj = None

                                    if provider.get('ip_list'):
                                        try:
                                            ip_list_obj = IpList.objects.get(
                                                ipList_identifier=provider['ip_list'],
                                                region=region,
                                                infra_type=infra
                                            )
                                        except:
                                            ip_list_obj = None
                                    else:
                                        ip_list_obj = None

                                    if provider.get('label_group'):
                                        try:
                                            label_group_obj = LabelGroup.objects.get(
                                                label_group_identifier=provider['label_group'],
                                                region=region,
                                                infra_type=infra
                                            )
                                        except:
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
                                    rule_instance.providers.add(rule_content_instance)
                                    rule_contents_vivos.add(rule_content_instance.id)

                            # # Services
                            rule_instance.services.clear()
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
                                        srv_content_instance, _ = ServiceContent.objects.update_or_create(
                                            region=region, infra_type=infra,
                                            port=service.get('port'),
                                            to_port=service.get('to_port'),
                                            proto=service.get('proto'),
                                            proto_letter='TCP' if service['proto'] == 6 else 'UDP' if service['proto'] == 17 else service['proto'],
                                            defaults={
                                                'updated_at': timezone.now(),
                                                'deleted': False
                                            },
                                        )
                                        service_obj = Service.objects.filter(
                                            name__isnull=True,
                                            region=region,
                                            infra_type=infra,
                                            content=srv_content_instance
                                        ).first()
                                        if service_obj is None:
                                            service_obj = Service.objects.create(region=region, infra_type=infra)
                                        service_obj.content.add(srv_content_instance)

                                    rule_instance.services.add(service_obj)
                        else:
                            get_rule_failures += 1

            # # Cleanup (por inventario: marca deleted=True lo que no aparecio en esta pasada)
            Rule.objects.filter(region=region, infra_type=infra).exclude(
                rule_identifier__in=rules_vivas
            ).update(deleted=True)

            if get_rule_failures == 0:
                RuleContent.objects.filter(region=region, infra_type=infra).exclude(
                    id__in=rule_contents_vivos
                ).update(deleted=True)

            Ruleset.objects.filter(region=region, infra_type=infra).exclude(
                ruleset_identifier__in=rulesets_vivos
            ).update(deleted=True)

        finish_at = timezone.now()
        task_instance.finish_at = finish_at
        task_instance.message = {'region': region, 'infra': infra, 'total': len(rulesets) if rulesets else 0,
                                 'get_rule_failures': get_rule_failures}
        task_instance.save()
