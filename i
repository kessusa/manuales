from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from API_cnx.illumio import IllumioAPI
from rss.models import Rule, Service, ServiceContent


def _proto_letter(proto):
    if proto == 6:
        return 'TCP'
    if proto == 17:
        return 'UDP'
    return str(proto)


class Command(BaseCommand):
    help = ('One-off: reconstruye los servicios de cada regla EXISTENTE a partir de Illumio '
            '(get_rule por regla), creando los ServiceContent con to_port donde toque y dejando '
            'la regla enlazada exactamente a los suyos. Resuelve el caso ambiguo porque cada '
            'regla dice si su puerto es suelto o rango.')

    def add_arguments(self, parser):
        parser.add_argument('--region', type=str, required=True)
        parser.add_argument('--infra', type=str, required=True)
        parser.add_argument('--dry-run', action='store_true',
                            help='Hace todo en una transaccion y la deshace al final')

    def handle(self, *args, **options):
        region = options['region']
        infra = options['infra']
        dry = options['dry_run']

        api = IllumioAPI(env=region, infra_type=infra)

        rule_sets = api.get_rule_sets()
        if not rule_sets:
            self.stdout.write(self.style.ERROR(
                'get_rule_sets() devolvio None/vacio. Revisa --region/--infra. Abortando.'
            ))
            return

        processed = 0       # reglas para las que se llamo a get_rule
        skipped_no_db = 0   # reglas de Illumio que no existen en la BD (las crea el import normal)
        updated = 0         # reglas a las que se les reescribio el set de servicios
        empty_detail = 0    # get_rule sin servicios -> no se toca (para no vaciar por fallo)

        with transaction.atomic():
            for rs in rule_sets:
                rsid = rs.get('ruleset_identifier')
                for rule_ref in (rs.get('rules') or []):
                    rid = rule_ref.get('rule_identifier')

                    # solo tocamos reglas que YA existen en la BD
                    rule_instance = Rule.objects.filter(
                        rule_identifier=rid, region=region, infra_type=infra
                    ).first()
                    if rule_instance is None:
                        skipped_no_db += 1
                        continue

                    detail = api.get_rule(rsid, rid)
                    processed += 1
                    if not detail:
                        continue

                    services = detail.get('services')
                    if not services:
                        # no tocar si vino vacio (puede ser un fallo transitorio) para no vaciar la regla
                        empty_detail += 1
                        continue

                    service_objs = []
                    for service in services:
                        if service.get('service_identifier'):
                            # NAMED: su contenido lo gestiona illumio_service; aqui solo enlazamos
                            service_obj, _ = Service.objects.get_or_create(
                                service_identifier=service.get('service_identifier'),
                                region=region, infra_type=infra,
                                defaults={'updated_at': timezone.now(), 'deleted': False},
                            )
                        else:
                            # INLINE: ServiceContent con to_port en el LOOKUP -> suelto y rango son filas distintas
                            srv_content, _ = ServiceContent.objects.update_or_create(
                                region=region, infra_type=infra,
                                port=service.get('port'),
                                to_port=service.get('to_port'),
                                proto=service.get('proto'),
                                proto_letter=_proto_letter(service.get('proto')),
                                defaults={'updated_at': timezone.now(), 'deleted': False},
                            )
                            # wrapper anonimo reutilizado por contenido (no se duplica)
                            service_obj = Service.objects.filter(
                                name__isnull=True, region=region, infra_type=infra,
                                content=srv_content
                            ).first()
                            if service_obj is None:
                                service_obj = Service.objects.create(region=region, infra_type=infra)
                                service_obj.content.add(srv_content)

                        service_objs.append(service_obj)

                    # la regla queda enlazada EXACTAMENTE a estos servicios (sin duplicados)
                    rule_instance.services.set(service_objs)
                    updated += 1

            self.stdout.write(
                f'Reglas con get_rule: {processed} | actualizadas: {updated} | '
                f'sin servicios (no tocadas): {empty_detail} | no estan en BD (saltadas): {skipped_no_db}'
            )

            if dry:
                self.stdout.write(self.style.WARNING('DRY-RUN: deshaciendo todos los cambios.'))
                transaction.set_rollback(True)

        self.stdout.write(self.style.SUCCESS('Hecho.'))
