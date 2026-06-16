import time

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from API_cnx.illumio import IllumioAPI
from rss.models import ServiceContent


def _proto_letter(proto):
    if proto == 6:
        return 'TCP'
    if proto == 17:
        return 'UDP'
    return str(proto)


class Command(BaseCommand):
    help = ('Rellena el to_port en los ServiceContent existentes usando illumio.py '
            '(catalogo de servicios para los named, get_rule por regla para los inline). '
            'Si el puerto inicial estaba como suelto, lo fusiona en el rango.')

    def add_arguments(self, parser):
        parser.add_argument('--region', type=str, required=True)
        parser.add_argument('--infra', type=str, required=True)
        parser.add_argument('--dry-run', action='store_true',
                            help='Hace todo en una transaccion y la deshace al final')

    def _fetch_services(self, obj_illumio):
        """Catalogo de servicios (named) - misma via que illumio_service."""
        collection_name = 'sec_policy/draft/services'
        total = int(obj_illumio.get_total(collection_name=collection_name))
        if total > 500:
            retry_after_time, job_id = obj_illumio.pull_job(collection_name=collection_name, total=total)
            while True:
                status, result = obj_illumio.get_job(job_id)
                if status == 'done':
                    file_id = result['href'].replace('/orgs/1/datafiles/', '')
                    result = obj_illumio.get_datafiles(file_id)
                    break
                time.sleep(retry_after_time)
        else:
            result = obj_illumio.get_collections(collection_name=collection_name, total=total)
        return result or []

    def handle(self, *args, **options):
        region = options['region']
        infra = options['infra']
        dry = options['dry_run']

        obj_illumio = IllumioAPI(env=region, infra_type=infra)

        range_map = {}      # (port, proto) -> to_port
        single_set = set()  # (port, proto) que aparece SIN to_port

        def ingest(port_specs):
            for sp in (port_specs or []):
                port = sp.get('port')
                proto = sp.get('proto')
                if port is None and proto is None:
                    continue
                to_p = sp.get('to_port')
                if to_p is not None:
                    range_map[(port, proto)] = to_p
                else:
                    single_set.add((port, proto))

        # ------------------------------------------------------------------
        # A) NAMED: catalogo de servicios (trae service_ports con to_port)
        # ------------------------------------------------------------------
        for service in self._fetch_services(obj_illumio):
            ingest(service.get('service_ports'))

        # ------------------------------------------------------------------
        # B) INLINE: get_rule_sets() + get_rule() por regla
        #    get_rule ya devuelve 'services' con proto/port/to_port
        # ------------------------------------------------------------------
        rule_count = 0
        for rs in obj_illumio.get_rule_sets():
            rsid = rs.get('ruleset_identifier')
            for rule in (rs.get('rules') or []):
                rid = rule.get('rule_identifier')
                detail = obj_illumio.get_rule(rsid, rid)
                rule_count += 1
                if not detail:
                    continue
                ingest(detail.get('services'))

        self.stdout.write(f'Reglas consultadas: {rule_count}')

        # Puerto que en Illumio existe a la vez como suelto Y como rango -> NO tocar el suelto
        ambiguous = {k for k in range_map if k in single_set}
        clean_ranges = {k: v for k, v in range_map.items() if k not in ambiguous}

        self.stdout.write(
            f'Rangos: {len(range_map)} | a aplicar: {len(clean_ranges)} | ambiguos (se omiten): {len(ambiguous)}'
        )
        for (port, proto) in sorted(ambiguous):
            self.stdout.write(
                f'  [ambiguo] {_proto_letter(proto)}-{port}: existe como suelto Y como rango'
                f'->{range_map[(port, proto)]}. Se deja el suelto; el rango hay que rederivarlo a mano.'
            )

        created_rows = 0
        consolidated = 0
        moved_links = 0
        deleted_solitary = 0

        with transaction.atomic():
            for (port, proto), to_p in clean_ranges.items():
                canonical, was_created = ServiceContent.objects.get_or_create(
                    region=region, infra_type=infra,
                    port=port, to_port=to_p, proto=proto,
                    defaults={
                        'proto_letter': _proto_letter(proto),
                        'updated_at': timezone.now(),
                        'deleted': False,
                    }
                )
                if was_created:
                    created_rows += 1
                elif canonical.deleted:
                    canonical.deleted = False
                    canonical.updated_at = timezone.now()
                    canonical.save(update_fields=['deleted', 'updated_at'])

                # puerto(s) suelto(s) con el mismo (port, proto) = el inicio del rango guardado solo
                solitary_rows = ServiceContent.objects.filter(
                    region=region, infra_type=infra,
                    port=port, proto=proto, to_port__isnull=True
                )
                touched = False
                for solitary in solitary_rows:
                    touched = True
                    for svc in list(solitary.service_set.all()):
                        moved_links += 1
                        svc.content.remove(solitary)
                        svc.content.add(canonical)
                    solitary.delete()
                    deleted_solitary += 1
                if touched:
                    consolidated += 1

            self.stdout.write(
                f'Filas de rango creadas: {created_rows} | sueltos fusionados: {consolidated} '
                f'(enlaces movidos: {moved_links}, sueltos borrados: {deleted_solitary})'
            )

            if dry:
                self.stdout.write(self.style.WARNING('DRY-RUN: deshaciendo todos los cambios.'))
                transaction.set_rollback(True)

        self.stdout.write(self.style.SUCCESS('Hecho.'))
