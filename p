import os

from django.core.management.base import BaseCommand

# OJO: ajusta este import al nombre real del modelo que mapea la tabla anti_ddos.
# Aqui se asume que se llama AntiDdos y vive en rss.models (igual que AviIwaf).
from rss.models import AviIwaf, AntiDdos


class Command(BaseCommand):
    help = 'Rellena avi_iwaf.url con la url de anti_ddos haciendo match vs_ip <-> ip_address'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Calcula cuantas filas se actualizarian, pero no guarda nada.',
        )
        parser.add_argument(
            '--overwrite',
            action='store_true',
            help='Sobrescribe url aunque avi_iwaf ya tenga un valor. Por defecto solo rellena las vacias.',
        )

    @staticmethod
    def extract_ips(ip_field):
        """
        Normaliza el contenido del jsonb ip_address a una lista de IPs (strings).
        Soporta: string suelto, lista de strings, lista de dicts y dict.
        """
        if not ip_field:
            return []
        if isinstance(ip_field, str):
            return [ip_field.strip()]
        if isinstance(ip_field, dict):
            return [v.strip() for v in ip_field.values() if isinstance(v, str)]
        if isinstance(ip_field, list):
            ips = []
            for item in ip_field:
                if isinstance(item, str):
                    ips.append(item.strip())
                elif isinstance(item, dict):
                    ips.extend(v.strip() for v in item.values() if isinstance(v, str))
            return ips
        return []

    def handle(self, *args, **options):
        os.environ['NO_PROXY'] = '*'

        dry_run = options['dry_run']
        overwrite = options['overwrite']

        # 1) IPs que nos interesan: las que estan en avi_iwaf.vs_ip
        target_ips = set(
            AviIwaf.objects
            .exclude(vs_ip__isnull=True)
            .exclude(vs_ip='')
            .values_list('vs_ip', flat=True)
        )
        self.stdout.write(f'vs_ip unicos en avi_iwaf: {len(target_ips)}')

        # 2) Mapa ip -> url recorriendo anti_ddos UNA sola vez.
        #    Solo guardamos las IPs que aparecen en avi_iwaf para no inflar memoria.
        ip_to_url = {}
        qs = (
            AntiDdos.objects
            .exclude(url__isnull=True)
            .exclude(url='')
            .values('ip_address', 'url')
            .iterator(chunk_size=2000)
        )
        for row in qs:
            url = row['url']
            for ip in self.extract_ips(row['ip_address']):
                if ip in target_ips and ip not in ip_to_url:
                    ip_to_url[ip] = url  # nos quedamos con la primera coincidencia
        self.stdout.write(f'IPs con url encontrada en anti_ddos: {len(ip_to_url)}')

        # 3) Preparar las actualizaciones de avi_iwaf
        to_update = []
        avi_qs = (
            AviIwaf.objects
            .exclude(vs_ip__isnull=True)
            .exclude(vs_ip='')
            .iterator(chunk_size=2000)
        )
        for avi in avi_qs:
            new_url = ip_to_url.get(avi.vs_ip)
            if not new_url:
                continue
            if avi.url == new_url:
                continue
            if avi.url and not overwrite:
                # ya tiene url y no queremos pisarla
                continue
            avi.url = new_url
            to_update.append(avi)

        if dry_run:
            self.stdout.write(self.style.WARNING(
                f'[dry-run] Se actualizarian {len(to_update)} filas. No se guardo nada.'
            ))
            return

        AviIwaf.objects.bulk_update(to_update, ['url'], batch_size=500)
        self.stdout.write(self.style.SUCCESS(
            f'{len(to_update)} filas de avi_iwaf actualizadas.'
        ))
