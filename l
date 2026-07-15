import os
from collections import defaultdict
from pathlib import Path

import xlsxwriter
from django.conf import settings
from django.core.management.base import BaseCommand

from rss.models import FirewallRule   # <-- AJUSTA: tu modelo de reglas (el del obj_list)

REGIONS = ['emea', 'amer', 'apac', 'cis', 'itg']
FOLDER = 'per_device_mapping'
FILENAME = 'per_device_mapping.xlsx'

HEADERS = ['ADOM', 'FIREWALL', 'POLICIES', 'OBJECTS', 'RULES ID', 'COUNT PER FIREWALL']


class Command(BaseCommand):
    help = 'Genera el Excel de per-device-mapping (una pestaña por región) en MEDIA_ROOT'

    def add_arguments(self, parser):
        parser.add_argument('--region', action='append', dest='regions',
                            help='Región concreta (repetible). Por defecto, todas.')

    # ------------------------------------------------------------------ datos
    def build_table(self, region):
        qs = (FirewallRule.objects
              .filter(tag__region=region, tag__deleted=False)
              .select_related('tag')
              .only('rule_id', 'section', 'per_device_mapping',
                    'tag__tag_name', 'tag__domain'))   # <-- AJUSTA rule_id / section

        # domain -> firewall -> datos
        adoms = defaultdict(lambda: defaultdict(lambda: {
            'policies': set(), 'objects': set(), 'rules': [],
        }))

        for r in qs.iterator(chunk_size=2000):
            groups = (r.per_device_mapping or {}).get('groups') or []
            if not groups:
                continue
            fw = adoms[r.tag.domain or '-'][r.tag.tag_name]
            fw['policies'].add(r.section)
            fw['objects'].update(groups)
            fw['rules'].append(f'{r.section}:ID:{r.rule_id}')

        table = []
        for domain, firewalls in sorted(adoms.items()):
            rows, adom_objects = [], set()
            for fw_name, d in sorted(firewalls.items()):
                adom_objects |= d['objects']
                rows.append({
                    'firewall': fw_name,
                    'policies': sorted(d['policies']),
                    'objects': sorted(d['objects']),
                    'rules': d['rules'],
                    'count_per_firewall': len(d['objects']),
                })
            table.append({
                'adom': domain,
                'rows': rows,
                'count_per_adom': len(adom_objects),   # objetos DISTINTOS del ADOM
            })
        return table

    # ------------------------------------------------------------------ excel
    def write_sheet(self, workbook, fmt, region, table):
        ws = workbook.add_worksheet(region.upper())

        for c, h in enumerate(HEADERS):
            ws.write(0, c, h, fmt['head'])
        ws.set_column('A:B', 28)
        ws.set_column('C:E', 45)
        ws.set_column('F:F', 20)
        ws.freeze_panes(1, 0)

        i = 1
        for adom in table:
            for row in adom['rows']:
                ws.write(i, 0, adom['adom'], fmt['cell'])
                ws.write(i, 1, row['firewall'], fmt['cell'])
                ws.write(i, 2, '\n'.join(row['policies']), fmt['cell'])
                ws.write(i, 3, '\n'.join(row['objects']), fmt['cell'])
                ws.write(i, 4, '\n'.join(row['rules']), fmt['cell'])
                ws.write(i, 5, row['count_per_firewall'], fmt['cell'])
                i += 1

            ws.write(i, 0, f"TOTAL {adom['adom']}", fmt['total'])
            for c in range(1, 5):
                ws.write_blank(i, c, None, fmt['total'])
            ws.write(i, 5, adom['count_per_adom'], fmt['total'])
            i += 1

        if i == 1:
            ws.write(1, 0, 'Sin objetos per-device-mapping', fmt['cell'])

    # ------------------------------------------------------------------ main
    def handle(self, *args, **options):
        regions = options['regions'] or REGIONS

        folder = Path(settings.MEDIA_ROOT) / FOLDER
        folder.mkdir(parents=True, exist_ok=True)
        final_path = folder / FILENAME
        tmp_path = final_path.with_suffix('.xlsx.tmp')

        workbook = xlsxwriter.Workbook(str(tmp_path), {'constant_memory': True})
        fmt = {
            'head': workbook.add_format({'bold': True, 'bg_color': '#DDDDDD', 'border': 1}),
            'cell': workbook.add_format({'text_wrap': True, 'valign': 'top', 'border': 1}),
            'total': workbook.add_format({'bold': True, 'bg_color': '#F2F2F2', 'border': 1}),
        }

        try:
            for region in regions:
                table = self.build_table(region)
                self.write_sheet(workbook, fmt, region, table)
                self.stdout.write(f'  {region}: {len(table)} ADOMs')
            workbook.close()
            os.replace(tmp_path, final_path)      # atómico: sustituye el antiguo de golpe
        except Exception:
            workbook.close()
            tmp_path.unlink(missing_ok=True)      # no dejamos basura ni pisamos el bueno
            raise

        self.stdout.write(self.style.SUCCESS(f'OK -> {final_path}'))
