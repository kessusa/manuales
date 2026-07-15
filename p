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

HEADERS = ['ADOM', 'POLICIES', 'OBJECTS', 'RULES ID',
           'COUNT PER ADOM', 'COUNT PER FIREWALL']

CELL_LIMIT = 32000   # Excel corta en 32.767; dejamos margen


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
              .only('rule_id', 'per_device_mapping',
                    'tag__tag_name', 'tag__domain'))   # <-- AJUSTA rule_id

        # domain -> policy (tag_name) -> datos
        adoms = defaultdict(lambda: defaultdict(lambda: {
            'objects': set(), 'rules': [],
        }))

        for r in qs.iterator(chunk_size=2000):
            groups = (r.per_device_mapping or {}).get('groups') or []
            if not groups:
                continue
            policy = adoms[r.tag.domain or '-'][r.tag.tag_name]
            policy['objects'].update(groups)
            policy['rules'].append(f'{r.tag.tag_name}:ID:{r.rule_id}')

        table = []
        for domain, policies in sorted(adoms.items()):
            names = sorted(policies)

            all_objects, all_rules = set(), []
            for name in names:
                all_objects |= policies[name]['objects']
                all_rules.extend(policies[name]['rules'])

            table.append({
                'adom': domain,
                'policies': names,                # lista plana
                'objects': sorted(all_objects),   # lista plana, solo nombres de grupo
                'rules': all_rules,               # policy:ID:xxxx
                'count_per_adom': len(all_objects),
                'count_per_firewall': {n: len(policies[n]['objects']) for n in names},
            })
        return table

    # ------------------------------------------------------------------ excel
    @staticmethod
    def join(values):
        text = '\n'.join(str(v) for v in values)
        if len(text) > CELL_LIMIT:
            text = text[:CELL_LIMIT] + '\n... (truncado)'
        return text

    def write_sheet(self, workbook, fmt, region, table):
        ws = workbook.add_worksheet(region.upper())

        for c, h in enumerate(HEADERS):
            ws.write(0, c, h, fmt['head'])
        ws.set_column('A:A', 20)
        ws.set_column('B:D', 45)
        ws.set_column('E:E', 16)
        ws.set_column('F:F', 32)
        ws.freeze_panes(1, 0)

        for i, adom in enumerate(table, start=1):
            ws.write(i, 0, adom['adom'], fmt['cell'])
            ws.write(i, 1, self.join(adom['policies']), fmt['cell'])
            ws.write(i, 2, self.join(adom['objects']), fmt['cell'])
            ws.write(i, 3, self.join(adom['rules']), fmt['cell'])
            ws.write(i, 4, adom['count_per_adom'], fmt['total'])
            ws.write(i, 5, self.join(f'{fw}: {n}' for fw, n
                                     in adom['count_per_firewall'].items()), fmt['cell'])

        if not table:
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
            'total': workbook.add_format({'bold': True, 'bg_color': '#F2F2F2',
                                          'border': 1, 'valign': 'top'}),
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
            tmp_path.unlink(missing_ok=True)      # ni basura ni pisar el bueno
            raise

        self.stdout.write(self.style.SUCCESS(f'OK -> {final_path}'))
