import io
from collections import defaultdict
from reportlab.lib.pagesizes import A2, landscape
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Flowable
)
from reportlab.pdfbase.pdfmetrics import stringWidth
# Sum, PlayflowsTagAudit, TITLE_STYLE, BASE_STYLE, TABLE_STYLE, agg_fields,
# pie_chart_with_legend, create_bar_graph, region_chart_data -> tus imports/definiciones actuales


class VerticalText(Flowable):
    """Dibuja el texto de cabecera girado 90° para columnas estrechas."""
    def __init__(self, text, font_name="Helvetica-Bold", font_size=7):
        super().__init__()
        self.text = str(text)
        self.font_name = font_name
        self.font_size = font_size

    def wrap(self, avail_w, avail_h):
        self.height = stringWidth(self.text, self.font_name, self.font_size) + 6
        self.width = self.font_size * 1.3
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFont(self.font_name, self.font_size)
        c.rotate(90)
        c.drawString(3, -self.font_size * 0.75, self.text)  # ajusta estos 2 números si queda descentrado
        c.restoreState()


# Overrides compactos: se aplican ENCIMA de tu TABLE_STYLE (setStyle es acumulativo)
COMPACT_OVERRIDES = TableStyle([
    ("FONTSIZE",      (0, 0), (-1, -1), 7),
    ("LEFTPADDING",   (0, 0), (-1, -1), 2),
    ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
    ("TOPPADDING",    (0, 0), (-1, -1), 1),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ("VALIGN",        (0, 0), (-1, 0), "BOTTOM"),    # fila de cabeceras
    ("VALIGN",        (0, 1), (-1, -1), "MIDDLE"),   # cuerpo
    ("ALIGN",         (1, 1), (-1, -1), "CENTER"),   # números centrados
])

HEADER_LABELS = [
    "Firewall Name", "SLA", "Risk Level", "Not Logged", "Expired Rules",
    "Wide Rules", "Disabled Rules", "Service=TCP-80", "Action=Encrypt",
    "No Hits", "Last Hits>12 months", "Comment=Null", "Forbidden Protocols",
    "Restricted Protocols", "Specific Version", "Forbidden with rk or serf",
    "Rules Need IPS", "Rules With IPS", "Rules Need APP Control",
    "Rules Have APP Control", "Rules Have Per Device Mapping", "Total",
]


def generate_firewall_pdf_report(region_list):
    # ===== BLOQUE DE CONSULTA: tu código actual, reproducido de las capturas =====
    qs_rules_stat = {r: [0] * len(agg_fields) for r in region_list}

    sum_annotations = {
        f"count_{field}": Sum(field) for field in agg_fields
    }
    sum_annotations["count_all_forbidden_protocol"] = (
        Sum("forbidden_internet_fw") + Sum("forbidden_internal_fw")  # <- esta línea salía cortada, verifica el 2º Sum
    )

    tag_audit_agg_qs = (
        PlayflowsTagAudit.objects
        .filter(tag__region__in=region_list)
        .values("tag__region")
        .annotate(**sum_annotations)
        .order_by("tag__region")
    )

    for row in tag_audit_agg_qs:
        region_key = row["tag__region"]
        qs_rules_stat[region_key] = [row[f"count_{field}"] for field in agg_fields]

    detail_qs = (
        PlayflowsTagAudit.objects
        .filter(tag__region__in=region_list)
        .select_related("tag")
        .only(
            "tag__tag_name", "wideness", "disabled", "not_logged",
            "expired_rules", "tcp_80", "no_comment", "no_hits", "last_hits",
            "action_encrypt", "forbidden_internal_fw", "forbidden_internet_fw",
            "forbidden_specific_version", "forbidden_with_rk_or_serf",
            "rules_needs_ips", "rules_needs_and_have_ips", "rules_needs_app_control",
            "rules_needs_and_have_app_control", "rules_have_per_device_mapping",
            "tag__sla", "tag__risk_level", "total_rules",
        )
    )

    detail_by_region = defaultdict(list)
    for audit in detail_qs:
        detail_by_region[audit.tag.region.lower()].append(audit)
    # ===== FIN BLOQUE DE CONSULTA =====

    buffer = io.BytesIO()
    MARGIN = 0.7 * inch

    doc = SimpleDocTemplate(
        buffer,
        title="[Firewall] Audit Report",
        pagesize=landscape(A2),
        rightMargin=MARGIN,
        leftMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
    )

    story = []
    story.append(Paragraph("[Firewall] Audit Report", TITLE_STYLE))
    story.append(HRFlowable(color=colors.darkgrey, spaceBefore=4, spaceAfter=4))
    story.append(pie_chart_with_legend(region_chart_data))
    story.append(Spacer(1, 0.8 * inch))
    story.append(create_bar_graph(qs_rules_stat, region_list))
    story.append(Spacer(1, 0.3 * inch))

    # --- anchos: nombre ancho, resto repartido (las cabeceras van en vertical) ---
    printable_width = landscape(A2)[0] - 2 * MARGIN
    name_w = printable_width * 0.18
    num_w = (printable_width - name_w) / (len(HEADER_LABELS) - 1)
    col_widths = [name_w] + [num_w] * (len(HEADER_LABELS) - 1)

    # --- cabecera: primera columna horizontal, las numéricas en vertical ---
    header_row = [HEADER_LABELS[0]] + [VerticalText(t) for t in HEADER_LABELS[1:]]

    for env in region_list:
        story.append(Paragraph(f"Region: {env.upper()}", BASE_STYLE))

        rows = [header_row] + [
            [
                audit.tag.tag_name,
                audit.tag.sla,
                audit.tag.risk_level,
                audit.not_logged,
                audit.expired_rules,
                audit.wideness,
                audit.disabled,
                audit.tcp_80,
                audit.action_encrypt,
                audit.no_hits,
                audit.last_hits,
                audit.no_comment,
                audit.forbidden_internal_fw,
                audit.forbidden_internet_fw,
                audit.forbidden_specific_version,
                audit.forbidden_with_rk_or_serf,
                audit.rules_needs_ips,
                audit.rules_needs_and_have_ips,
                audit.rules_needs_app_control,
                audit.rules_needs_and_have_app_control,
                audit.rules_have_per_device_mapping,
                audit.total_rules,
            ]
            for audit in detail_by_region.get(env, [])
        ]

        if len(rows) == 1:
            rows.append(["—"] * len(HEADER_LABELS))

        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TABLE_STYLE)        # tu estilo de siempre
        tbl.setStyle(COMPACT_OVERRIDES)  # ajustes compactos encima

        story.append(tbl)
        story.append(Spacer(1, 0.2 * inch))
        story.append(HRFlowable(color=colors.darkgrey, spaceBefore=4, spaceAfter=4))
        story.append(Spacer(1, 0.2 * inch))

    doc.build(story)
    buffer.seek(0)
    return buffer
