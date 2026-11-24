"""PDF executive report, built with ReportLab.

Layout: title page + executive summary, severity/status charts, top rules,
incident table, and recommendations. Built entirely from report_data so it
never queries the database directly -- one source of truth shared with the CSV."""
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

NAVY = colors.HexColor("#0a1128")
PANEL = colors.HexColor("#111c3d")
ACCENT = colors.HexColor("#3b82f6")
SEV_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#22c55e"),
}
RECOMMENDATIONS = [
    "Block or rate-limit the source IPs behind brute-force and port-scan alerts "
    "at the perimeter firewall.",
    "Enforce multi-factor authentication on all externally reachable login services.",
    "Review and resolve all open critical and high-severity incidents before closing this period.",
    "Treat ML anomaly predictions as investigation leads, not confirmed incidents, "
    "and review them alongside rule-based alerts.",
    "Re-run detection regularly (or automate it) so new attacks are caught promptly.",
]


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("ReportTitle", parent=ss["Title"], textColor=NAVY, fontSize=26))
    ss.add(ParagraphStyle("SectionHeading", parent=ss["Heading1"], textColor=NAVY,
                          spaceBefore=18, spaceAfter=8))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], fontSize=10, leading=14))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=8, textColor=colors.grey))
    return ss


def _severity_pie(counts: dict) -> Drawing:
    data = [n for n in counts.values() if n > 0] or [1]
    labels = [f"{s} ({n})" for s, n in counts.items() if n > 0] or ["no alerts"]
    d = Drawing(260, 160)
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 10, 10, 140, 140
    pie.data = data
    pie.labels = labels
    pie.slices.strokeWidth = 1
    sev_names = [s for s, n in counts.items() if n > 0] or ["low"]
    for i, sev in enumerate(sev_names):
        pie.slices[i].fillColor = SEV_COLORS.get(sev, colors.grey)
    d.add(pie)
    return d


def _rules_bar_chart(top_rules: list) -> Drawing:
    if not top_rules:
        d = Drawing(400, 40)
        d.add(String(0, 15, "No alerts recorded in this period.", fontSize=10))
        return d
    names = [n[:28] for n, _ in top_rules]
    values = [c for _, c in top_rules]
    d = Drawing(440, 200)
    chart = VerticalBarChart()
    chart.x, chart.y = 60, 30
    chart.width, chart.height = 360, 150
    chart.data = [values]
    chart.categoryAxis.categoryNames = names
    chart.categoryAxis.labels.angle = 30
    chart.categoryAxis.labels.dx = -8
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.bars[0].fillColor = ACCENT
    d.add(chart)
    return d


def _alert_table(alerts: list, styles) -> Table:
    header = ["Severity", "Rule", "Source IP", "User", "Events", "First seen (UTC)"]
    rows = [header]
    for a in alerts[:40]:
        rows.append([
            a["severity"].upper(), f"{a['rule_id']} {a['name']}"[:42],
            a.get("source_ip") or "-", a.get("username") or "-",
            str(a["event_count"]), str(a["first_seen"]).replace("T", " ")[:19],
        ])
    table = Table(rows, repeatRows=1, colWidths=[2.0*cm, 6.2*cm, 2.6*cm, 2.2*cm, 1.6*cm, 3.4*cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, a in enumerate(alerts[:40], start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS.get(a["severity"], colors.black)))
    table.setStyle(TableStyle(style))
    return table


def _incident_table(incidents: list, styles) -> Table:
    header = ["Incident ID", "Title", "Severity", "Status", "Detected (UTC)"]
    rows = [header]
    for inc in incidents[:40]:
        rows.append([
            inc["incident_id"], inc["title"][:38], inc["severity"].upper(),
            inc["status"], str(inc["detected_at"]).replace("T", " ")[:19],
        ])
    table = Table(rows, repeatRows=1, colWidths=[2.6*cm, 6.5*cm, 2.2*cm, 2.8*cm, 3.9*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
    ]))
    return table


def build_pdf_report(report_data: dict, out_path) -> None:
    styles = _styles()
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        topMargin=2*cm, bottomMargin=2*cm, leftMargin=2*cm, rightMargin=2*cm,
    )
    stats, sev, status = report_data["stats"], report_data["severity_counts"], report_data["status_counts"]
    story = []

    # --- Title page / executive summary ---
    story.append(Paragraph("AI-Powered Mini SOC", styles["ReportTitle"]))
    story.append(Paragraph("Security Operations Report", styles["Heading2"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated {report_data['generated_at']:%Y-%m-%d %H:%M} UTC", styles["Small"]))
    story.append(Spacer(1, 16))

    summary = (
        f"During the period covered by this report, the platform processed "
        f"<b>{stats['total_events']}</b> security events and raised "
        f"<b>{stats['total_alerts']}</b> rule-based alerts, of which "
        f"<b>{sev['critical']}</b> were classified critical and <b>{sev['high']}</b> high "
        f"severity. <b>{report_data['open_incidents']}</b> incidents remain open or under "
        f"investigation. <b>{stats['failed_logins']}</b> failed login attempts were recorded "
        f"across all monitored sources."
    )
    story.append(Paragraph(summary, styles["Body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Alerts by Severity", styles["SectionHeading"]))
    story.append(_severity_pie(sev))

    story.append(Paragraph("Top Triggered Detections", styles["SectionHeading"]))
    story.append(_rules_bar_chart(report_data["top_rules"]))

    # --- Incidents ---
    story.append(PageBreak())
    story.append(Paragraph("Security Incidents", styles["SectionHeading"]))
    if report_data["incidents"]:
        story.append(Paragraph(
            f"{len(report_data['incidents'])} incident(s) on record "
            f"(showing up to 40 below, most recent first).", styles["Body"]))
        story.append(Spacer(1, 8))
        story.append(_incident_table(report_data["incidents"], styles))
    else:
        story.append(Paragraph("No incidents have been created yet.", styles["Body"]))

    # --- Alert evidence ---
    story.append(PageBreak())
    story.append(Paragraph("Detection Evidence", styles["SectionHeading"]))
    if report_data["alerts"]:
        story.append(Paragraph(
            f"{len(report_data['alerts'])} alert(s) on record "
            f"(showing up to 40 below, most recent first).", styles["Body"]))
        story.append(Spacer(1, 8))
        story.append(_alert_table(report_data["alerts"], styles))
    else:
        story.append(Paragraph("No alerts have been recorded yet.", styles["Body"]))

    # --- Recommendations ---
    story.append(PageBreak())
    story.append(Paragraph("Recommendations", styles["SectionHeading"]))
    for rec in RECOMMENDATIONS:
        story.append(Paragraph(f"&bull; {rec}", styles["Body"]))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "This report was generated automatically by the Mini SOC platform. "
        "ML-based anomaly predictions are statistical leads and require analyst "
        "review; they are not included as confirmed incidents in this report.",
        styles["Small"],
    ))

    doc.build(story)
