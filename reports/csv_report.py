"""CSV export: one row per alert, flat and spreadsheet-friendly."""
import csv
import io

FIELDS = (
    "rule_id", "name", "detection_type", "severity", "source_ip", "username",
    "host", "first_seen", "last_seen", "event_count", "status", "mitre", "description",
)


def build_alerts_csv(report_data: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for alert in report_data["alerts"]:
        writer.writerow(alert)
    return buf.getvalue()
