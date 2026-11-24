"""Builds the data used by both the CSV and PDF reports."""
from datetime import datetime, timezone

from database import db

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def build_report_data(db_path=None) -> dict:
    stats = db.get_stats(db_path)
    alerts = db.fetch_alerts(500, db_path)
    incidents = db.list_incidents(limit=500, db_path=db_path)

    by_sev = {row["severity"]: row["n"] for row in stats["alerts_by_severity"]}
    severity_counts = {s: by_sev.get(s, 0) for s in SEVERITY_ORDER}

    status_counts = {}
    for inc in incidents:
        status_counts[inc["status"]] = status_counts.get(inc["status"], 0) + 1

    rule_counts = {}
    for a in alerts:
        rule_counts[a["name"]] = rule_counts.get(a["name"], 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda kv: -kv[1])[:8]

    return {
        "generated_at": datetime.now(timezone.utc),
        "stats": stats,
        "alerts": alerts,
        "incidents": incidents,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "top_rules": top_rules,
        "open_incidents": sum(1 for i in incidents if i["status"] in ("open", "investigating")),
    }
