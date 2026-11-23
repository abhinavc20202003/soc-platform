"""Incident response: turns alerts into tracked incidents."""
import json
from typing import Optional

from database import db
from incident_response.playbooks import get_playbook


def build_incident(alert: dict) -> dict:
    """Create an incident record (not yet saved) from an alert row."""
    pb = get_playbook(alert["name"])
    parts = []
    if alert.get("username"):
        parts.append(f"user {alert['username']}")
    if alert.get("host"):
        parts.append(f"host {alert['host']}")
    explanation = (
        f"{alert.get('description') or ''} Detected by rule {alert['rule_id']} "
        f"({alert['name']}). MITRE ATT&CK: {alert.get('mitre') or 'n/a'}."
    ).strip()
    return {
        "incident_id": f"PENDING-{alert['id']}",  # replaced by INC-YYYY-NNNN on insert
        "alert_id": alert["id"],
        "title": alert["name"],
        "classification": pb["classification"],
        "severity": alert["severity"],
        "source_ip": alert.get("source_ip"),
        "affected": ", ".join(parts) or "unknown",
        "detected_at": alert["first_seen"],
        "explanation": explanation,
        "containment": json.dumps(pb["containment"]),
        "checklist": json.dumps([{"item": s, "done": False} for s in pb["checklist"]]),
    }


def generate_incidents(db_path=None) -> int:
    """Create an incident for every alert that doesn't have one. Safe to re-run."""
    db.init_db(db_path)
    created = 0
    for alert in db.alerts_without_incident(db_path):
        if db.insert_incident(build_incident(alert), db_path) is not None:
            created += 1
    return created


def _decode(row: dict) -> dict:
    row = dict(row)
    row["containment"] = json.loads(row.get("containment") or "[]")
    row["checklist"] = json.loads(row.get("checklist") or "[]")
    return row


def list_incidents(status=None, severity=None, limit=100, db_path=None) -> list:
    return [_decode(r) for r in db.list_incidents(status, severity, limit, db_path)]


def get_incident_detail(incident_id: str, db_path=None) -> Optional[dict]:
    row = db.get_incident(incident_id, db_path)
    if row is None:
        return None
    incident = _decode(row)
    alert = db.get_alert(incident["alert_id"], db_path)
    evidence = []
    if alert:
        try:
            ids = json.loads(alert.get("evidence") or "[]")
        except json.JSONDecodeError:
            ids = []
        evidence = db.fetch_events_by_ids(ids, db_path)
        incident["alert"] = {
            k: alert.get(k)
            for k in ("rule_id", "name", "detection_type", "mitre",
                      "first_seen", "last_seen", "event_count")
        }
    else:
        incident["alert"] = None
    incident["evidence_events"] = evidence
    return incident


def update_incident(incident_id: str, status=None, notes=None,
                    checklist_done=None, db_path=None) -> Optional[dict]:
    """Update status, notes and checklist ticks. Returns the updated incident,
    None if it doesn't exist. Raises ValueError on invalid input."""
    row = db.get_incident(incident_id, db_path)
    if row is None:
        return None
    checklist_json = None
    if checklist_done is not None:
        items = json.loads(row["checklist"] or "[]")
        if len(checklist_done) != len(items):
            raise ValueError(f"checklist_done must have {len(items)} entries")
        for item, done in zip(items, checklist_done):
            item["done"] = bool(done)  # only the done flag is editable, never the text
        checklist_json = json.dumps(items)
    db.update_incident(incident_id, status=status, notes=notes,
                       checklist=checklist_json, db_path=db_path)
    return get_incident_detail(incident_id, db_path)