"""Runs all detection rules and stores the resulting alerts."""
import json
import logging

from database import db
from detection.network_rules import NETWORK_RULES
from detection.rules import ALL_RULES

log = logging.getLogger(__name__)

RULES = ALL_RULES + NETWORK_RULES


def run_rules(events: list) -> list:
    """Run every rule. One failing rule never stops the others."""
    alerts = []
    for rule in RULES:
        try:
            alerts.extend(rule(events))
        except Exception:
            log.exception("Rule %s failed", rule.__name__)
    alerts.sort(key=lambda a: a["first_seen"])
    return alerts


def run_detection(db_path=None) -> tuple:
    """Load events, run rules, save alerts. Returns (alerts, new_alerts_saved)."""
    db.init_db(db_path)
    events = db.fetch_all_events(db_path)
    alerts = run_rules(events)
    to_store = [{**a, "evidence": json.dumps(a["evidence"])} for a in alerts]
    new = db.insert_alerts(to_store, db_path)
    return alerts, new
