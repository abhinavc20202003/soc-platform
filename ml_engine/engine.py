"""Runs ML detection over stored events and saves anomalies."""
import json

from database import db
from ml_engine.anomaly import detect


def run_ml(db_path=None) -> tuple:
    """Returns (anomalies, new_anomalies_saved)."""
    db.init_db(db_path)
    events = db.fetch_all_events(db_path)
    anomalies = detect(events)
    rows = [{**a, "features": json.dumps(a["details"])} for a in anomalies]
    new = db.insert_anomalies(rows, db_path)
    return anomalies, new