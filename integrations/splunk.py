"""Splunk HTTP Event Collector (HEC) integration.

Sends events, rule alerts and ML anomalies to Splunk. A checkpoint file records
the last row sent from each table, so re-running never sends duplicates."""
import json
import logging
from datetime import datetime
from pathlib import Path

import requests
import urllib3

import config
from database import db

log = logging.getLogger(__name__)

BATCH_SIZE = 100
TIMEOUT_SECONDS = 10
STATE_FILE = config.BASE_DIR / "logs" / "splunk_state.json"

# table -> (Splunk 'source' label, column holding the event time)
STREAMS = {
    "events": ("mini-soc:event", "timestamp"),
    "alerts": ("mini-soc:alert", "first_seen"),
    "anomalies": ("mini-soc:anomaly", "window_start"),
}
JSON_FIELDS = ("evidence", "features")


class SplunkError(Exception):
    """Raised when Splunk can't be reached or rejects the data."""


def is_configured() -> bool:
    return bool(config.SPLUNK_HEC_URL and config.SPLUNK_HEC_TOKEN)


def _base_url() -> str:
    return config.SPLUNK_HEC_URL.rstrip("/")


def _headers() -> dict:
    return {"Authorization": f"Splunk {config.SPLUNK_HEC_TOKEN}"}


def _verify() -> bool:
    verify = config.SPLUNK_VERIFY_SSL
    if not verify:  # lab only: Splunk's default certificate is self-signed
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return verify


def format_event(table: str, row: dict) -> dict:
    """Wrap a database row in the HEC envelope."""
    source, time_field = STREAMS[table]
    body = dict(row)
    # 'source' is a reserved Splunk field, so our own log source is renamed.
    if "source" in body:
        body["log_source"] = body.pop("source")
    for field in JSON_FIELDS:  # stored as JSON text in SQLite
        if isinstance(body.get(field), str):
            try:
                body[field] = json.loads(body[field])
            except json.JSONDecodeError:
                pass
    return {
        "time": datetime.fromisoformat(row[time_field]).timestamp(),
        "host": row.get("host") or "mini-soc",
        "source": source,
        "sourcetype": "_json",
        "index": config.SPLUNK_INDEX,
        "event": body,
    }


def send_batch(payloads: list) -> None:
    if not is_configured():
        raise SplunkError("Splunk HEC is not configured (set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env)")
    body = "\n".join(json.dumps(p) for p in payloads)
    try:
        resp = requests.post(
            f"{_base_url()}/services/collector/event",
            data=body, headers=_headers(),
            timeout=TIMEOUT_SECONDS, verify=_verify(),
        )
    except requests.RequestException as exc:
        raise SplunkError(f"Could not reach Splunk HEC: {str(exc)[:200]}") from None
    if resp.status_code != 200:
        raise SplunkError(f"Splunk HEC rejected the data (HTTP {resp.status_code}): {resp.text[:200]}")
    try:
        code = resp.json().get("code")
    except ValueError:
        code = None
    if code not in (0, None):
        raise SplunkError(f"Splunk HEC returned error code {code}: {resp.text[:200]}")


def health_check() -> bool:
    try:
        resp = requests.get(
            f"{_base_url()}/services/collector/health",
            headers=_headers(), timeout=TIMEOUT_SECONDS, verify=_verify(),
        )
    except requests.RequestException:
        return False
    return resp.status_code == 200


# ---------------------------------------------------------------- checkpoint
def _load_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return {k: int(data.get(k, 0)) for k in STREAMS}
    except (OSError, ValueError, TypeError):
        return {k: 0 for k in STREAMS}


def _save_state(state: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state))


def _max_id(table: str, db_path) -> int:
    if table not in STREAMS:
        raise ValueError(table)
    with db.connection(db_path) as conn:
        return conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]


def _fetch_after(table: str, last_id: int, limit: int, db_path) -> list:
    if table not in STREAMS:  # table names come only from the fixed STREAMS dict
        raise ValueError(table)
    with db.connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def sync(db_path=None, state_file: Path = STATE_FILE) -> dict:
    """Send everything not yet sent. Returns rows sent per table.
    The checkpoint only advances after Splunk accepts a batch."""
    db.init_db(db_path)
    state = _load_state(state_file)
    sent = {}
    for table in STREAMS:
        if state[table] > _max_id(table, db_path):  # database was recreated
            state[table] = 0
        sent[table] = 0
        while True:
            rows = _fetch_after(table, state[table], BATCH_SIZE, db_path)
            if not rows:
                break
            send_batch([format_event(table, r) for r in rows])
            state[table] = rows[-1]["id"]
            _save_state(state, state_file)
            sent[table] += len(rows)
    return sent
