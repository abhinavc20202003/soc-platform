"""SQLite database layer for the Mini SOC platform."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    host        TEXT,
    source_ip   TEXT,
    username    TEXT,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint    TEXT NOT NULL UNIQUE,
    rule_id        TEXT NOT NULL,
    name           TEXT NOT NULL,
    detection_type TEXT NOT NULL DEFAULT 'rule',
    severity       TEXT NOT NULL,
    source_ip      TEXT,
    username       TEXT,
    host           TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    event_count    INTEGER NOT NULL,
    description    TEXT,
    mitre          TEXT,
    evidence       TEXT,
    status         TEXT NOT NULL DEFAULT 'open',
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id    TEXT NOT NULL UNIQUE,
    alert_id       INTEGER NOT NULL UNIQUE,
    title          TEXT NOT NULL,
    classification TEXT NOT NULL,
    severity       TEXT NOT NULL,
    source_ip      TEXT,
    affected       TEXT,
    detected_at    TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open',
    explanation    TEXT,
    containment    TEXT,
    checklist      TEXT,
    notes          TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS anomalies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint    TEXT NOT NULL UNIQUE,
    detection_type TEXT NOT NULL DEFAULT 'ml_anomaly',
    method         TEXT NOT NULL,
    kind           TEXT NOT NULL,
    entity         TEXT,
    source_ip      TEXT,
    username       TEXT,
    window_start   TEXT NOT NULL,
    score          REAL,
    severity       TEXT NOT NULL,
    description    TEXT,
    features       TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_anomalies_window ON anomalies(window_start);
"""
COLUMNS = (
    "timestamp", "source", "host", "source_ip",
    "username", "event_type", "severity", "message", "raw",
)

ALERT_COLUMNS = (
    "fingerprint", "rule_id", "name", "detection_type", "severity",
    "source_ip", "username", "host", "first_seen", "last_seen",
    "event_count", "description", "mitre", "evidence", "status",
)


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def connection(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> None:
    with connection(db_path) as conn:
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------- events
def insert_event(event: dict, db_path: Optional[Path] = None) -> int:
    # Parameterized query: values are never concatenated into SQL.
    sql = (
        f"INSERT INTO events ({', '.join(COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in COLUMNS)})"
    )
    with connection(db_path) as conn:
        cur = conn.execute(sql, tuple(event.get(c) for c in COLUMNS))
        return cur.lastrowid


def insert_events(events: list, db_path: Optional[Path] = None) -> int:
    sql = (
        f"INSERT INTO events ({', '.join(COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in COLUMNS)})"
    )
    rows = [tuple(e.get(c) for c in COLUMNS) for e in events]
    with connection(db_path) as conn:
        conn.executemany(sql, rows)
    return len(rows)


def fetch_events(limit: int = 100, db_path: Optional[Path] = None) -> list:
    limit = max(1, min(int(limit), 1000))
    with connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def fetch_all_events(db_path: Optional[Path] = None) -> list:
    """All events, oldest first. Used by the detection engine."""
    with connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC, id ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def count_events(db_path: Optional[Path] = None) -> int:
    with connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


# ---------------------------------------------------------------- alerts
def insert_alerts(alerts: list, db_path: Optional[Path] = None) -> int:
    """Insert alerts, silently skipping duplicates. Returns number of NEW rows."""
    sql = (
        f"INSERT OR IGNORE INTO alerts ({', '.join(ALERT_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in ALERT_COLUMNS)})"
    )
    rows = [tuple(a.get(c) for c in ALERT_COLUMNS) for a in alerts]
    with connection(db_path) as conn:
        before = conn.total_changes
        conn.executemany(sql, rows)
        return conn.total_changes - before


def fetch_alerts(limit: int = 100, db_path: Optional[Path] = None) -> list:
    limit = max(1, min(int(limit), 1000))
    with connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY first_seen DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def count_alerts(db_path: Optional[Path] = None) -> int:
    with connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

# ---------------------------------------------------------------- dashboard queries
def search_events(event_type=None, severity=None, source_ip=None,
                  limit: int = 100, db_path: Optional[Path] = None) -> list:
    """Filtered event search. Filters are bound parameters, never concatenated."""
    clauses, params = [], []
    for column, value in (("event_type", event_type), ("severity", severity),
                          ("source_ip", source_ip)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit), 500)))
    with connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC, id DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats(db_path: Optional[Path] = None) -> dict:
    with connection(db_path) as conn:
        def one(sql):
            return conn.execute(sql).fetchone()[0]

        def many(sql):
            return [dict(r) for r in conn.execute(sql).fetchall()]

        return {
            "total_events": one("SELECT COUNT(*) FROM events"),
            "failed_logins": one("SELECT COUNT(*) FROM events WHERE event_type='login_failed'"),
            "total_alerts": one("SELECT COUNT(*) FROM alerts"),
            "alerts_by_severity": many(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"),
            "events_by_type": many(
                "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"),
            "top_ips": many(
                "SELECT source_ip, COUNT(*) AS n FROM events "
                "WHERE event_type='login_failed' AND source_ip IS NOT NULL "
                "GROUP BY source_ip ORDER BY n DESC LIMIT 5"),
            "timeline": many(
                "SELECT substr(timestamp,1,13) AS hour, COUNT(*) AS n "
                "FROM events GROUP BY hour ORDER BY hour"),
        }
# ---------------------------------------------------------------- incidents
INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "false_positive")

INCIDENT_COLUMNS = (
    "incident_id", "alert_id", "title", "classification", "severity",
    "source_ip", "affected", "detected_at", "explanation", "containment", "checklist",
)


def alerts_without_incident(db_path: Optional[Path] = None) -> list:
    with connection(db_path) as conn:
        rows = conn.execute(
            "SELECT a.* FROM alerts a LEFT JOIN incidents i ON i.alert_id = a.id "
            "WHERE i.id IS NULL ORDER BY a.first_seen ASC, a.id ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def insert_incident(incident: dict, db_path: Optional[Path] = None) -> Optional[int]:
    """Insert an incident (one per alert). Returns the row id, or None if it already exists."""
    sql = (
        f"INSERT OR IGNORE INTO incidents ({', '.join(INCIDENT_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in INCIDENT_COLUMNS)})"
    )
    with connection(db_path) as conn:
        cur = conn.execute(sql, tuple(incident.get(c) for c in INCIDENT_COLUMNS))
        if cur.rowcount == 0:
            return None
        row_id = cur.lastrowid
        year = str(incident["detected_at"])[:4]
        conn.execute(
            "UPDATE incidents SET incident_id = ? WHERE id = ?",
            (f"INC-{year}-{row_id:04d}", row_id),
        )
        return row_id


def list_incidents(status=None, severity=None, limit: int = 100,
                   db_path: Optional[Path] = None) -> list:
    clauses, params = [], []
    for column, value in (("status", status), ("severity", severity)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit), 500)))
    with connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM incidents {where} ORDER BY detected_at DESC, id DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_incident(incident_id: str, db_path: Optional[Path] = None) -> Optional[dict]:
    with connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    return dict(row) if row else None


def update_incident(incident_id: str, status=None, notes=None, checklist=None,
                    db_path: Optional[Path] = None) -> bool:
    """Update status, notes and/or checklist. Column names are fixed literals;
    all values are bound parameters."""
    if status is not None and status not in INCIDENT_STATUSES:
        raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
    sets, params = [], []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if notes is not None:
        sets.append("notes = ?")
        params.append(notes)
    if checklist is not None:
        sets.append("checklist = ?")
        params.append(checklist)
    if not sets:
        return False
    sets.append("updated_at = CURRENT_TIMESTAMP")
    params.append(incident_id)
    with connection(db_path) as conn:
        cur = conn.execute(
            f"UPDATE incidents SET {', '.join(sets)} WHERE incident_id = ?", params
        )
        return cur.rowcount > 0


def get_alert(alert_id: int, db_path: Optional[Path] = None) -> Optional[dict]:
    with connection(db_path) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def fetch_events_by_ids(ids, db_path: Optional[Path] = None) -> list:
    ids = [int(i) for i in ids][:200]
    if not ids:
        return []
    marks = ", ".join("?" for _ in ids)
    with connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY timestamp ASC, id ASC",
            ids,
        ).fetchall()
    return [dict(r) for r in rows]
# ---------------------------------------------------------------- ML anomalies
ANOMALY_COLUMNS = (
    "fingerprint", "method", "kind", "entity", "source_ip", "username",
    "window_start", "score", "severity", "description", "features",
)


def insert_anomalies(anomalies: list, db_path: Optional[Path] = None) -> int:
    """Insert ML anomalies, skipping duplicates. Returns number of NEW rows."""
    sql = (
        f"INSERT OR IGNORE INTO anomalies ({', '.join(ANOMALY_COLUMNS)}) "
        f"VALUES ({', '.join('?' for _ in ANOMALY_COLUMNS)})"
    )
    rows = [tuple(a.get(c) for c in ANOMALY_COLUMNS) for a in anomalies]
    with connection(db_path) as conn:
        before = conn.total_changes
        conn.executemany(sql, rows)
        return conn.total_changes - before


def fetch_anomalies(limit: int = 100, db_path: Optional[Path] = None) -> list:
    limit = max(1, min(int(limit), 500))
    with connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM anomalies ORDER BY window_start DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def count_anomalies(db_path: Optional[Path] = None) -> int:
    with connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]