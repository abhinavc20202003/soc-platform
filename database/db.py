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
"""

COLUMNS = (
    "timestamp", "source", "host", "source_ip",
    "username", "event_type", "severity", "message", "raw",
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


def count_events(db_path: Optional[Path] = None) -> int:
    with connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]