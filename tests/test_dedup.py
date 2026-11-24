import sqlite3
from datetime import datetime, timezone

import config
import ingest
from database import db
from parsers.schema import make_event

BASE = datetime(2026, 11, 24, 9, 0, 0, tzinfo=timezone.utc)


def test_insert_event_twice_is_idempotent(tmp_path):
    f = tmp_path / "one.db"
    db.init_db(f)
    ev = make_event(timestamp=BASE, source="t", event_type="other",
                    severity="low", message="hello")
    first_id = db.insert_event(ev, f)
    second_id = db.insert_event(ev, f)
    assert first_id is not None
    assert second_id is None
    assert db.count_events(f) == 1


def test_insert_events_skips_duplicates_within_one_call(tmp_path):
    f = tmp_path / "batch.db"
    db.init_db(f)
    ev = make_event(timestamp=BASE, source="t", event_type="other",
                    severity="low", message="dup")
    new = db.insert_events([ev, ev, ev], f)
    assert new == 1
    assert db.count_events(f) == 1


def test_reingesting_same_file_twice_adds_nothing_new(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "re.db")
    path = config.SAMPLE_LOG_DIR / "linux_auth.log"
    first = ingest.ingest_file("linux", path)
    second = ingest.ingest_file("linux", path)
    assert first == 9
    assert second == 0
    assert db.count_events() == 9


def test_distinct_similar_events_are_kept_separate(tmp_path):
    f = tmp_path / "distinct.db"
    db.init_db(f)
    a = make_event(timestamp=BASE, source="t", event_type="network_connection",
                   source_ip="1.2.3.4", dest_ip="5.6.7.8", dest_port=80, raw="probe 80")
    b = make_event(timestamp=BASE, source="t", event_type="network_connection",
                   source_ip="1.2.3.4", dest_ip="5.6.7.8", dest_port=81, raw="probe 81")
    new = db.insert_events([a, b], f)
    assert new == 2
    assert db.count_events(f) == 2


def test_migration_deduplicates_an_old_database_with_duplicates(tmp_path):
    f = tmp_path / "dirty.db"
    conn = sqlite3.connect(f)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "source TEXT NOT NULL, host TEXT, source_ip TEXT, username TEXT, "
        "event_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT, raw TEXT)"
    )
    row = ("2026-11-22T10:00:00+00:00", "t", None, "9.9.9.9", None, "other", "low", "dup", "dup-raw")
    conn.executemany(
        "INSERT INTO events (timestamp, source, host, source_ip, username, event_type, "
        "severity, message, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [row, row, row],
    )
    conn.commit()
    conn.close()

    db.init_db(f)  # the migration runs here, automatically
    assert db.count_events(f) == 1
    with db.connection(f) as c:
        indexes = {r["name"] for r in c.execute("PRAGMA index_list(events)")}
    assert "idx_events_content_hash" in indexes


def test_migration_is_safe_on_a_duplicate_free_database(tmp_path):
    f = tmp_path / "clean.db"
    db.init_db(f)
    db.insert_events([
        make_event(timestamp=BASE, source="t", event_type="other", severity="low", message="a"),
        make_event(timestamp=BASE, source="t", event_type="other", severity="low", message="b"),
    ], f)
    db.init_db(f)  # re-running the migration must not drop legitimate rows
    assert db.count_events(f) == 2
