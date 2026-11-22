from database import db
from parsers import linux_auth


def test_insert_and_fetch(tmp_path):
    db_file = tmp_path / "test.db"
    db.init_db(db_file)
    ev = linux_auth.parse_line(
        "Nov 22 10:00:01 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2",
        year=2026,
    )
    db.insert_event(ev, db_file)
    assert db.count_events(db_file) == 1
    rows = db.fetch_events(10, db_file)
    assert rows[0]["source_ip"] == "203.0.113.50"


def test_sql_injection_is_stored_as_data(tmp_path):
    db_file = tmp_path / "test.db"
    db.init_db(db_file)
    ev = linux_auth.parse_line(
        "Nov 22 10:00:01 web01 sshd[1]: Failed password for x'; DROP TABLE events;-- from 203.0.113.50 port 1 ssh2",
        year=2026,
    )
    db.insert_event(ev, db_file)
    assert db.count_events(db_file) == 1