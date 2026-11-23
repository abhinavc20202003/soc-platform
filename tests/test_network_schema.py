import json
import sqlite3
from datetime import datetime, timezone

from database import db
from parsers import windows_events
from parsers.schema import make_event

BASE = dict(
    timestamp=datetime(2026, 11, 23, 9, 0, 0, tzinfo=timezone.utc),
    source="test",
    event_type="network_connection",
)


def test_make_event_validates_port_and_dest_ip():
    ok = make_event(dest_ip="192.168.56.20", dest_port="445", **BASE)
    assert (ok["dest_ip"], ok["dest_port"]) == ("192.168.56.20", 445)
    bad = make_event(dest_ip="999.1.1.1", dest_port=70000, **BASE)
    assert bad["dest_ip"] is None and bad["dest_port"] is None
    assert make_event(dest_port="abc", **BASE)["dest_port"] is None


def test_sysmon_network_event_keeps_destination():
    line = json.dumps({
        "TimeCreated": "2026-11-23T09:00:00.250Z", "EventID": 3,
        "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WIN",
        "Image": "System", "SourceIp": "192.168.56.150",
        "DestinationIp": "192.168.56.20", "DestinationPort": "445",
    })
    ev = windows_events.parse_line(line)
    assert ev["event_type"] == "network_connection"
    assert ev["source_ip"] == "192.168.56.150"
    assert (ev["dest_ip"], ev["dest_port"]) == ("192.168.56.20", 445)


def test_destination_round_trips_through_database(tmp_path):
    f = tmp_path / "d.db"
    db.init_db(f)
    db.insert_event(make_event(dest_ip="192.168.56.20", dest_port=3389, **BASE), f)
    row = db.fetch_events(1, f)[0]
    assert (row["dest_ip"], row["dest_port"]) == ("192.168.56.20", 3389)


def test_init_db_upgrades_an_old_database(tmp_path):
    f = tmp_path / "old.db"
    conn = sqlite3.connect(f)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "source TEXT NOT NULL, host TEXT, source_ip TEXT, username TEXT, "
        "event_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT, raw TEXT)"
    )
    conn.execute(
        "INSERT INTO events (timestamp, source, event_type, severity) "
        "VALUES ('2026-11-22T10:00:00+00:00', 't', 'other', 'low')"
    )
    conn.commit()
    conn.close()
    db.init_db(f)
    with db.connection(f) as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(events)")}
    assert {"dest_ip", "dest_port"} <= cols
    assert db.count_events(f) == 1  # existing data survives the upgrade
