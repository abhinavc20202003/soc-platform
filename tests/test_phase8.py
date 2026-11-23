from datetime import datetime, timedelta, timezone

import pytest

import config
import simulate
from database import db
from detection.engine import run_detection, run_rules
from detection.network_rules import port_scan, suspicious_connection
from incident_response.playbooks import DEFAULT_PLAYBOOK, get_playbook
from parsers import linux_auth, windows_events
from parsers.schema import make_event
from simulation import attacks

BASE = datetime(2026, 11, 23, 9, 0, 0, tzinfo=timezone.utc)


def conn(offset, port, src="198.51.100.9", dst="192.168.56.20"):
    return make_event(
        timestamp=BASE + timedelta(seconds=offset), source="test",
        event_type="network_connection", host="h1",
        source_ip=src, dest_ip=dst, dest_port=port,
    )


def _events(scenario):
    linux, windows = scenario
    return linux_auth.parse_lines(linux, year=2026) + windows_events.parse_lines(windows)


# ------------------------------------------------------------- rules
def test_scan_fires_at_threshold():
    alerts = port_scan([conn(i, 1000 + i) for i in range(10)])
    assert len(alerts) == 1 and alerts[0]["rule_id"] == "R007"


def test_few_ports_is_quiet():
    assert port_scan([conn(i, 1000 + i) for i in range(9)]) == []


def test_slow_scan_is_quiet():
    assert port_scan([conn(i * 120, 1000 + i) for i in range(30)]) == []


def test_same_port_repeated_is_not_a_scan():
    assert port_scan([conn(i, 80) for i in range(50)]) == []


def test_suspicious_port_flagged():
    alerts = suspicious_connection([conn(0, 4444), conn(1, 443)])
    assert len(alerts) == 1 and alerts[0]["rule_id"] == "R008"


def test_suspicious_ports_are_configurable(monkeypatch):
    monkeypatch.setattr(config, "SUSPICIOUS_PORTS", {8081})
    assert len(suspicious_connection([conn(0, 8081)])) == 1
    assert suspicious_connection([conn(0, 4444)]) == []


# ------------------------------------------------------------- scenarios
@pytest.mark.parametrize("name, expected", [
    ("bruteforce", ["R001", "R003", "R004"]),
    ("portscan", ["R007"]),
    ("c2", ["R008"]),
    ("process", ["R006", "R006"]),
    ("privesc", ["R005", "R005"]),
])
def test_each_scenario_triggers_expected_rules(name, expected):
    alerts = run_rules(_events(attacks.SCENARIOS[name](BASE)))
    assert sorted(a["rule_id"] for a in alerts) == expected


def test_port_scan_details():
    alert = run_rules(_events(attacks.portscan(BASE)))[0]
    assert alert["source_ip"] == attacks.ATTACKER
    assert alert["event_count"] == 30
    assert alert["mitre"] == "T1046"


def test_all_scenarios_end_to_end(tmp_path):
    f = tmp_path / "sim.db"
    db.init_db(f)
    db.insert_events(_events(attacks.generate_all(BASE)), f)
    alerts, new = run_detection(f)
    assert sorted(a["rule_id"] for a in alerts) == [
        "R001", "R003", "R004", "R005", "R005", "R006", "R006", "R007", "R008"]
    assert new == 9


def test_new_rules_have_playbooks():
    for name in ("Port scan detected", "Connection to suspicious port"):
        assert get_playbook(name) is not DEFAULT_PLAYBOOK


def test_simulate_cli_ingests(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "cli.db")
    monkeypatch.setattr(simulate, "OUT_DIR", tmp_path / "out")
    assert simulate.main(["portscan", "--ingest"]) == 0
    assert db.count_alerts() == 1
    assert (tmp_path / "out" / "portscan_windows.jsonl").exists()
