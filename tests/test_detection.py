import itertools
from datetime import datetime, timedelta, timezone

import config
from database import db
from detection import rules
from detection.engine import run_detection, run_rules
from parsers import linux_auth, windows_events
from parsers.schema import make_event

BASE = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def mk(offset, etype, ip=None, user=None, host="h1", msg=None):
    e = make_event(
        timestamp=BASE + timedelta(seconds=offset), source="test",
        event_type=etype, severity="medium", host=host,
        source_ip=ip, username=user, message=msg,
    )
    e["id"] = next(_ids)
    return e


def fails(n, step=2, ip="198.51.100.9", user="root"):
    return [mk(i * step, "login_failed", ip, user) for i in range(n)]


def test_brute_force_fires_at_threshold():
    alerts = rules.brute_force(fails(5))
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R001"
    assert alerts[0]["event_count"] == 5


def test_brute_force_below_threshold_is_quiet():
    assert rules.brute_force(fails(4)) == []


def test_slow_failures_are_not_brute_force():
    assert rules.brute_force(fails(5, step=100)) == []


def test_one_burst_makes_one_alert():
    assert len(rules.brute_force(fails(12))) == 1


def test_fail_then_success_is_critical():
    evs = fails(3) + [mk(10, "login_success", "198.51.100.9", "root")]
    alerts = rules.failed_then_success(evs)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"


def test_success_without_failures_is_quiet():
    assert rules.failed_then_success([mk(1, "login_success", "198.51.100.9", "bob")]) == []


def test_many_usernames_flagged():
    evs = [mk(i, "login_failed", "198.51.100.9", u) for i, u in enumerate(["a", "b", "c"])]
    alerts = rules.suspicious_ip(evs)
    assert any(a["name"] == "Credential guessing across many accounts" for a in alerts)


def test_blocklisted_ip_flagged(monkeypatch):
    monkeypatch.setattr(config, "SUSPICIOUS_IPS", {"198.51.100.7"})
    alerts = rules.suspicious_ip([mk(1, "login_success", "198.51.100.7", "bob")])
    assert alerts and alerts[0]["name"] == "Activity from blocklisted IP"


def test_shadow_access_is_critical():
    ev = mk(1, "privilege_escalation", user="alice", host="web01",
            msg="alice : COMMAND=/bin/cat /etc/shadow")
    assert rules.privilege_escalation([ev])[0]["severity"] == "critical"


def test_mimikatz_is_high_and_benign_is_quiet():
    bad = mk(1, "process_creation", msg="EventID 1 C:\\tools\\mimikatz.exe")
    good = mk(2, "process_creation", msg="EventID 1 C:\\Windows\\notepad.exe")
    alerts = rules.suspicious_process([bad, good])
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"


def _sample_events():
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    return events


def test_sample_logs_end_to_end():
    alerts = run_rules(_sample_events())
    by_rule = {}
    for a in alerts:
        by_rule[a["rule_id"]] = by_rule.get(a["rule_id"], 0) + 1
    assert by_rule == {"R001": 1, "R003": 2, "R004": 1, "R005": 2, "R006": 1}
    assert len(alerts) == 7


def test_alerts_are_deduplicated_in_database(tmp_path):
    db_file = tmp_path / "t.db"
    db.init_db(db_file)
    db.insert_events(_sample_events(), db_file)
    _, new_first = run_detection(db_file)
    _, new_second = run_detection(db_file)
    assert new_first == 7
    assert new_second == 0
    assert db.count_alerts(db_file) == 7