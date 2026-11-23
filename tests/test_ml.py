import itertools
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import config
from app import app
from database import db
from ml_engine import features
from ml_engine.anomaly import (
    behaviour_anomalies, detect, isolation_forest_anomalies, statistical_anomalies,
)
from ml_engine.baseline import generate_baseline_events
from ml_engine.engine import run_ml
from ml_engine.model import Baseline
from parsers import linux_auth, windows_events
from parsers.schema import make_event

BASE = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def mk(offset, etype, ip=None, user=None, host="h1"):
    e = make_event(
        timestamp=BASE + timedelta(seconds=offset), source="test", event_type=etype,
        severity="medium", host=host, source_ip=ip, username=user,
    )
    e["id"] = next(_ids)
    return e


def burst():
    users = ["root", "admin", "test", "guest"]
    evs = [mk(i, "login_failed", "198.51.100.9", users[i % 4]) for i in range(15)]
    evs.append(mk(20, "login_success", "198.51.100.9", "root"))
    return evs


def normal_window():
    return features.build_windows([mk(0, "login_success", "192.168.56.10", "alice")], 5)


def _sample_events():
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    return events


@pytest.fixture(scope="module")
def baseline():
    return Baseline()


def test_baseline_is_deterministic_and_sizeable():
    a, b = generate_baseline_events(), generate_baseline_events()
    assert [e["timestamp"] for e in a] == [e["timestamp"] for e in b]
    assert len(a) > 150


def test_windows_group_by_entity():
    evs = burst() + [mk(5, "login_success", "198.51.100.77", "bob")]
    by = {r["entity"]: r for r in features.build_windows(evs, 5)}
    assert set(by) == {"198.51.100.9", "198.51.100.77"}
    f = by["198.51.100.9"]["features"]
    assert (f["n_events"], f["n_failed"], f["n_success"], f["n_users"]) == (16, 15, 1, 4)


def test_window_boundary_splits_events():
    evs = [mk(299, "login_success", "198.51.100.9", "a"),
           mk(300, "login_success", "198.51.100.9", "a")]
    assert len(features.build_windows(evs, 5)) == 2


def test_zscore_flags_burst_but_not_normal(baseline):
    flagged = statistical_anomalies(baseline, features.build_windows(burst(), 5))
    assert len(flagged) == 1 and flagged[0]["method"] == "zscore"
    assert statistical_anomalies(baseline, normal_window()) == []


def test_isolation_forest_scores_burst_higher(baseline):
    s_burst = -baseline.forest.score_samples(
        features.to_matrix(features.build_windows(burst(), 5)))[0]
    s_normal = -baseline.forest.score_samples(features.to_matrix(normal_window()))[0]
    assert s_burst > s_normal
    assert isolation_forest_anomalies(baseline, normal_window()) == []


def test_behaviour_new_source_and_unseen_account(baseline):
    evs = [
        mk(0, "login_success", "203.0.113.50", "root"),
        mk(1, "login_success", "192.168.56.101", "administrator"),
        mk(2, "login_success", "192.168.56.10", "alice"),  # known source: quiet
    ]
    got = {(a["kind"], a["username"]) for a in behaviour_anomalies(baseline, evs)}
    assert got == {("unseen_account", "root"), ("new_source", "administrator")}


def test_behaviour_off_hours(baseline):
    ev = mk(-7 * 3600, "login_success", "192.168.56.10", "alice")  # 03:00 UTC
    got = {(a["kind"], a["username"]) for a in behaviour_anomalies(baseline, [ev])}
    assert got == {("off_hours", "alice")}


def test_domain_prefix_is_normalised(baseline):
    ev = mk(0, "login_success", "192.168.56.20", "WIN\\Administrator")
    assert behaviour_anomalies(baseline, [ev]) == []


def test_sample_logs_end_to_end(baseline):
    anomalies = detect(_sample_events(), baseline)
    assert any(a["method"] == "zscore" and a["source_ip"] == "203.0.113.50" for a in anomalies)
    kinds = {(a["kind"], a["username"]) for a in anomalies if a["method"] == "behaviour"}
    assert ("unseen_account", "root") in kinds
    assert ("new_source", "administrator") in kinds
    assert all(a["detection_type"] == "ml_anomaly" for a in anomalies)
    assert all(a["severity"] in ("low", "medium", "high") for a in anomalies)


def test_run_ml_is_deduplicated(tmp_path):
    f = tmp_path / "ml.db"
    db.init_db(f)
    db.insert_events(_sample_events(), f)
    anomalies, new1 = run_ml(f)
    _, new2 = run_ml(f)
    assert new1 == len({a["fingerprint"] for a in anomalies})
    assert new2 == 0
    assert db.count_anomalies(f) == new1


def test_api_ml_run_and_list(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    db.init_db()
    db.insert_events(_sample_events())
    client = TestClient(app)
    result = client.post("/api/ml/run").json()
    assert result["anomalies_detected"] >= 3
    rows = client.get("/api/anomalies").json()
    assert len(rows) == result["new_anomalies"]
    assert all(r["detection_type"] == "ml_anomaly" for r in rows)
    assert isinstance(rows[0]["features"], dict)