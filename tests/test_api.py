import pytest
from fastapi.testclient import TestClient

import config
from app import app
from database import db
from parsers import linux_auth, windows_events


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    db.init_db()
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    db.insert_events(events)
    return TestClient(app)


def test_detect_then_stats(client):
    r = client.post("/api/detect")
    assert r.json() == {"alerts_detected": 7, "new_alerts": 7}
    stats = client.get("/api/stats").json()
    assert stats["total_events"] == 16
    assert stats["total_alerts"] == 7
    assert stats["failed_logins"] == 9


def test_event_filter(client):
    rows = client.get("/api/events?event_type=login_failed&limit=50").json()
    assert len(rows) == 9
    assert all(r["event_type"] == "login_failed" for r in rows)


def test_invalid_filters_rejected(client):
    assert client.get("/api/events?event_type=bogus").status_code == 422
    assert client.get("/api/events?source_ip=999.1.1.1").status_code == 422
    assert client.get("/api/events?limit=100000").status_code == 422


def test_dashboard_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Security Overview" in r.text