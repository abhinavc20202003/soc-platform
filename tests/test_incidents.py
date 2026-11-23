import re

import pytest
from fastapi.testclient import TestClient

import config
from app import app
from database import db
from detection.engine import run_detection
from incident_response import manager
from incident_response.manager import generate_incidents
from parsers import linux_auth, windows_events


def _events():
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    return events


@pytest.fixture
def dbfile(tmp_path):
    f = tmp_path / "inc.db"
    db.init_db(f)
    db.insert_events(_events(), f)
    run_detection(f)
    return f


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    db.init_db()
    db.insert_events(_events())
    return TestClient(app)


def _seed(client):
    client.post("/api/detect")
    return client.post("/api/incidents/generate").json()


# ------------------------------------------------------- manager / database
def test_incidents_created_once(dbfile):
    assert generate_incidents(dbfile) == 7
    assert generate_incidents(dbfile) == 0
    assert len(manager.list_incidents(limit=100, db_path=dbfile)) == 7


def test_incident_fields(dbfile):
    generate_incidents(dbfile)
    critical = manager.list_incidents(severity="critical", db_path=dbfile)
    assert len(critical) == 3
    for inc in critical:
        assert re.fullmatch(r"INC-2026-\d{4}", inc["incident_id"])
        assert inc["status"] == "open"
        assert inc["containment"]
        assert len(inc["checklist"]) > 1
        assert all(c["done"] is False for c in inc["checklist"])


def test_detail_includes_evidence(dbfile):
    generate_incidents(dbfile)
    inc = manager.list_incidents(severity="critical", db_path=dbfile)[0]
    detail = manager.get_incident_detail(inc["incident_id"], dbfile)
    assert detail["evidence_events"]
    assert detail["alert"]["mitre"]


def test_update_status_and_checklist(dbfile):
    generate_incidents(dbfile)
    inc = manager.list_incidents(db_path=dbfile)[0]
    n = len(inc["checklist"])
    updated = manager.update_incident(
        inc["incident_id"], status="investigating", notes="Looking into it.",
        checklist_done=[True] + [False] * (n - 1), db_path=dbfile,
    )
    assert updated["status"] == "investigating"
    assert updated["notes"] == "Looking into it."
    assert updated["checklist"][0]["done"] is True
    assert updated["checklist"][0]["item"] == inc["checklist"][0]["item"]


def test_checklist_length_mismatch_rejected(dbfile):
    generate_incidents(dbfile)
    inc = manager.list_incidents(db_path=dbfile)[0]
    with pytest.raises(ValueError):
        manager.update_incident(inc["incident_id"], checklist_done=[True], db_path=dbfile)


def test_update_unknown_incident_returns_none(dbfile):
    assert manager.update_incident("INC-2026-9999", status="resolved", db_path=dbfile) is None


# ------------------------------------------------------------------- API
def test_api_generate_and_list(client):
    assert _seed(client) == {"new_incidents": 7}
    assert client.post("/api/incidents/generate").json() == {"new_incidents": 0}
    assert len(client.get("/api/incidents").json()) == 7


def test_api_filters(client):
    _seed(client)
    assert len(client.get("/api/incidents?severity=critical").json()) == 3
    assert client.get("/api/incidents?status=resolved").json() == []
    assert client.get("/api/incidents?status=bogus").status_code == 422
    assert client.get("/api/incidents?severity=bogus").status_code == 422


def test_api_detail(client):
    _seed(client)
    iid = client.get("/api/incidents?severity=critical").json()[0]["incident_id"]
    detail = client.get(f"/api/incidents/{iid}").json()
    assert detail["evidence_events"]
    assert detail["containment"]


def test_api_patch_updates(client):
    _seed(client)
    iid = client.get("/api/incidents").json()[0]["incident_id"]
    r = client.patch(f"/api/incidents/{iid}",
                     json={"status": "resolved", "notes": "Blocked IP at firewall."})
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert client.get("/api/incidents?status=resolved").json()[0]["incident_id"] == iid


def test_api_patch_validation(client):
    _seed(client)
    iid = client.get("/api/incidents").json()[0]["incident_id"]
    assert client.patch(f"/api/incidents/{iid}", json={"status": "bogus"}).status_code == 422
    assert client.patch(f"/api/incidents/{iid}", json={"checklist_done": [True]}).status_code == 422


def test_api_bad_and_missing_ids(client):
    assert client.get("/api/incidents/bogus").status_code == 422
    assert client.get("/api/incidents/INC-2026-9999").status_code == 404


def test_incidents_page_loads(client):
    r = client.get("/incidents")
    assert r.status_code == 200
    assert "Incident Response" in r.text