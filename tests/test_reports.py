import pytest
from fastapi.testclient import TestClient

import config
from app import app
from database import db
from detection.engine import run_detection
from incident_response.manager import generate_incidents
from parsers import linux_auth, windows_events
from reports.csv_report import build_alerts_csv
from reports.data import build_report_data
from reports.pdf_report import build_pdf_report


def _events():
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    return events


@pytest.fixture
def dbfile(tmp_path):
    f = tmp_path / "r.db"
    db.init_db(f)
    db.insert_events(_events(), f)
    run_detection(f)
    generate_incidents(f)
    return f


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.db")
    db.init_db()
    db.insert_events(_events())
    run_detection()
    generate_incidents()
    return TestClient(app)


def test_report_data_matches_database(dbfile):
    data = build_report_data(dbfile)
    assert data["stats"]["total_alerts"] == 7
    assert data["severity_counts"]["critical"] == 3
    assert len(data["incidents"]) == 7
    assert data["open_incidents"] == 7


def test_report_data_handles_empty_database(tmp_path):
    f = tmp_path / "empty.db"
    db.init_db(f)
    data = build_report_data(f)
    assert data["stats"]["total_alerts"] == 0
    assert data["severity_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert data["alerts"] == [] and data["incidents"] == []


def test_csv_has_header_and_one_row_per_alert(dbfile):
    text = build_alerts_csv(build_report_data(dbfile))
    lines = text.strip().splitlines()
    assert lines[0].startswith("rule_id,name,detection_type")
    assert len(lines) == 8  # header + 7 alerts


def test_pdf_builds_a_real_file(dbfile, tmp_path):
    out = tmp_path / "report.pdf"
    build_pdf_report(build_report_data(dbfile), out)
    assert out.exists() and out.stat().st_size > 2000
    assert out.read_bytes()[:4] == b"%PDF"


def test_pdf_builds_on_empty_database(tmp_path):
    f = tmp_path / "empty.db"
    db.init_db(f)
    out = tmp_path / "empty.pdf"
    build_pdf_report(build_report_data(f), out)
    assert out.exists() and out.read_bytes()[:4] == b"%PDF"


def test_api_csv_download(client):
    r = client.get("/api/reports/csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert len(r.text.strip().splitlines()) == 8


def test_api_pdf_download(client):
    r = client.get("/api/reports/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"
