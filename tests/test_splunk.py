import json

import pytest
import requests

import config
from database import db
from detection.engine import run_detection
from integrations import splunk
from parsers import linux_auth, windows_events


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"text": "Success", "code": 0}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


def _events():
    with (config.SAMPLE_LOG_DIR / "linux_auth.log").open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    with (config.SAMPLE_LOG_DIR / "windows_events.jsonl").open() as fh:
        events += windows_events.parse_lines(fh)
    return events


@pytest.fixture
def dbfile(tmp_path):
    f = tmp_path / "s.db"
    db.init_db(f)
    db.insert_events(_events(), f)
    run_detection(f)
    return f


@pytest.fixture
def hec(monkeypatch):
    monkeypatch.setattr(config, "SPLUNK_HEC_URL", "https://127.0.0.1:8088")
    monkeypatch.setattr(config, "SPLUNK_HEC_TOKEN", "test-token-123")
    monkeypatch.setattr(config, "SPLUNK_VERIFY_SSL", True)
    calls = []

    def fake_post(url, data=None, headers=None, timeout=None, verify=None):
        calls.append({"url": url, "data": data, "headers": headers})
        return FakeResponse()

    monkeypatch.setattr(splunk.requests, "post", fake_post)
    return calls


def _count(calls):
    return sum(len(c["data"].splitlines()) for c in calls)


def test_format_alert_event(dbfile):
    alert = db.fetch_alerts(1, dbfile)[0]
    payload = splunk.format_event("alerts", alert)
    assert payload["source"] == "mini-soc:alert"
    assert payload["index"] == config.SPLUNK_INDEX
    assert isinstance(payload["time"], float)
    assert isinstance(payload["event"]["evidence"], list)


def test_format_event_renames_reserved_source_field(dbfile):
    ev = db.fetch_events(1, dbfile)[0]
    payload = splunk.format_event("events", ev)
    assert "source" not in payload["event"]
    assert "log_source" in payload["event"]


def test_sync_sends_everything_once(hec, dbfile, tmp_path):
    state = tmp_path / "state.json"
    assert splunk.sync(dbfile, state) == {"events": 16, "alerts": 7, "anomalies": 0}
    assert _count(hec) == 23
    assert hec[0]["headers"]["Authorization"] == "Splunk test-token-123"
    assert hec[0]["url"].endswith("/services/collector/event")
    assert splunk.sync(dbfile, state) == {"events": 0, "alerts": 0, "anomalies": 0}
    assert _count(hec) == 23


def test_batches_respect_size(monkeypatch, hec, dbfile, tmp_path):
    monkeypatch.setattr(splunk, "BATCH_SIZE", 5)
    splunk.sync(dbfile, tmp_path / "state.json")
    assert all(len(c["data"].splitlines()) <= 5 for c in hec)
    assert _count(hec) == 23


def test_failure_does_not_advance_checkpoint(monkeypatch, hec, dbfile, tmp_path):
    state = tmp_path / "state.json"
    monkeypatch.setattr(
        splunk.requests, "post",
        lambda *a, **k: FakeResponse(403, {"text": "Invalid token", "code": 4}),
    )
    with pytest.raises(splunk.SplunkError) as exc:
        splunk.sync(dbfile, state)
    assert "test-token-123" not in str(exc.value)  # secrets never appear in errors
    assert not state.exists()
    monkeypatch.setattr(splunk.requests, "post", lambda *a, **k: FakeResponse())
    assert splunk.sync(dbfile, state)["events"] == 16


def test_not_configured_raises(monkeypatch):
    monkeypatch.setattr(config, "SPLUNK_HEC_URL", "")
    monkeypatch.setattr(config, "SPLUNK_HEC_TOKEN", "")
    with pytest.raises(splunk.SplunkError):
        splunk.send_batch([{}])


def test_checkpoint_resets_if_database_recreated(hec, dbfile, tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"events": 999, "alerts": 999, "anomalies": 999}))
    assert splunk.sync(dbfile, state)["events"] == 16


def test_health_check(monkeypatch, hec):
    monkeypatch.setattr(splunk.requests, "get", lambda *a, **k: FakeResponse())
    assert splunk.health_check() is True

    def boom(*a, **k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(splunk.requests, "get", boom)
    assert splunk.health_check() is False
