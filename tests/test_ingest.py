import config
from parsers import linux_auth, windows_events


def test_sample_linux_log_parses():
    path = config.SAMPLE_LOG_DIR / "linux_auth.log"
    with path.open() as fh:
        events = linux_auth.parse_lines(fh, year=2026)
    assert len(events) == 9
    failed = [e for e in events if e["event_type"] == "login_failed"]
    assert len(failed) == 6


def test_sample_windows_log_parses():
    path = config.SAMPLE_LOG_DIR / "windows_events.jsonl"
    with path.open() as fh:
        events = windows_events.parse_lines(fh)
    assert len(events) == 7
    assert sum(e["event_type"] == "login_failed" for e in events) == 3