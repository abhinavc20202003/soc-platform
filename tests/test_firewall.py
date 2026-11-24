import config
import ingest
from detection.engine import run_rules
from parsers import windows_firewall


def fw(sec, port, flags="S", path="RECEIVE", action="DROP"):
    return (f"2026-11-23 10:15:{sec:02d} {action} TCP 192.168.56.150 192.168.56.20 "
            f"44521 {port} 60 {flags} 123 0 1024 - - - {path}")


def test_inbound_syn_becomes_connection_event():
    ev = windows_firewall.parse_line(fw(0, 445))
    assert ev["event_type"] == "network_connection"
    assert ev["source"] == "windows_firewall"
    assert (ev["source_ip"], ev["dest_ip"], ev["dest_port"]) == ("192.168.56.150", "192.168.56.20", 445)
    assert ev["host"] == "WIN-ENDPOINT"


def test_non_syn_and_outbound_are_ignored():
    assert windows_firewall.parse_line(fw(0, 445, flags="A")) is None
    assert windows_firewall.parse_line(fw(0, 445, flags="SA")) is None
    assert windows_firewall.parse_line(fw(0, 445, path="SEND")) is None


def test_comments_and_garbage_are_ignored():
    assert windows_firewall.parse_line("#Version: 1.5") is None
    assert windows_firewall.parse_line("garbage") is None
    assert windows_firewall.parse_line("") is None


def test_firewall_scan_triggers_port_scan_rule():
    events = windows_firewall.parse_lines([fw(i, 1000 + i) for i in range(20)])
    assert [a["rule_id"] for a in run_rules(events)] == ["R007"]


def test_ingest_firewall_kind(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "fw.db")
    f = tmp_path / "pfirewall.log"
    f.write_text("#Version: 1.5\n" + "\n".join(fw(i, 2000 + i) for i in range(12)) + "\n")
    assert ingest.ingest_file("firewall", f) == 12
