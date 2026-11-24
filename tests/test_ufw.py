import config
import ingest
from detection.engine import run_rules
from parsers import linux_ufw


def ufw(sec, port, flags="SYN", proto="TCP"):
    return (f"Nov 23 10:15:{sec:02d} lab-ubuntu kernel: [UFW BLOCK] IN=enp0s8 OUT= "
            f"MAC=08:00:27:aa:bb:cc:08:00:27:dd:ee:ff:08:00 SRC=192.168.56.150 DST=192.168.56.20 "
            f"LEN=44 TOS=0x00 PREC=0x00 TTL=44 ID=1234 PROTO={proto} SPT=44521 DPT={port} "
            f"WINDOW=1024 RES=0x00 {flags} URGP=0")


def test_ufw_syn_becomes_connection_event():
    ev = linux_ufw.parse_line(ufw(0, 445), year=2026)
    assert ev["event_type"] == "network_connection"
    assert ev["source"] == "linux_ufw"
    assert (ev["source_ip"], ev["dest_ip"], ev["dest_port"]) == ("192.168.56.150", "192.168.56.20", 445)
    assert ev["host"] == "lab-ubuntu"


def test_non_syn_udp_and_garbage_are_ignored():
    assert linux_ufw.parse_line(ufw(0, 445, flags="ACK"), year=2026) is None
    assert linux_ufw.parse_line(ufw(0, 445, flags="SYN ACK"), year=2026) is None
    assert linux_ufw.parse_line(ufw(0, 53, proto="UDP"), year=2026) is None
    assert linux_ufw.parse_line("garbage") is None
    assert linux_ufw.parse_line("") is None


def test_ufw_scan_triggers_port_scan_rule():
    events = linux_ufw.parse_lines([ufw(i, 1000 + i) for i in range(20)], year=2026)
    assert [a["rule_id"] for a in run_rules(events)] == ["R007"]


def test_ingest_ufw_kind(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "ufw.db")
    f = tmp_path / "ufw.log"
    f.write_text("\n".join(ufw(i, 2000 + i) for i in range(12)) + "\n")
    assert ingest.ingest_file("ufw", f) == 12
