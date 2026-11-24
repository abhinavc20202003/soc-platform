"""Load a log file into the database.

Usage:
    python ingest.py linux sample_logs/linux_auth.log
    python ingest.py windows sample_logs/windows_events.jsonl
    python ingest.py firewall C:/soc-lab-transfer/pfirewall.log
    python ingest.py ufw C:/soc-lab-transfer/ufw_export.log

Run each file once: re-ingesting the same file creates duplicate events.
"""
import sys
from pathlib import Path

from database import db
from parsers import linux_auth, linux_ufw, windows_events, windows_firewall

PARSERS = {
    "linux": linux_auth.parse_lines,
    "windows": windows_events.parse_lines,
    "firewall": windows_firewall.parse_lines,
    "ufw": linux_ufw.parse_lines,
}


def ingest_file(kind: str, path: Path) -> int:
    if kind not in PARSERS:
        raise ValueError(f"Unknown log kind: {kind!r} (use linux, windows, firewall or ufw)")
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        events = PARSERS[kind](fh)
    db.init_db()
    return db.insert_events(events)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    n = ingest_file(sys.argv[1], Path(sys.argv[2]))
    print(f"Ingested {n} events. Total in database: {db.count_events()}")
