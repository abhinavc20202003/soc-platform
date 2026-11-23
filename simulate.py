"""Generate synthetic attack logs for the lab.

Usage:
    python simulate.py list
    python simulate.py bruteforce|portscan|c2|process|privesc|all
    python simulate.py all --ingest     also load into the database, run detection
                                        and create incidents

This only writes log lines. It sends no network traffic. Use a separate
database for lab work:  $env:SOC_DB_PATH = "database\\lab.db"
"""
import argparse
from datetime import datetime, timezone

import config
from database import db
from detection.engine import run_detection
from incident_response.manager import generate_incidents
from parsers import linux_auth, windows_events
from simulation import attacks

OUT_DIR = config.BASE_DIR / "logs" / "simulated"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic attack logs.")
    parser.add_argument("scenario", choices=["list", "all", *attacks.SCENARIOS])
    parser.add_argument("--ingest", action="store_true",
                        help="load events into the database and run detection")
    args = parser.parse_args(argv)

    if args.scenario == "list":
        for name, text in attacks.DESCRIPTIONS.items():
            print(f"{name:<11} {text}")
        return 0

    base = datetime.now(timezone.utc).replace(microsecond=0)
    if args.scenario == "all":
        linux, windows = attacks.generate_all(base)
    else:
        linux, windows = attacks.SCENARIOS[args.scenario](base)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    linux_file = OUT_DIR / f"{args.scenario}_linux.log"
    win_file = OUT_DIR / f"{args.scenario}_windows.jsonl"
    linux_file.write_text("".join(line + "\n" for line in linux), encoding="utf-8")
    win_file.write_text("".join(line + "\n" for line in windows), encoding="utf-8")
    print(f"Wrote {len(linux)} Linux lines and {len(windows)} Windows events to {OUT_DIR}")

    if args.ingest:
        events = linux_auth.parse_lines(linux, year=base.year) + windows_events.parse_lines(windows)
        db.init_db()
        db.insert_events(events)
        alerts, new = run_detection()
        incidents = generate_incidents()
        print(f"Database: {config.DB_PATH}")
        print(f"Ingested {len(events)} events -> {len(alerts)} alerts total ({new} new), "
              f"{incidents} new incidents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
