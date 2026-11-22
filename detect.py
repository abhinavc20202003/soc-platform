"""Run the detection engine against events in the database.

Usage:
    python detect.py
"""
from detection.engine import run_detection


def main() -> None:
    alerts, new = run_detection()
    print(f"{len(alerts)} alerts detected ({new} new saved)\n")
    for a in alerts:
        print(
            f"[{a['severity'].upper():8}] {a['rule_id']} {a['name']:<48} "
            f"ip={a['source_ip']} user={a['username']} events={a['event_count']}"
        )


if __name__ == "__main__":
    main()