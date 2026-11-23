"""Run detection, then create incidents for new alerts.

Usage:
    python detect.py
"""
from detection.engine import run_detection
from incident_response.manager import generate_incidents


def main() -> None:
    alerts, new = run_detection()
    print(f"{len(alerts)} alerts detected ({new} new saved)\n")
    for a in alerts:
        print(
            f"[{a['severity'].upper():8}] {a['rule_id']} {a['name']:<48} "
            f"ip={a['source_ip']} user={a['username']} events={a['event_count']}"
        )
    print(f"\n{generate_incidents()} new incidents created")


if __name__ == "__main__":
    main()