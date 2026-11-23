"""Send events, alerts and ML anomalies to Splunk via HEC.

Usage:
    python push_splunk.py            send anything new
    python push_splunk.py --reset    forget what was sent (use after deleting
                                     soc.db or clearing the Splunk index)
"""
import sys

from integrations import splunk


def main() -> int:
    if "--reset" in sys.argv:
        splunk.STATE_FILE.unlink(missing_ok=True)
        print("Checkpoint cleared. The next run resends everything.")
        return 0
    if not splunk.is_configured():
        print("Splunk is not configured. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in .env")
        return 1
    if not splunk.health_check():
        print("Splunk HEC is not reachable or not healthy. Is Splunk running with HEC enabled?")
        return 2
    try:
        sent = splunk.sync()
    except splunk.SplunkError as exc:
        print(f"Send failed: {exc}")
        return 3
    print(f"Sent to Splunk: {sent['events']} events, {sent['alerts']} alerts, "
          f"{sent['anomalies']} ML anomalies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
