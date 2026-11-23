"""Run ML anomaly detection against events in the database.

Usage:
    python run_ml.py
"""
from ml_engine.engine import run_ml


def main() -> None:
    anomalies, new = run_ml()
    print(f"{len(anomalies)} ML anomalies predicted ({new} new saved)")
    print("These are statistical predictions, not confirmed detections.\n")
    for a in anomalies:
        print(
            f"[{a['severity'].upper():6}] {a['method']:<16} {a['kind']:<16} "
            f"entity={a['entity']} user={a['username']} score={a['score']}"
        )


if __name__ == "__main__":
    main()