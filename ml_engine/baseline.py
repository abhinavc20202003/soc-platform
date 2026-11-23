"""Synthetic 'normal' activity used to train the anomaly detectors.

Deterministic (fixed seed) so results are reproducible. In production this
would be replaced by weeks of real, analyst-reviewed logs from your own
environment. It includes some legitimate unusual patterns (a service-account
batch, a shared jump host, an occasional lockout) so the model learns that
not every busy window is an attack.
"""
import random
from datetime import datetime, timedelta, timezone

from parsers.schema import make_event

START = datetime(2026, 10, 1, tzinfo=timezone.utc)

USERS = {
    "alice": "192.168.56.10",
    "bob": "192.168.56.11",
    "carol": "192.168.56.12",
    "administrator": "192.168.56.20",
}
SERVICE_ACCOUNT = ("svc-backup", "192.168.56.30")
JUMP_HOST_IP = "192.168.56.40"


def _ev(ts, etype, ip, user):
    return make_event(
        timestamp=ts, source="baseline", event_type=etype,
        severity="medium" if etype == "login_failed" else "low",
        host="baseline-host", source_ip=ip, username=user,
    )


def generate_baseline_events(days: int = 28, seed: int = 42) -> list:
    rng = random.Random(seed)
    events = []
    for day in range(days):
        base = START + timedelta(days=day)
        if base.weekday() >= 5:  # no weekend activity
            continue

        # Ordinary working-hours sessions, sometimes with one typo first.
        for user, ip in USERS.items():
            for _ in range(rng.randint(1, 3)):
                t = base + timedelta(
                    hours=rng.randint(8, 17),
                    minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
                if rng.random() < 0.15:
                    events.append(_ev(t - timedelta(seconds=rng.randint(5, 20)),
                                      "login_failed", ip, user))
                events.append(_ev(t, "login_success", ip, user))

        # Service-account batch: many logins in a few minutes.
        if day % 5 == 2:
            t = base + timedelta(hours=11, minutes=rng.choice([0, 10, 20, 30, 40]))
            user, ip = SERVICE_ACCOUNT
            for i in range(rng.randint(8, 12)):
                events.append(_ev(t + timedelta(seconds=i * 15), "login_success", ip, user))

        # Shared jump host: several users from one IP.
        if day % 4 == 1:
            t = base + timedelta(hours=14, minutes=rng.choice([0, 15, 30]))
            for i, user in enumerate(("alice", "bob", "carol")):
                events.append(_ev(t + timedelta(seconds=i * 30), "login_success",
                                  JUMP_HOST_IP, user))

        # Occasional legitimate lockout: a few failures, then success.
        if day % 6 == 3:
            t = base + timedelta(hours=9, minutes=rng.choice([0, 20, 40]))
            ip = USERS["bob"]
            for i in range(rng.randint(3, 4)):
                events.append(_ev(t + timedelta(seconds=i * 20), "login_failed", ip, "bob"))
            events.append(_ev(t + timedelta(seconds=90), "login_success", ip, "bob"))
    return events