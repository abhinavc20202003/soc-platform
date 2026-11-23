"""Turns raw events into per-entity, per-time-window feature rows."""
from collections import defaultdict
from datetime import datetime, timezone

FEATURES = ["n_events", "n_failed", "n_success", "n_users", "fail_ratio"]


def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["timestamp"])


def normalize_user(name) -> str:
    """'DOMAIN\\Alice' -> 'alice'."""
    return (name or "").split("\\")[-1].strip().lower()


def entity_of(event: dict):
    """The thing we profile: the source IP, or the host if there is no IP."""
    if event.get("source_ip"):
        return event["source_ip"]
    if event.get("host"):
        return f"host:{event['host']}"
    return None


def window_start(ts: datetime, minutes: int) -> datetime:
    secs = minutes * 60
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % secs, tz=timezone.utc)


def build_windows(events: list, minutes: int) -> list:
    if not 1 <= minutes <= 60:
        raise ValueError("window minutes must be between 1 and 60")
    groups = defaultdict(list)
    for e in events:
        entity = entity_of(e)
        if entity is None:
            continue
        groups[(entity, window_start(_ts(e), minutes))].append(e)

    rows = []
    for (entity, ws), evs in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        n = len(evs)
        failed = sum(e["event_type"] == "login_failed" for e in evs)
        success = sum(e["event_type"] == "login_success" for e in evs)
        users = {normalize_user(e.get("username")) for e in evs if e.get("username")}
        rows.append({
            "entity": entity,
            "source_ip": None if entity.startswith("host:") else entity,
            "window_start": ws.isoformat(),
            "features": {
                "n_events": n,
                "n_failed": failed,
                "n_success": success,
                "n_users": len(users),
                "fail_ratio": round(failed / n, 4),
            },
            "users": sorted(users),
            "event_ids": [e["id"] for e in evs if e.get("id") is not None],
        })
    return rows


def to_matrix(rows: list) -> list:
    return [[r["features"][f] for f in FEATURES] for r in rows]