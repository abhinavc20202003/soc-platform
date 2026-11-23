"""Anomaly detectors. They return predictions, never confirmed alerts."""
import config
from ml_engine.features import _ts, build_windows, normalize_user, to_matrix
from ml_engine.model import Baseline

Z_FEATURES = ("n_events", "n_failed")


def _anomaly(method, kind, entity, source_ip, username, window, score,
             severity, description, details) -> dict:
    return {
        "fingerprint": f"{method}|{kind}|{entity}|{username}|{window}",
        "detection_type": "ml_anomaly",
        "method": method,
        "kind": kind,
        "entity": entity,
        "source_ip": source_ip,
        "username": username,
        "window_start": window,
        "score": round(float(score), 4),
        "severity": severity,  # ML output is capped below 'critical' by design
        "description": description,
        "details": details,
    }


def isolation_forest_anomalies(baseline: Baseline, rows: list) -> list:
    if not rows:
        return []
    X = to_matrix(rows)
    preds = baseline.forest.predict(X)
    scores = -baseline.forest.score_samples(X)  # higher = more anomalous
    out = []
    for row, pred, score in zip(rows, preds, scores):
        if pred != -1:
            continue
        f = row["features"]
        out.append(_anomaly(
            "isolation_forest", "pattern_outlier", row["entity"], row["source_ip"], None,
            row["window_start"], score, "medium",
            f"Activity from {row['entity']} is unusual compared to the learned baseline: "
            f"{f['n_events']} events, {f['n_failed']} failures, {f['n_users']} accounts.",
            {**f, "users": row["users"]},
        ))
    return out


def statistical_anomalies(baseline: Baseline, rows: list) -> list:
    out = []
    for row in rows:
        zs = {f: (row["features"][f] - baseline.mean[f]) / baseline.std[f] for f in Z_FEATURES}
        feature = max(zs, key=zs.get)
        if zs[feature] < config.ML_ZSCORE_THRESHOLD:
            continue
        out.append(_anomaly(
            "zscore", "volume_spike", row["entity"], row["source_ip"], None,
            row["window_start"], zs[feature], "medium",
            f"{feature} = {row['features'][feature]} is {zs[feature]:.1f} standard deviations "
            f"above the baseline mean of {baseline.mean[feature]:.1f}.",
            {**row["features"], "users": row["users"], "z_score": round(zs[feature], 2)},
        ))
    return out


def behaviour_anomalies(baseline: Baseline, events: list) -> list:
    out = []
    for e in events:
        if e["event_type"] != "login_success":
            continue
        ts = _ts(e)
        user = normalize_user(e.get("username"))
        ip = e.get("source_ip")
        entity = ip or f"host:{e.get('host')}"
        window = ts.isoformat()

        if ts.hour >= config.OFF_HOURS_START or ts.hour < config.OFF_HOURS_END:
            out.append(_anomaly(
                "behaviour", "off_hours", entity, ip, user or None, window, 1.0, "low",
                f"Successful login for '{user}' at {ts:%H:%M} UTC, outside normal hours.",
                {"hour_utc": ts.hour},
            ))

        if user and ip:
            known = baseline.profile.get(user)
            if known is None:
                out.append(_anomaly(
                    "behaviour", "unseen_account", entity, ip, user, window, 1.0, "low",
                    f"Account '{user}' has no history in the baseline but logged in from {ip}.",
                    {"known_ips": []},
                ))
            elif ip not in known:
                out.append(_anomaly(
                    "behaviour", "new_source", entity, ip, user, window, 1.0, "medium",
                    f"'{user}' logged in from {ip}, which is not one of their usual sources "
                    f"({', '.join(sorted(known))}).",
                    {"known_ips": sorted(known)},
                ))
    return out


def detect(events: list, baseline: Baseline = None) -> list:
    if baseline is None:
        baseline = Baseline()
    rows = build_windows(events, config.ML_WINDOW_MINUTES)
    anomalies = (
        isolation_forest_anomalies(baseline, rows)
        + statistical_anomalies(baseline, rows)
        + behaviour_anomalies(baseline, events)
    )
    anomalies.sort(key=lambda a: (a["window_start"], a["method"]))
    return anomalies