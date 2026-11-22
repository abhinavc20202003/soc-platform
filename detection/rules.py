"""Rule-based detections. Each rule takes a list of normalized events and
returns a list of alert dicts. Rules never touch the database."""
from collections import defaultdict
from datetime import datetime, timedelta

import config

SENSITIVE_PATHS = ("/etc/shadow", "/etc/sudoers")

# pattern -> severity for suspicious process command lines
SUSPICIOUS_PATTERNS = {
    "mimikatz": "high",
    "sekurlsa": "high",
    "-enc ": "high",
    "-encodedcommand": "high",
    "downloadstring": "high",
    "invoke-expression": "high",
    "psexec": "high",
    "certutil": "medium",
    "bitsadmin": "medium",
    "net user": "medium",
    "whoami": "medium",
}


# ---------------------------------------------------------------- helpers
def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["timestamp"])


def _group(events, keyfn) -> dict:
    groups = defaultdict(list)
    for e in events:
        key = keyfn(e)
        if key is not None:
            groups[key].append(e)
    for items in groups.values():
        items.sort(key=_ts)
    return groups


def _single(values):
    """Return the value if all non-empty values are identical, else None."""
    unique = {v for v in values if v}
    return next(iter(unique)) if len(unique) == 1 else None


def _find_bursts(events: list, window: int, threshold: int) -> list:
    """Find clusters where `threshold` events occur within `window` seconds.
    A burst is extended while each next event is within `window` of the last,
    so one attack produces one alert, not many."""
    bursts, i, n = [], 0, len(events)
    while i + threshold - 1 < n:
        span = (_ts(events[i + threshold - 1]) - _ts(events[i])).total_seconds()
        if span <= window:
            j = i + threshold - 1
            while j + 1 < n and (_ts(events[j + 1]) - _ts(events[j])).total_seconds() <= window:
                j += 1
            bursts.append(events[i:j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


def _alert(rule_id, name, severity, events, description, mitre,
           source_ip=None, username=None, host=None) -> dict:
    times = sorted(_ts(e) for e in events)
    first, last = times[0].isoformat(), times[-1].isoformat()
    return {
        "fingerprint": f"{rule_id}|{name}|{source_ip}|{username}|{host}|{first}",
        "rule_id": rule_id,
        "name": name,
        "detection_type": "rule",
        "severity": severity,
        "source_ip": source_ip,
        "username": username,
        "host": host,
        "first_seen": first,
        "last_seen": last,
        "event_count": len(events),
        "description": description,
        "mitre": mitre,
        "evidence": [e["id"] for e in events if e.get("id") is not None],
        "status": "open",
    }


# ---------------------------------------------------------------- rules
def brute_force(events: list) -> list:
    """R001: many failed logins from one IP in a short window."""
    thr, win = config.BRUTE_FORCE_THRESHOLD, config.BRUTE_FORCE_WINDOW_SECONDS
    fails = [e for e in events if e["event_type"] == "login_failed"]
    alerts = []
    for ip, evs in _group(fails, lambda e: e.get("source_ip")).items():
        for burst in _find_bursts(evs, win, thr):
            alerts.append(_alert(
                "R001", "Brute-force login attempts", "high", burst,
                f"{len(burst)} failed logins from {ip} (threshold {thr} within {win}s).",
                "T1110", source_ip=ip,
                username=_single(e.get("username") for e in burst),
                host=_single(e.get("host") for e in burst),
            ))
    return alerts


def account_targeting(events: list) -> list:
    """R002: many failed logins against one account, from any source."""
    thr, win = config.BRUTE_FORCE_THRESHOLD, config.BRUTE_FORCE_WINDOW_SECONDS
    fails = [e for e in events if e["event_type"] == "login_failed"]
    alerts = []
    groups = _group(fails, lambda e: (e["username"], e.get("host")) if e.get("username") else None)
    for (user, host), evs in groups.items():
        for burst in _find_bursts(evs, win, thr):
            alerts.append(_alert(
                "R002", "Multiple failed authentications on one account", "medium", burst,
                f"{len(burst)} failed logins for account '{user}' (threshold {thr} within {win}s).",
                "T1110.001", username=user, host=host,
                source_ip=_single(e.get("source_ip") for e in burst),
            ))
    return alerts


def failed_then_success(events: list) -> list:
    """R003: repeated failures followed by a successful login from the same IP."""
    min_fail = config.FAIL_THEN_SUCCESS_MIN_FAILURES
    window = timedelta(seconds=config.FAIL_THEN_SUCCESS_WINDOW_SECONDS)
    relevant = [e for e in events if e["event_type"] in ("login_failed", "login_success")]
    alerts = []
    for ip, evs in _group(relevant, lambda e: e.get("source_ip")).items():
        recent = []
        for e in evs:
            if e["event_type"] == "login_failed":
                recent.append(e)
                continue
            cutoff = _ts(e) - window
            fails = [f for f in recent if _ts(f) >= cutoff]
            if len(fails) >= min_fail:
                alerts.append(_alert(
                    "R003", "Failed logins followed by successful login", "critical",
                    fails + [e],
                    f"{len(fails)} failed logins from {ip} were followed by a successful "
                    f"login as '{e.get('username')}'. The account may be compromised.",
                    "T1110 / T1078", source_ip=ip,
                    username=e.get("username"), host=e.get("host"),
                ))
            recent = []
    return alerts


def suspicious_ip(events: list) -> list:
    """R004: blocklisted IPs, or one IP guessing many different usernames."""
    alerts = []
    for ip, evs in _group(events, lambda e: e.get("source_ip")).items():
        if ip in config.SUSPICIOUS_IPS:
            alerts.append(_alert(
                "R004", "Activity from blocklisted IP", "high", evs,
                f"{len(evs)} events from {ip}, which is on the suspicious IP list.",
                "T1078", source_ip=ip,
                username=_single(e.get("username") for e in evs),
                host=_single(e.get("host") for e in evs),
            ))
    fails = [e for e in events if e["event_type"] == "login_failed"]
    for ip, evs in _group(fails, lambda e: e.get("source_ip")).items():
        users = {e["username"] for e in evs if e.get("username")}
        if len(users) >= config.DISTINCT_USER_THRESHOLD:
            alerts.append(_alert(
                "R004", "Credential guessing across many accounts", "medium", evs,
                f"{ip} failed logins against {len(users)} different accounts "
                f"({', '.join(sorted(users))}).",
                "T1110.003", source_ip=ip,
                host=_single(e.get("host") for e in evs),
            ))
    return alerts


def privilege_escalation(events: list) -> list:
    """R005: privilege use, critical when touching sensitive files."""
    privs = [e for e in events if e["event_type"] == "privilege_escalation"]
    alerts = []
    groups = _group(privs, lambda e: (e.get("host"), e.get("username")))
    for (host, user), evs in groups.items():
        sensitive = any(p in (e.get("message") or "") for e in evs for p in SENSITIVE_PATHS)
        alerts.append(_alert(
            "R005", "Privilege escalation indicator",
            "critical" if sensitive else "high", evs,
            f"Privileged activity by '{user}' on {host}"
            + (" involving a sensitive file (e.g. /etc/shadow)." if sensitive else "."),
            "T1548", username=user, host=host,
        ))
    return alerts


def suspicious_process(events: list) -> list:
    """R006: process creation matching known-suspicious command patterns."""
    alerts = []
    for e in events:
        if e["event_type"] != "process_creation":
            continue
        msg = (e.get("message") or "").lower()
        hits = [p for p in SUSPICIOUS_PATTERNS if p in msg]
        if not hits:
            continue
        severity = "high" if any(SUSPICIOUS_PATTERNS[p] == "high" for p in hits) else "medium"
        alerts.append(_alert(
            "R006", "Suspicious process execution", severity, [e],
            f"Process matched suspicious pattern(s): {', '.join(hits)}.",
            "T1059", username=e.get("username"), host=e.get("host"),
        ))
    return alerts


ALL_RULES = [
    brute_force,
    account_targeting,
    failed_then_success,
    suspicious_ip,
    privilege_escalation,
    suspicious_process,
]