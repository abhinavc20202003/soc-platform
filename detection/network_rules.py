"""Network detections: port scans and connections to suspicious ports."""
import config
from detection.rules import _alert, _group, _single, _ts


def _conns(events: list) -> list:
    return [
        e for e in events
        if e["event_type"] == "network_connection"
        and e.get("source_ip") and e.get("dest_port") is not None
    ]


def _scan_bursts(events: list, window: int, threshold: int) -> list:
    """Clusters where `threshold` DISTINCT ports are hit within `window` seconds.
    A scan is extended while each next event is within `window` of the last,
    so one scan produces one alert."""
    bursts, i, n = [], 0, len(events)
    while i < n:
        j = i
        while j + 1 < n and (_ts(events[j + 1]) - _ts(events[i])).total_seconds() <= window:
            j += 1
        if len({e["dest_port"] for e in events[i:j + 1]}) >= threshold:
            while j + 1 < n and (_ts(events[j + 1]) - _ts(events[j])).total_seconds() <= window:
                j += 1
            bursts.append(events[i:j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


def port_scan(events: list) -> list:
    """R007: one source probing many different ports on one target."""
    thr, win = config.PORT_SCAN_PORT_THRESHOLD, config.PORT_SCAN_WINDOW_SECONDS
    alerts = []
    groups = _group(_conns(events), lambda e: (e["source_ip"], e.get("dest_ip") or e.get("host")))
    for (src, target), evs in groups.items():
        for burst in _scan_bursts(evs, win, thr):
            ports = sorted({e["dest_port"] for e in burst})
            sample = ", ".join(str(p) for p in ports[:10]) + (" ..." if len(ports) > 10 else "")
            alerts.append(_alert(
                "R007", "Port scan detected", "high" if len(ports) >= 100 else "medium", burst,
                f"{src} probed {len(ports)} different ports on {target} "
                f"(threshold {thr} within {win}s). Ports: {sample}.",
                "T1046", source_ip=src,
                host=_single(e.get("host") for e in burst),
            ))
    return alerts


def suspicious_connection(events: list) -> list:
    """R008: connections to ports commonly used by reverse shells and C2 tools."""
    bad = [e for e in _conns(events) if e["dest_port"] in config.SUSPICIOUS_PORTS]
    alerts = []
    groups = _group(bad, lambda e: (e["source_ip"], e.get("dest_ip"), e["dest_port"]))
    for (src, dst, port), evs in groups.items():
        alerts.append(_alert(
            "R008", "Connection to suspicious port", "high", evs,
            f"{len(evs)} connection(s) from {src} to {dst or 'unknown'}:{port}, a port "
            f"commonly used by reverse shells and C2 tools.",
            "T1571", source_ip=src,
            username=_single(e.get("username") for e in evs),
            host=_single(e.get("host") for e in evs),
        ))
    return alerts


NETWORK_RULES = [port_scan, suspicious_connection]
