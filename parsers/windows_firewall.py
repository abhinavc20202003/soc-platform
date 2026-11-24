"""Parser for the Windows Defender Firewall log (pfirewall.log).

Each inbound TCP SYN (a connection attempt) becomes a network_connection event.
The firewall logs in the machine's local time, so the lab VM is set to UTC and
the timestamps line up with the Security and Sysmon events."""
from datetime import datetime, timezone
from typing import Optional

from parsers.schema import make_event

DEFAULT_HOST = "WIN-ENDPOINT"


def parse_line(line: str, host: str = DEFAULT_HOST) -> Optional[dict]:
    line = line.strip()
    if not line or line.startswith("#") or len(line) > 1000:
        return None
    f = line.split()
    if len(f) < 17:
        return None
    date, time, action, proto, src, dst, sport, dport = f[:8]
    flags, path = f[9], f[16]
    if proto != "TCP" or path != "RECEIVE" or action not in ("DROP", "ALLOW"):
        return None
    if "S" not in flags or "A" in flags:  # keep SYN only, not SYN-ACK or data
        return None
    try:
        ts = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    event = make_event(
        timestamp=ts, source="windows_firewall", event_type="network_connection",
        severity="low", host=host, source_ip=src, dest_ip=dst, dest_port=dport,
        message=f"Firewall {action} TCP {src}:{sport} -> {dst}:{dport}", raw=line,
    )
    if event["source_ip"] is None or event["dest_port"] is None:
        return None
    return event


def parse_lines(lines, host: str = DEFAULT_HOST) -> list:
    events = []
    for line in lines:
        ev = parse_line(line, host)
        if ev:
            events.append(ev)
    return events
