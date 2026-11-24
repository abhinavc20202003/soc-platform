"""Parser for Ubuntu UFW firewall messages (kernel log lines).

Each inbound TCP SYN that UFW logs becomes a network_connection event.
Input is `journalctl -k -o short` output, e.g.
  Nov 23 10:15:01 lab-ubuntu kernel: [UFW BLOCK] IN=enp0s8 ... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=44521 DPT=445 ... SYN URGP=0
Set the Ubuntu VM to UTC so timestamps line up with the other sources."""
import re
from datetime import datetime, timezone
from typing import Optional

from parsers.schema import make_event

LINE_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+kernel:.*"
    r"\[UFW (?P<action>BLOCK|AUDIT|ALLOW)\]"
)
FIELD_RE = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=(\S+)")


def parse_line(line: str, year: Optional[int] = None) -> Optional[dict]:
    line = line.strip()
    if not line or len(line) > 2000:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None
    fields = dict(FIELD_RE.findall(line))
    if fields.get("PROTO") != "TCP":
        return None
    if not re.search(r"\bSYN\b", line) or re.search(r"\bACK\b", line):
        return None  # keep connection attempts only
    year = year or datetime.now(timezone.utc).year
    try:
        ts = datetime.strptime(
            f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    src, dst, dport = fields.get("SRC"), fields.get("DST"), fields.get("DPT")
    event = make_event(
        timestamp=ts, source="linux_ufw", event_type="network_connection",
        severity="low", host=m["host"], source_ip=src, dest_ip=dst, dest_port=dport,
        message=f"UFW {m['action']} TCP {src}:{fields.get('SPT')} -> {dst}:{dport}", raw=line,
    )
    if event["source_ip"] is None or event["dest_port"] is None:
        return None
    return event


def parse_lines(lines, year: Optional[int] = None) -> list:
    events = []
    for line in lines:
        ev = parse_line(line, year)
        if ev:
            events.append(ev)
    return events
