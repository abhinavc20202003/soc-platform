"""Parser for Linux authentication logs: classic syslog format
(/var/log/auth.log on older systems) and modern rsyslog ISO-8601 format
(Ubuntu 22.04+ default: "2026-11-24T05:45:07.320220+00:00 host proc[pid]: msg")."""
import re
from datetime import datetime
from typing import Optional

from parsers.schema import make_event

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"
)
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
SESSION_ROOT_RE = re.compile(r"session opened for user root")


def _split_line(line: str, year: Optional[int]):
    """Returns (timestamp, host, proc, msg) for either log format, or None."""
    m = ISO_RE.match(line)
    if m:
        try:
            return datetime.fromisoformat(m["ts"]), m["host"], m["proc"], m["msg"]
        except ValueError:
            return None

    m = SYSLOG_RE.match(line)
    if m:
        year = year or datetime.now().year
        try:
            ts = datetime.strptime(
                f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None
        return ts, m["host"], m["proc"], m["msg"]

    return None


def parse_line(line: str, year: Optional[int] = None) -> Optional[dict]:
    """Parse one auth log line. Returns a normalized event or None."""
    line = line.strip()
    if not line or len(line) > 4000:
        return None
    parsed = _split_line(line, year)
    if parsed is None:
        return None
    ts, host, proc, msg = parsed
    common = dict(timestamp=ts, source="linux_auth", host=host, message=msg, raw=line)

    f = FAILED_RE.search(msg) or INVALID_USER_RE.search(msg)
    if f:
        return make_event(
            event_type="login_failed", severity="medium",
            source_ip=f["ip"], username=f["user"], **common,
        )

    a = ACCEPTED_RE.search(msg)
    if a:
        return make_event(
            event_type="login_success", severity="low",
            source_ip=a["ip"], username=a["user"], **common,
        )

    if "sudo" in proc:
        s = SUDO_RE.search(msg)
        if s:
            return make_event(
                event_type="privilege_escalation", severity="high",
                username=s["user"], **common,
            )

    if SESSION_ROOT_RE.search(msg):
        return make_event(event_type="privilege_escalation", severity="high", **common)

    return make_event(event_type="other", severity="low", **common)


def parse_lines(lines, year: Optional[int] = None) -> list:
    events = []
    for line in lines:
        ev = parse_line(line, year)
        if ev:
            events.append(ev)
    return events
