"""Parser for Linux /var/log/auth.log (syslog format)."""
import re
from datetime import datetime
from typing import Optional

from parsers.schema import make_event

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
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


def parse_line(line: str, year: Optional[int] = None) -> Optional[dict]:
    """Parse one auth.log line. Returns a normalized event or None."""
    line = line.strip()
    if not line or len(line) > 4000:
        return None
    m = SYSLOG_RE.match(line)
    if not m:
        return None

    year = year or datetime.now().year
    try:
        ts = datetime.strptime(
            f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    host, proc, msg = m["host"], m["proc"], m["msg"]
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

    if proc == "sudo":
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