"""Parser for Windows Security and Sysmon events (JSON-lines export)."""
import json
from datetime import datetime, timezone
from typing import Optional

from parsers.schema import make_event

SECURITY_MAP = {
    4625: ("login_failed", "medium"),
    4624: ("login_success", "low"),
    4634: ("logoff", "low"),
    4672: ("privilege_escalation", "high"),
    4720: ("account_created", "medium"),
    4688: ("process_creation", "low"),
}

SYSMON_MAP = {
    1: ("process_creation", "low"),
    3: ("network_connection", "low"),
}

SUSPICIOUS_PROCESSES = (
    "powershell.exe", "cmd.exe", "mimikatz", "psexec", "certutil.exe",
    "bitsadmin.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
)


def _parse_time(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line or len(line) > 20000:
        return None
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict):
        return None

    try:
        ts = _parse_time(str(rec["TimeCreated"]))
        event_id = int(rec["EventID"])
    except (KeyError, ValueError, TypeError):
        return None

    channel = str(rec.get("Channel", ""))
    is_sysmon = "sysmon" in channel.lower()
    mapping = SYSMON_MAP if is_sysmon else SECURITY_MAP
    event_type, severity = mapping.get(event_id, ("other", "low"))

    image = str(rec.get("Image") or rec.get("NewProcessName") or "")
    if event_type == "process_creation" and any(
        s in image.lower() for s in SUSPICIOUS_PROCESSES
    ):
        severity = "medium"

    msg = f"EventID {event_id}"
    if image:
        msg += f" {image}"
    if rec.get("CommandLine"):
        msg += f" | {str(rec['CommandLine'])[:300]}"

    return make_event(
        timestamp=ts,
        source="windows_sysmon" if is_sysmon else "windows_security",
        event_type=event_type,
        severity=severity,
        host=rec.get("Computer"),
        source_ip=rec.get("IpAddress") or rec.get("SourceIp"),
        username=rec.get("TargetUserName") or rec.get("User"),
        message=msg,
        raw=line,
    )


def parse_lines(lines) -> list:
    events = []
    for line in lines:
        ev = parse_line(line)
        if ev:
            events.append(ev)
    return events