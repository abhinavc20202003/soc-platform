"""Normalized event schema shared by all parsers."""
import ipaddress
from datetime import datetime, timezone
from typing import Optional

SEVERITIES = ("low", "medium", "high", "critical")

EVENT_TYPES = (
    "login_failed",
    "login_success",
    "logoff",
    "privilege_escalation",
    "process_creation",
    "network_connection",
    "account_created",
    "service_event",
    "other",
)


def validate_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical IP string, or None if invalid or missing."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def validate_port(value) -> Optional[int]:
    """Return a TCP/UDP port (1-65535) as an int, or None if invalid."""
    if isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def make_event(
    *,
    timestamp: datetime,
    source: str,
    event_type: str,
    severity: str = "low",
    host: Optional[str] = None,
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    dest_port=None,
    username: Optional[str] = None,
    message: Optional[str] = None,
    raw: Optional[str] = None,
) -> dict:
    if event_type not in EVENT_TYPES:
        event_type = "other"
    if severity not in SEVERITIES:
        severity = "low"
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return {
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "source": source,
        "host": (host or "")[:255] or None,
        "source_ip": validate_ip(source_ip),
        "dest_ip": validate_ip(dest_ip),
        "dest_port": validate_port(dest_port),
        "username": (username or "")[:255] or None,
        "event_type": event_type,
        "severity": severity,
        "message": (message or "")[:1000] or None,
        "raw": (raw or "")[:4000] or None,
    }
