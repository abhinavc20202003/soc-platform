"""Synthetic attack scenarios for the lab. They only generate log lines;
nothing here touches the network. IPs are private lab addresses."""
import json
from datetime import datetime, timedelta

ATTACKER = "192.168.56.150"   # Kali VM in the lab
TARGET = "192.168.56.20"      # Windows endpoint
LINUX_HOST = "lab-linux"
WIN_HOST = "WIN-ENDPOINT"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"

SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 8000, 8080, 8443,
    9000, 9200, 27017,
]


def _syslog(ts: datetime, proc: str, msg: str) -> str:
    return f"{ts:%b %d %H:%M:%S} {LINUX_HOST} {proc}: {msg}"


def _win(ts: datetime, event_id: int, channel: str, **fields) -> str:
    rec = {
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "EventID": event_id,
        "Channel": channel,
        "Computer": WIN_HOST,
    }
    rec.update(fields)
    return json.dumps(rec)


def bruteforce(base: datetime):
    """SSH password guessing against several accounts, then a successful login."""
    users = ["root", "admin", "ubuntu", "test"]
    lines = [
        _syslog(base + timedelta(seconds=i), "sshd[2201]",
                f"Failed password for {users[i % 4]} from {ATTACKER} port {40000 + i} ssh2")
        for i in range(12)
    ]
    lines.append(_syslog(base + timedelta(seconds=14), "sshd[2201]",
                         f"Accepted password for root from {ATTACKER} port 40014 ssh2"))
    return lines, []


def portscan(base: datetime):
    """An Nmap-style scan: 30 different ports on the Windows endpoint in 7.5 seconds."""
    recs = [
        _win(base + timedelta(milliseconds=250 * i), 3, SYSMON, Image="System",
             SourceIp=ATTACKER, DestinationIp=TARGET, DestinationPort=str(port))
        for i, port in enumerate(SCAN_PORTS)
    ]
    return [], recs


def c2(base: datetime):
    """PowerShell on the endpoint repeatedly connecting out to port 4444."""
    recs = [
        _win(base + timedelta(seconds=30 * i), 3, SYSMON, Image=POWERSHELL,
             User=f"{WIN_HOST}\\administrator", SourceIp=TARGET,
             DestinationIp=ATTACKER, DestinationPort="4444")
        for i in range(3)
    ]
    return [], recs


def process(base: datetime):
    """Encoded PowerShell and reconnaissance commands (safe test strings)."""
    recs = [
        _win(base, 1, SYSMON, Image=POWERSHELL, User=f"{WIN_HOST}\\administrator",
             CommandLine="powershell.exe -NoProfile -enc SQBFAFgA"),
        _win(base + timedelta(seconds=20), 1, SYSMON, Image=CMD,
             User=f"{WIN_HOST}\\administrator",
             CommandLine="cmd.exe /c whoami && net user"),
    ]
    return [], recs


def privesc(base: datetime):
    """A sudo read of /etc/shadow on Linux and a privileged logon on Windows."""
    lines = [_syslog(base, "sudo",
                     "bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow")]
    recs = [_win(base + timedelta(seconds=5), 4672, "Security", TargetUserName="administrator")]
    return lines, recs


SCENARIOS = {
    "bruteforce": bruteforce,
    "portscan": portscan,
    "c2": c2,
    "process": process,
    "privesc": privesc,
}

DESCRIPTIONS = {
    "bruteforce": "SSH brute force with a successful login (R001, R003, R004)",
    "portscan": "Nmap-style port scan (R007)",
    "c2": "Outbound connection to port 4444 (R008)",
    "process": "Encoded PowerShell and recon commands (R006)",
    "privesc": "sudo read of /etc/shadow and a privileged logon (R005)",
}


def generate_all(base: datetime):
    """All scenarios, five minutes apart so they don't overlap."""
    linux, windows = [], []
    for i, fn in enumerate(SCENARIOS.values()):
        lx, win = fn(base + timedelta(minutes=5 * i))
        linux += lx
        windows += win
    return linux, windows
