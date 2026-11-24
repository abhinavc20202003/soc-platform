# Real Attack Lab Results

This platform was validated against a real attack, not just synthetic data.

## Setup

- **Attacker**: Kali Linux VM, host-only network, `192.168.56.150`
- **Target**: Ubuntu Desktop VM, host-only network, `192.168.56.20`
- **Network**: VirtualBox host-only adapter (`192.168.56.0/24`), no internet
  route for the attacker VM
- **Target hardening for logging**: OpenSSH server installed and running,
  UFW enabled (`default deny incoming`, port 22 allowed, logging on), system
  clock set to UTC

## Attacks performed

| Attack | Tool | Target | Detection |
|---|---|---|---|
| Port scan (ports 1-1000) | `nmap -sS -T4 -Pn` | `192.168.56.20` | R007 Port scan detected |
| SSH brute force (4 users x 8 passwords) | `hydra` | `192.168.56.20:22` | R001, R002, R004 |
| Account compromise | `hydra` (found `labuser:Summer2026!`) | `192.168.56.20` | R003 (critical) |
| Privilege escalation | `sudo cat /etc/shadow` | `192.168.56.20` | R005 (critical) |

## Real detection output
14 alerts detected (14 new saved)

[HIGH ] R005 Privilege escalation indicator user=None events=39
[CRITICAL] R005 Privilege escalation indicator user=vboxuser events=37
[HIGH ] R007 Port scan detected ip=192.168.56.150 events=1994
[HIGH ] R001 Brute-force login attempts ip=192.168.56.150 events=20
[MEDIUM ] R002 Multiple failed authentications user=root events=8
[CRITICAL] R003 Failed logins -> successful login user=labuser events=21
[MEDIUM ] R004 Credential guessing (many accounts) ip=192.168.56.150 events=59
...
14 new incidents created

Every alert category fired against real traffic: port scanning, brute force,
per-account targeting, credential guessing across accounts, a confirmed
account compromise, and privilege escalation.

## Debugging notes (see also `interview_qa.md`)

Two real issues came up and were fixed during this lab run, not anticipated
in advance:

1. **Timestamp format.** Ubuntu 26.04's `/var/log/auth.log` uses ISO-8601
   timestamps, not the classic syslog format the parser originally expected.
   Fixed by adding a second timestamp-parsing path, with regression tests
   for both formats.
2. **Telemetry choice for port scanning.** A SYN scan mostly produces
   closed/filtered responses, which Sysmon-style connection logging doesn't
   capture. Firewall logs (Windows Firewall, and UFW for this Linux-only
   lab) record every probed port regardless of outcome, which is why the
   port-scan rule reads from firewall logs rather than connection events.

## Screenshots

See `documentation/screenshots/` for the Nmap/Hydra terminal output, the
dashboard view of this run, and the port-scan incident detail with its real
evidence.
