from parsers import linux_auth, windows_events


def test_linux_failed_password():
    line = "Nov 22 10:00:01 web01 sshd[1201]: Failed password for root from 203.0.113.50 port 51000 ssh2"
    ev = linux_auth.parse_line(line, year=2026)
    assert ev["event_type"] == "login_failed"
    assert ev["source_ip"] == "203.0.113.50"
    assert ev["username"] == "root"
    assert ev["severity"] == "medium"


def test_linux_invalid_user():
    line = "Nov 22 10:00:07 web01 sshd[1201]: Failed password for invalid user test from 203.0.113.50 port 51006 ssh2"
    ev = linux_auth.parse_line(line, year=2026)
    assert ev["username"] == "test"


def test_linux_accepted_login():
    line = "Nov 22 10:10:00 web01 sshd[1305]: Accepted publickey for alice from 192.168.56.10 port 40222 ssh2"
    ev = linux_auth.parse_line(line, year=2026)
    assert ev["event_type"] == "login_success"


def test_linux_sudo_is_privilege_escalation():
    line = "Nov 22 10:05:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    ev = linux_auth.parse_line(line, year=2026)
    assert ev["event_type"] == "privilege_escalation"
    assert ev["username"] == "alice"


def test_linux_garbage_returns_none():
    assert linux_auth.parse_line("not a log line") is None
    assert linux_auth.parse_line("") is None


def test_windows_failed_logon():
    line = '{"TimeCreated":"2026-11-22T10:00:01Z","EventID":4625,"Channel":"Security","Computer":"WIN","TargetUserName":"administrator","IpAddress":"192.168.56.101"}'
    ev = windows_events.parse_line(line)
    assert ev["event_type"] == "login_failed"
    assert ev["source"] == "windows_security"
    assert ev["source_ip"] == "192.168.56.101"


def test_windows_sysmon_suspicious_process():
    line = '{"TimeCreated":"2026-11-22T10:02:00Z","EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WIN","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe"}'
    ev = windows_events.parse_line(line)
    assert ev["event_type"] == "process_creation"
    assert ev["source"] == "windows_sysmon"
    assert ev["severity"] == "medium"


def test_windows_bad_json_returns_none():
    assert windows_events.parse_line("{broken") is None
    assert windows_events.parse_line('{"EventID": 4625}') is None


def test_invalid_ip_is_dropped():
    line = "Nov 22 10:00:01 web01 sshd[1]: Failed password for root from 999.1.1.1 port 1 ssh2"
    ev = linux_auth.parse_line(line, year=2026)
    assert ev["source_ip"] is None

def test_linux_iso8601_failed_password():
    line = "2026-11-24T05:45:07.320220+00:00 ubuntu sshd-session[7375]: Failed password for labuser from 192.168.56.150 port 50000 ssh2"
    ev = linux_auth.parse_line(line)
    assert ev["event_type"] == "login_failed"
    assert ev["source_ip"] == "192.168.56.150"
    assert ev["username"] == "labuser"


def test_linux_iso8601_accepted_login():
    line = "2026-11-24T05:46:06.665043+00:00 ubuntu sshd-session[7375]: Accepted password for vboxuser from 192.168.56.1 port 57261 ssh2"
    ev = linux_auth.parse_line(line)
    assert ev["event_type"] == "login_success"
    assert ev["username"] == "vboxuser"


def test_linux_iso8601_sudo_shadow_access():
    line = "2026-11-24T05:45:04+00:00 ubuntu sudo: vboxuser : TTY=/dev/pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    ev = linux_auth.parse_line(line)
    assert ev["event_type"] == "privilege_escalation"
    assert ev["username"] == "vboxuser"
