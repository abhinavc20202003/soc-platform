# Interview Q&A - AI-Powered Mini SOC

Real questions you might get, answered from what was actually built and
actually debugged in this project.

## Architecture & design

**Q: Why separate rule-based alerts from ML anomalies instead of one unified
alert table?**
A: They answer different questions. A rule alert means "this matched a known
bad pattern" - it's confirmed and explainable. An ML anomaly means "this is
statistically unusual compared to a baseline" - it's a lead, not a
conclusion. Mixing them risks an analyst treating a prediction as a fact.
Concretely: ML anomalies live in their own table, are capped below
`critical` severity, and never auto-generate incidents. The dashboard shows
them in a clearly labelled "unconfirmed" panel.

**Q: Why normalize every log source to one event schema instead of keeping
each format native?**
A: So every downstream component - detection rules, the ML feature builder,
the dashboard, Splunk forwarding - works against one contract and doesn't
need to know whether an event came from a Windows Event Log, a Linux
syslog line, or a firewall log. Adding a new source (which happened twice:
Windows Firewall logs, then Linux UFW logs) only means writing one new
parser; nothing else changes.

**Q: Why three different ML methods instead of just the Isolation Forest?**
A: They catch different failure modes. Isolation Forest finds multivariate
outliers but can't extrapolate past the range it trained on. Z-score catches
pure volume spikes directly against a learned mean/stddev, which is more
sensitive to extreme bursts. Behaviour profiling catches things volume-based
methods structurally can't see at all - like a normal-volume login from an
account's completely new source IP. In the real lab, all three independently
flagged the attacker IP from different angles, which is a strong
corroboration signal.

## Real debugging stories (use these - they show genuine problem-solving)

**Q: Tell me about a bug you had to debug in this project.**
A: During the real Kali-vs-Ubuntu lab, my brute-force and failed-then-success
rules didn't fire even though Hydra clearly succeeded. I traced it to a
timestamp-format mismatch: the parser was built for classic syslog format
(`Nov 24 10:00:01`), but Ubuntu 26.04's `/var/log/auth.log` uses ISO-8601
(`2026-11-24T05:45:07.320220+00:00`) via newer rsyslog defaults. The regex
silently failed on every line, so nothing parsed - not an exception, just
zero events. I fixed it by adding a second regex path that detects and
parses the ISO-8601 format, while keeping the original format for backward
compatibility, and added regression tests for both formats.

**Q: Describe a design decision you had to revisit.**
A: My original port-scan detection relied on Sysmon's network-connection
events. But a SYN scan mostly hits closed or filtered ports, and Sysmon only
logs completed connections - so a real Nmap scan would've produced almost no
Sysmon data, and the rule would never fire on the exact attack it was built
for. I had to add a firewall-log parser (Windows Firewall and, for the Linux
side of the lab, UFW) specifically because that's where every probed port -
successful or not - actually gets recorded. This is a good example of
"the telemetry source has to match what the detection logic needs," which
isn't obvious until you try to detect a real attack.

**Q: How did you handle duplicate data?**
A: I found through testing that re-ingesting the same log file (which
happens naturally if a collector restarts and re-reads a file) silently
created duplicate events, which then skewed alert counts (a brute-force
alert showing double the real event count) and poisoned the ML baseline. I
fixed it with a content-hash fingerprint on each event - hashing the raw log
line (or key fields, for synthetic events without raw text) - enforced as a
unique index in SQLite. Inserts use `INSERT OR IGNORE`, so re-ingesting a
file becomes a safe no-op. I also wrote a one-time migration that cleans up
and backfills hashes for existing databases automatically on startup, so no
manual fix was needed for data already collected.

**Q: What would you do differently with more time?**
A: Three things: (1) make the privilege-escalation rule less noisy with an
allowlist for routine sudo commands, since right now it flags every sudo
session, not just suspicious ones; (2) correlate related alerts from the
same source into a single incident rather than creating one incident per
alert, since a real attack chain (scan -> brute force -> compromise) is
really one story, not four; (3) move from manual file-based log transfer to
a lightweight forwarder for continuous collection.

## Detection logic specifics

**Q: How does your brute-force detection avoid false positives on normal
retry behaviour (e.g. someone mistyping their password twice)?**
A: It requires both a minimum count (5 failures by default) and a time
window (60 seconds) - so it's specifically burst behaviour, not occasional
errors. The baseline generator for the ML engine also explicitly includes
"legitimate lockout" scenarios (a few failures then a correct password) so
the ML side learns that pattern as normal too, not just the rule engine.

**Q: Why cap ML anomaly severity below critical?**
A: Because ML output is a statistical prediction, not a confirmed detection,
and critical severity should be reserved for alerts an analyst can act on
immediately with confidence. Capping severity, keeping ML alerts in a
separate table, and not auto-generating incidents from them are all the same
design principle applied three different ways: don't let a probabilistic
signal masquerade as a certain one.

**Q: Walk me through what happens when a port scan is detected.**
A: The firewall or UFW parser turns each blocked connection attempt into a
`network_connection` event with a source IP, destination IP, and
destination port. The `port_scan` rule groups events by (source, target) and
looks for bursts where 10+ *distinct* ports are hit within 60 seconds (not
just high volume - repeatedly hitting one port doesn't count, which is
covered by a dedicated test). When it fires, it creates an alert with MITRE
ATT&CK T1046, which then becomes an incident with a specific playbook:
confirm the source isn't an authorised scanner, check which ports actually
responded, and check for follow-up connections from the same source.

## General SOC/security knowledge

**Q: What's the difference between a SIEM and a SOAR?**
A: A SIEM (this platform's dashboard + Splunk integration) aggregates and
correlates security data to generate alerts. A SOAR goes further by
automating the response - in this project, the incident manager with
playbooks and checklists is a manual, analyst-driven version of what a SOAR
would automate (auto-blocking an IP, auto-isolating a host, etc.).

**Q: Why MITRE ATT&CK mapping on your alerts?**
A: It gives every alert a standard, industry-recognized reference point
(e.g. T1110 for brute force, T1046 for network scanning) instead of an
ad-hoc description, which makes alerts meaningful to anyone familiar with
the framework and supports building detection coverage maps later.
