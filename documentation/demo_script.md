# Demo Script (approx. 5-7 minutes)

## 1. The problem (30s)
"This is a Mini SOC platform I built that collects security logs from
multiple sources, detects attacks using both rule-based logic and machine
learning, and manages the full incident response workflow - validated
against a real attack from a Kali Linux VM."

## 2. Show the dashboard (1 min)
- Open `http://127.0.0.1:8080/`
- Point out: total events, failed logins, severity breakdown chart, event
  timeline, top offending IPs, live event feed with filters.
- "This data came from a real Nmap scan and Hydra brute-force attack against
  an Ubuntu VM, which I'll show in a moment."

## 3. Show the alerts (1 min)
- Scroll to the alerts table.
- Point to the port-scan alert: "This detected a real Nmap scan - 1994
  distinct port probes from the attacker in under a minute, flagged with
  MITRE ATT&CK T1046."
- Point to the critical "failed logins -> successful login" alert: "This is
  Hydra finding a working password after ~20 failed attempts - a confirmed
  account compromise."

## 4. ML anomaly panel (1 min)
- Point to the separate ML panel: "These are statistical predictions, kept
  deliberately separate from confirmed rule alerts - capped below critical
  severity, shown in their own section, and they never auto-create
  incidents. Three independent methods - Isolation Forest, Z-score, and
  behaviour profiling - all flagged the same attacker IP."

## 5. Incident response (1.5 min)
- Navigate to `/incidents`.
- Click the critical compromise incident.
- "Every alert becomes a tracked incident with a classification, specific
  containment steps, and an investigation checklist drawn from a response
  playbook - not generic text, and tailored per attack type."
- Tick a checklist item, add a note, change status to "investigating", save.
- "And here's the actual evidence - the real log lines that triggered this."

## 6. Reporting (30s)
- Click "Download PDF report".
- "This generates an executive-level report on demand - severity charts, an
  incident table, and recommendations - from live data."

## 7. Splunk (optional, 30s)
- If Splunk is running: show `index=soc | stats count by source` and the
  dashboard.
- "Everything also forwards to Splunk via HEC, with a checkpoint system so
  re-running the sync never duplicates data."

## 8. Code quality (1 min, if asked or for a technical audience)
- "106 automated tests covering every component."
- Run `pytest -v` live, or show the summary line.
- "I also found and fixed a real duplicate-ingestion bug using a
  content-hash fingerprint - worth mentioning since it came from actually
  running this against a live attack, not just designing it on paper."

## Closing line
"This started as a learning project, but by running it against a real
attack instead of just synthetic data, I hit real engineering problems -
timestamp format mismatches, telemetry gaps, duplicate data - and fixing
them is honestly the part I learned the most from."
