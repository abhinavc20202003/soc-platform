# AI-Powered Mini SOC

A functional Security Operations Centre platform: it collects logs from Linux
and Windows systems, detects attacks using both rule-based logic and machine
learning, tracks incidents through a full response workflow, and reports on
everything through a dashboard, PDF/CSV exports, and Splunk integration.

Built as a portfolio project to demonstrate practical SOC engineering: log
parsing, detection engineering, ML-based anomaly detection, incident response,
and SIEM integration, validated against a real attack lab (Kali vs. Ubuntu).

## Features

- **Multi-source log collection**: Linux auth logs, Windows Security/Sysmon
  events, Windows Firewall logs, and Linux UFW logs, all normalized to one
  event schema.
- **Rule-based detection (8 rules)**: brute force, per-account targeting,
  failed-then-successful login (compromise), credential guessing,
  blocklisted IPs, privilege escalation, suspicious process execution, port
  scanning, and suspicious-port connections (C2).
- **ML anomaly detection**: Isolation Forest (multivariate outliers),
  Z-score (volume spikes), and behaviour profiling (new source IP, unseen
  account, off-hours login) - kept clearly separate from confirmed rule
  alerts.
- **Incident response**: every alert becomes a tracked incident with a
  classification, containment playbook, investigation checklist, analyst
  notes, and a status lifecycle (open -> investigating -> contained ->
  resolved / false positive).
- **Dashboard**: dark-themed, live event feed, severity/timeline charts,
  alert table, and ML anomaly panel.
- **Reporting**: on-demand PDF (executive summary, charts, incident/alert
  tables, recommendations) and CSV export.
- **Splunk integration**: HEC-based forwarding of events, alerts, and
  anomalies, with sample SPL queries and a dashboard definition.
- **Attack simulator**: five scripted attack scenarios (brute force, port
  scan, C2, suspicious process, privilege escalation) for repeatable testing.
- **Validated in a real lab**: a Kali VM scanning and brute-forcing an Ubuntu
  VM, detected end-to-end through the real pipeline (see
  `documentation/lab_results.md`).
- **106 automated tests** covering parsers, detection rules, the ML engine,
  the API, incident management, Splunk integration, and deduplication.

## Architecture

See [`documentation/architecture.md`](documentation/architecture.md) for a
full diagram and data-flow explanation. In short:Log sources -> Parsers -> Normalized events -> SQLite
|
+-------------------+-------------------+
| |
Rule engine (R001-R008) ML engine (Isolation
| Forest/Z-score/behaviour)
v |
Incident manager <------------------------------+
+ playbooks
|
+---------------+----------------+
v v
FastAPI dashboard PDF/CSV reports + Splunk HEC

## Tech stack

Python, FastAPI, SQLite, scikit-learn (Isolation Forest), Bootstrap, Chart.js,
ReportLab, Splunk Enterprise (HEC), pytest.

## Project structure
soc-platform/
app.py FastAPI app and all API routes
config.py Central configuration
ingest.py CLI: load a log file into the database
detect.py CLI: run detection + generate incidents
run_ml.py CLI: run ML anomaly detection
push_splunk.py CLI: forward data to Splunk via HEC
simulate.py CLI: generate synthetic attack logs
parsers/ One parser per log source, normalized schema
database/ SQLite layer (schema, migrations, queries)
detection/ Rule-based detection engine
ml_engine/ Isolation Forest, Z-score, behaviour profiling
incident_response/ Incident manager + response playbooks
reports/ PDF and CSV report builders
integrations/splunk.py Splunk HEC client
templates/ Dashboard and incidents HTML
tests/ 106 tests across every module
sample_logs/ Synthetic sample logs for quick testing
documentation/ Architecture, Splunk queries, lab results, demo script

## Setup

Requires Python 3.12 and Windows PowerShell (commands below are for Windows;
adapt paths for macOS/Linux).

```powershell
git clone <your-repo-url>
cd soc-platform
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Quick start

```powershell
# Load sample data
python ingest.py linux sample_logs\linux_auth.log
python ingest.py windows sample_logs\windows_events.jsonl

# Run detection and create incidents
python detect.py

# Run ML anomaly detection
python run_ml.py

# Start the dashboard
uvicorn app:app --reload --port 8080
```

Open `http://127.0.0.1:8080/` for the dashboard and
`http://127.0.0.1:8080/incidents` for incident management.
API docs: `http://127.0.0.1:8080/docs`.

## Running the attack simulator

```powershell
python simulate.py list
python simulate.py all --ingest
```

This generates and ingests five attack scenarios in one step, triggering all
8 detection rules.

## Running the test suite

```powershell
pytest -v
```

106 tests, covering parsers, detection rules, the ML engine, incident
management, the API, Splunk integration, and deduplication.

## Splunk integration (optional)

See [`documentation/splunk_queries.md`](documentation/splunk_queries.md) for
setup steps, sample SPL queries, and the dashboard XML. Requires a Splunk
Enterprise trial license (Free tier does not support scheduled alerts).

```powershell
python push_splunk.py
```

## Real attack lab

This platform was validated against a real attack, not just synthetic data:
a Kali Linux VM running Nmap and Hydra against an Ubuntu VM. See
[`documentation/lab_results.md`](documentation/lab_results.md) for the full
write-up, including real detection output.

## Known limitations

- Isolation Forest trains on a synthetic baseline; a production deployment
  would train on weeks of reviewed real traffic.
- Log transfer from VMs is manual (shared folder / scp); continuous
  collection (e.g. a lightweight forwarder) is a natural next step.
- No authentication on the dashboard/API yet - designed for localhost-only
  use in this portfolio context.
- One incident is created per alert; correlating related alerts (e.g. the
  same IP triggering brute force, port scan, and credential guessing) into a
  single case is a reasonable next enhancement.
- The privilege-escalation rule (R005) is intentionally broad (it flags any
  sudo session), which is realistic but noisy - tuning it with an allowlist
  of routine admin commands would be a sensible next step.

## Interview preparation

See [`documentation/interview_qa.md`](documentation/interview_qa.md) for
questions and answers based on real design decisions and real debugging from
building this project.
