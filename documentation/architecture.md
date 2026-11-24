# System Architecture

```mermaid
flowchart TD
    subgraph Sources["Log Sources"]
        A1[Linux auth.log / journalctl]
        A2[Windows Security + Sysmon]
        A3[Windows Firewall log]
        A4[Linux UFW log]
        A5[Attack Simulator]
    end

    subgraph Ingestion["Ingestion & Normalization"]
        B1[Parsers<br/>linux_auth / windows_events /<br/>windows_firewall / linux_ufw]
        B2[Normalized Event Schema<br/>timestamp, source_ip, dest_ip,<br/>dest_port, user, event_type, severity]
        B3[(SQLite Database<br/>events / alerts / incidents / anomalies)]
    end

    subgraph Detection["Detection Layer"]
        C1[Rule Engine<br/>R001-R008]
        C2[ML Engine<br/>Isolation Forest / Z-score / Behaviour]
    end

    subgraph Response["Response & Reporting"]
        D1[Incident Manager<br/>+ Playbooks]
        D2[PDF / CSV Reports]
    end

    subgraph Delivery["Delivery"]
        E1[FastAPI Backend]
        E2[SOC Dashboard<br/>Bootstrap + Chart.js]
        E3[Incidents UI]
        E4[Splunk HEC<br/>Events / Alerts / Anomalies]
    end

    A1 & A2 & A3 & A4 & A5 --> B1 --> B2 --> B3
    B3 --> C1
    B3 --> C2
    C1 -->|alerts| B3
    C2 -->|anomalies| B3
    B3 --> D1
    D1 --> B3
    B3 --> D2
    B3 --> E1
    E1 --> E2
    E1 --> E3
    B3 --> E4
```

## Data flow summary

1. **Collection** - Logs arrive from Linux auth, Windows Event Log/Sysmon, Windows Firewall, Linux UFW, or the built-in attack simulator.
2. **Normalization** - Each source has its own parser, but every parser outputs the same event schema (`parsers/schema.py`), so downstream code never needs to know where an event came from.
3. **Storage** - Events are deduplicated by content hash and stored in SQLite (`database/db.py`).
4. **Detection** - Two independent engines run over the same event store:
   - **Rules** (`detection/rules.py`, `detection/network_rules.py`) produce confirmed, explainable alerts (R001-R008).
   - **ML** (`ml_engine/`) produces statistical anomaly predictions (Isolation Forest, Z-score, behaviour profiling), kept in a separate table and capped below `critical` severity.
5. **Response** - Each alert becomes a tracked incident (`incident_response/`) with a playbook: classification, containment steps, and an investigation checklist.
6. **Delivery** - A FastAPI backend (`app.py`) serves a dark-themed dashboard and incident-management UI, exports PDF/CSV reports, and forwards everything to Splunk via HEC for SPL search and alerting.
