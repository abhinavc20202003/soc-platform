"""Mini SOC API and dashboard."""
import json
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Annotated, Literal, Optional

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import config
from database import db
from detection.engine import run_detection
from incident_response import manager
from ml_engine.engine import run_ml
from parsers.schema import EVENT_TYPES, SEVERITIES, validate_ip


@asynccontextmanager
async def lifespan(_app):
    db.init_db()
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan)
templates = Jinja2Templates(directory=str(config.BASE_DIR / "templates"))

IncidentId = Annotated[str, Path(pattern=r"^INC-\d{4}-\d{4,}$")]


class IncidentUpdate(BaseModel):
    status: Optional[Literal["open", "investigating", "contained", "resolved", "false_positive"]] = None
    notes: Optional[str] = Field(default=None, max_length=5000)
    checklist_done: Optional[list[bool]] = Field(default=None, max_length=50)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": config.APP_NAME, "version": config.APP_VERSION}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"app_name": config.APP_NAME})


@app.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request):
    return templates.TemplateResponse(request, "incidents.html", {"app_name": config.APP_NAME})


@app.get("/api/stats")
def api_stats() -> dict:
    return db.get_stats()


@app.get("/api/events")
def api_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
) -> list:
    if event_type and event_type not in EVENT_TYPES:
        raise HTTPException(422, f"event_type must be one of {EVENT_TYPES}")
    if severity and severity not in SEVERITIES:
        raise HTTPException(422, f"severity must be one of {SEVERITIES}")
    if source_ip:
        source_ip = validate_ip(source_ip)
        if source_ip is None:
            raise HTTPException(422, "source_ip is not a valid IP address")
    return db.search_events(event_type, severity, source_ip, limit)


@app.get("/api/alerts")
def api_alerts(limit: int = Query(100, ge=1, le=500)) -> list:
    alerts = db.fetch_alerts(limit)
    for a in alerts:
        try:
            a["evidence"] = json.loads(a["evidence"] or "[]")
        except json.JSONDecodeError:
            a["evidence"] = []
    return alerts


@app.post("/api/detect")
def api_detect() -> dict:
    alerts, new = run_detection()
    return {"alerts_detected": len(alerts), "new_alerts": new}


# ---------------------------------------------------------------- incidents
@app.post("/api/incidents/generate")
def api_generate_incidents() -> dict:
    return {"new_incidents": manager.generate_incidents()}


@app.get("/api/incidents")
def api_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
) -> list:
    if status and status not in db.INCIDENT_STATUSES:
        raise HTTPException(422, f"status must be one of {db.INCIDENT_STATUSES}")
    if severity and severity not in SEVERITIES:
        raise HTTPException(422, f"severity must be one of {SEVERITIES}")
    return manager.list_incidents(status, severity, limit)


@app.get("/api/incidents/{incident_id}")
def api_incident_detail(incident_id: IncidentId) -> dict:
    incident = manager.get_incident_detail(incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident


@app.patch("/api/incidents/{incident_id}")
def api_update_incident(update: IncidentUpdate, incident_id: IncidentId) -> dict:
    try:
        result = manager.update_incident(
            incident_id, update.status, update.notes, update.checklist_done
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if result is None:
        raise HTTPException(404, "Incident not found")
    return result
# ---------------------------------------------------------------- ML anomalies
@app.post("/api/ml/run")
def api_ml_run() -> dict:
    anomalies, new = run_ml()
    return {"anomalies_detected": len(anomalies), "new_anomalies": new}


@app.get("/api/anomalies")
def api_anomalies(limit: int = Query(100, ge=1, le=500)) -> list:
    rows = db.fetch_anomalies(limit)
    for r in rows:
        try:
            r["features"] = json.loads(r["features"] or "{}")
        except json.JSONDecodeError:
            r["features"] = {}
    return rows

# ---------------------------------------------------------------- reports
@app.get("/api/reports/csv")
def api_report_csv():
    from fastapi.responses import Response
    from reports.csv_report import build_alerts_csv
    from reports.data import build_report_data

    csv_text = build_alerts_csv(build_report_data())
    filename = f"mini-soc-alerts-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
    return Response(
        content=csv_text, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/reports/pdf")
def api_report_pdf():
    from fastapi.responses import FileResponse
    from reports.data import build_report_data
    from reports.pdf_report import build_pdf_report

    out_dir = config.BASE_DIR / "logs" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"mini-soc-report-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.pdf"
    out_path = out_dir / filename
    build_pdf_report(build_report_data(), out_path)
    return FileResponse(out_path, media_type="application/pdf", filename=filename)
