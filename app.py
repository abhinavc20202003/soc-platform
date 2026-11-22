"""Mini SOC API and dashboard."""
import json
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import config
from database import db
from detection.engine import run_detection
from parsers.schema import EVENT_TYPES, SEVERITIES, validate_ip


@asynccontextmanager
async def lifespan(_app):
    db.init_db()
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan)
templates = Jinja2Templates(directory=str(config.BASE_DIR / "templates"))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": config.APP_NAME, "version": config.APP_VERSION}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"app_name": config.APP_NAME})


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