"""Entry point for the Mini SOC API."""
from fastapi import FastAPI

import config

app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
    }