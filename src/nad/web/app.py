"""FastAPI application factory.

The CLI builds a `MonitorService` and hands it to `create_app(service)` —
keeps the web layer free of capture/detection knowledge.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..service import MonitorService


STATIC_DIR = Path(__file__).parent / "static"


def create_app(service: MonitorService) -> FastAPI:
    app = FastAPI(title="Network Anomaly Detector", version="0.0.1")

    @app.on_event("startup")
    def _startup() -> None:
        service.start()

    @app.on_event("shutdown")
    def _shutdown() -> None:
        service.stop()

    @app.get("/api/status")
    def get_status() -> JSONResponse:
        return JSONResponse(service.status())

    @app.get("/api/windows")
    def get_windows(limit: int = 60) -> JSONResponse:
        return JSONResponse(service.windows(limit=limit))

    @app.get("/api/alerts")
    def get_alerts(limit: int = 50) -> JSONResponse:
        return JSONResponse(service.alerts(limit=limit))

    @app.get("/api/baseline")
    def get_baseline() -> JSONResponse:
        return JSONResponse(service.baseline())

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app
