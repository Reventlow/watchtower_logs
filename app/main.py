"""FastAPI application serving the watchtower log dashboard.

Routes:
  GET  /               - the dashboard
  GET  /api/logs       - historical entries (filterable)
  GET  /api/stats      - aggregate stats for the header / stat tiles
  GET  /api/stream     - server-sent events with live entries + stats
  POST /api/test-alert - send a test notification to ntfy
  GET  /healthz        - container healthcheck

Everything is guarded by the LAN-only middleware (see netguard.py).
"""

import asyncio
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app import docker_logs
from app.alerts import notifier
from app.netguard import lan_only_middleware
from app.store import store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="watchtower logs", docs_url=None, redoc_url=None)
app.add_middleware(BaseHTTPMiddleware, dispatch=lan_only_middleware)


@app.on_event("startup")
async def startup() -> None:
    """Wire the tailer thread to the serving event loop."""
    store.attach_loop(asyncio.get_running_loop())
    docker_logs.start()


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/logs")
async def api_logs(
    level: str = Query("", pattern="^(|info|warning|error)$"),
    q: str = Query("", max_length=200),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    entries = store.entries(level=level, query=q, limit=limit)
    return {"entries": [e.to_dict() for e in entries]}


@app.get("/api/stats")
async def api_stats() -> dict:
    return store.stats()


@app.get("/api/stream")
async def api_stream() -> StreamingResponse:
    """SSE stream: new log entries as they arrive, stats every 15s."""

    async def event_source():
        queue = store.subscribe()
        try:
            yield _sse("stats", store.stats())
            while True:
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield _sse("log", entry.to_dict())
                except asyncio.TimeoutError:
                    # Heartbeat doubles as a stats refresh for the countdown.
                    yield _sse("stats", store.stats())
        finally:
            store.unsubscribe(queue)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/test-alert")
async def api_test_alert() -> dict:
    """Fire a test notification so the ntfy path can be verified end-to-end."""
    if not notifier.enabled:
        return {"sent": False, "reason": "NTFY_TOPIC is not configured"}
    sent = await asyncio.to_thread(notifier.send_test)
    return {"sent": sent}


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "connected": store.connected}


def _sse(event: str, data: dict) -> str:
    """Format one server-sent event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
