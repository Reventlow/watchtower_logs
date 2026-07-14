"""FastAPI application serving the watchtower log dashboard.

Routes:
  GET  /               - the dashboard
  GET  /auth/login     - login page (username + password + TOTP)
  POST /auth/session   - create a session (sets a 30-day cookie)
  POST /auth/logout    - clear the session cookie
  GET  /api/logs       - historical entries (filterable)
  GET  /api/stats      - aggregate stats for the header / stat tiles
  GET  /api/stream     - server-sent events with live entries + stats
  POST /api/test-alert - send a test notification to ntfy
  GET  /healthz        - container healthcheck

Access control: when auth is configured (AUTH_PASSWORD_HASH + TOTP_SECRET +
SESSION_SECRET) every route except /auth/*, /healthz and /static/* requires
a session cookie or an API bearer token. Independently, the IP allowlist in
netguard.py applies when ALLOWED_NETWORKS is non-empty — and as a safe
default the app refuses to start wide open (no auth AND no allowlist).
"""

import asyncio
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from app import auth, docker_logs
from app.alerts import notifier
from app.config import settings
from app.netguard import client_ip, lan_only_middleware
from app.store import store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="watchtower logs", docs_url=None, redoc_url=None)

# Paths reachable without a session: the login flow, the container
# healthcheck, and static assets (UI shell only — all data sits behind /api).
_PUBLIC_PATHS = {"/auth/login", "/auth/session", "/healthz"}


async def auth_middleware(request: Request, call_next):
    """Require a valid session cookie or API bearer token."""
    path = request.url.path
    if path in _PUBLIC_PATHS or path.startswith("/static/"):
        return await call_next(request)

    token = request.cookies.get(auth.SESSION_COOKIE, "")
    if token and auth.verify_session(token):
        return await call_next(request)

    header = request.headers.get("authorization", "")
    if header.startswith("Bearer ") and auth.verify_api_token(header[7:]):
        return await call_next(request)

    # Browsers navigating to a page get the login form; API clients get 401.
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/auth/login", status_code=303)
    return JSONResponse(status_code=401, content={"detail": "Authentication required."})


# Middleware runs in reverse order of registration: IP guard (if configured)
# first, then auth.
if settings.auth_enabled:
    app.add_middleware(BaseHTTPMiddleware, dispatch=auth_middleware)
if settings.allowed_networks:
    app.add_middleware(BaseHTTPMiddleware, dispatch=lan_only_middleware)
if not settings.auth_enabled and not settings.allowed_networks:
    raise RuntimeError(
        "Refusing to start wide open: configure authentication "
        "(AUTH_PASSWORD_HASH, TOTP_SECRET, SESSION_SECRET) or ALLOWED_NETWORKS."
    )


@app.on_event("startup")
async def startup() -> None:
    """Wire the tailer thread to the serving event loop."""
    store.attach_loop(asyncio.get_running_loop())
    docker_logs.start()


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/auth/login")
async def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


class LoginBody(BaseModel):
    username: str = ""
    password: str = ""
    code: str = ""


@app.post("/auth/session")
async def create_session(request: Request, body: LoginBody) -> JSONResponse:
    """Verify credentials + TOTP and set the 30-day session cookie."""
    client = client_ip(request)
    if auth.throttled(client):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many failed attempts. Try again in 15 minutes."},
        )

    ok = await asyncio.to_thread(auth.login, body.username, body.password, body.code)
    if not ok:
        auth.record_failure(client)
        logger.warning("Failed login for %r from %s", body.username, client)
        return JSONResponse(
            status_code=401,
            content={"detail": "Wrong username, password or code."},
        )

    response = JSONResponse(content={"ok": True})
    response.set_cookie(
        auth.SESSION_COOKIE,
        auth.create_session(body.username),
        max_age=settings.session_days * 86400,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )
    logger.info("Login by %s from %s", body.username, client)
    return response


@app.post("/auth/logout")
async def logout() -> JSONResponse:
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(auth.SESSION_COOKIE)
    return response


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
