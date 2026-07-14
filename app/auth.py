"""Authentication: password + TOTP login, signed sessions, API tokens.

Everything is standard-library crypto:
  * Passwords are PBKDF2-HMAC-SHA256 ("pbkdf2_sha256:<iter>:<salt>:<hash>",
    colon-separated so compose files never see a `$` to interpolate).
  * MFA is RFC 6238 TOTP (SHA1/30s/6 digits — what authenticator apps use),
    accepting one timestep of clock drift and refusing code replay.
  * Sessions are HMAC-SHA256-signed tokens with an absolute expiry
    (SESSION_DAYS, default 30), carried in an HttpOnly cookie.
  * API tokens (for Claude Code and scripts) are compared in constant time
    against the API_TOKENS list.

Auth is enabled when AUTH_PASSWORD_HASH, TOTP_SECRET and SESSION_SECRET are
all configured; otherwise the app falls back to the LAN-only IP guard.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time

from app.config import settings

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000


def hash_password(password: str, iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Hash a password for storage in AUTH_PASSWORD_HASH."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return ":".join(
        (
            "pbkdf2_sha256",
            str(iterations),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification against a stored hash."""
    try:
        algorithm, iterations, salt_b64, hash_b64 = encoded.split(":")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
    return hmac.compare_digest(digest, expected)


# ---------------------------------------------------------------------------
# TOTP (RFC 6238)
# ---------------------------------------------------------------------------

_TOTP_PERIOD = 30
_TOTP_DIGITS = 6

# Highest timestep already accepted, to refuse replayed codes.
_last_used_step: int = 0
_totp_lock = threading.Lock()


def totp_code(secret_b32: str, timestep: int) -> str:
    """Compute the TOTP code for one timestep."""
    key = base64.b32decode(secret_b32.upper().replace(" ", ""))
    digest = hmac.new(key, struct.pack(">Q", timestep), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 10 ** _TOTP_DIGITS:0{_TOTP_DIGITS}d}"


def verify_totp(secret_b32: str, code: str, now: float | None = None) -> bool:
    """Check a submitted code against the current, previous and next step.

    A given timestep is only accepted once (replay protection); an attacker
    who shoulder-surfs a code cannot reuse it inside its validity window.
    """
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    current = int((now if now is not None else time.time()) // _TOTP_PERIOD)
    global _last_used_step
    with _totp_lock:
        for step in (current, current - 1, current + 1):
            if step <= _last_used_step:
                continue
            if hmac.compare_digest(totp_code(secret_b32, step), code):
                _last_used_step = step
                return True
    return False


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

SESSION_COOKIE = "wt_session"


def create_session(username: str, now: float | None = None) -> str:
    """Create a signed session token expiring SESSION_DAYS from now."""
    issued = now if now is not None else time.time()
    payload = {"u": username, "exp": int(issued + settings.session_days * 86400)}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{body}.{_sign(body)}"


def verify_session(token: str, now: float | None = None) -> str | None:
    """Return the username for a valid, unexpired session token."""
    try:
        body, signature = token.split(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(body), signature):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, TypeError):
        return None
    current = now if now is not None else time.time()
    if current >= payload.get("exp", 0):
        return None
    return payload.get("u")


def _sign(body: str) -> str:
    return hmac.new(settings.session_secret.encode(), body.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# API tokens
# ---------------------------------------------------------------------------

def verify_api_token(presented: str) -> bool:
    """Constant-time check against the configured API tokens."""
    return any(hmac.compare_digest(presented, token) for token in settings.api_tokens)


# ---------------------------------------------------------------------------
# Login throttle
# ---------------------------------------------------------------------------

_WINDOW_SECONDS = 900
_MAX_FAILURES = 10

_failures: dict[str, list[float]] = {}
_throttle_lock = threading.Lock()


def throttled(client: str, now: float | None = None) -> bool:
    """True when this client has exhausted its failed-login budget."""
    current = now if now is not None else time.monotonic()
    with _throttle_lock:
        attempts = [t for t in _failures.get(client, []) if current - t < _WINDOW_SECONDS]
        _failures[client] = attempts
        return len(attempts) >= _MAX_FAILURES


def record_failure(client: str, now: float | None = None) -> None:
    """Register a failed login attempt for the throttle."""
    current = now if now is not None else time.monotonic()
    with _throttle_lock:
        _failures.setdefault(client, []).append(current)


def login(username: str, password: str, code: str) -> bool:
    """Full credential check: username, password, then TOTP."""
    if not hmac.compare_digest(username, settings.auth_username):
        # Burn the same time as a real check to avoid a username oracle.
        verify_password(password, settings.auth_password_hash)
        return False
    if not verify_password(password, settings.auth_password_hash):
        return False
    return verify_totp(settings.totp_secret, code)
