"""Tests for password hashing, TOTP, sessions, API tokens and throttling."""

import time
from dataclasses import replace
from unittest.mock import patch

from app import auth
from app.auth import (
    create_session,
    hash_password,
    throttled,
    totp_code,
    record_failure,
    verify_password,
    verify_session,
    verify_totp,
)

SECRET_B32 = "JBSWY3DPEHPK3PXP"  # standard test vector secret


def test_password_roundtrip():
    encoded = hash_password("correct horse battery staple", iterations=1000)
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)


def test_password_hash_has_no_dollar_signs():
    # Compose files interpolate `$`, so the stored format must avoid it.
    assert "$" not in hash_password("x", iterations=1000)


def test_verify_password_rejects_garbage():
    assert not verify_password("x", "")
    assert not verify_password("x", "not:a:real:hash")
    assert not verify_password("x", "md5:1:abc:def")


def test_totp_accepts_current_and_adjacent_steps(monkeypatch):
    monkeypatch.setattr(auth, "_last_used_step", 0)
    now = 1_700_000_000.0
    step = int(now // 30)
    assert verify_totp(SECRET_B32, totp_code(SECRET_B32, step), now=now)
    monkeypatch.setattr(auth, "_last_used_step", 0)
    assert verify_totp(SECRET_B32, totp_code(SECRET_B32, step - 1), now=now)
    monkeypatch.setattr(auth, "_last_used_step", 0)
    assert verify_totp(SECRET_B32, totp_code(SECRET_B32, step + 1), now=now)


def test_totp_rejects_wrong_and_stale_codes(monkeypatch):
    monkeypatch.setattr(auth, "_last_used_step", 0)
    now = 1_700_000_000.0
    step = int(now // 30)
    assert not verify_totp(SECRET_B32, "000000", now=now)
    assert not verify_totp(SECRET_B32, totp_code(SECRET_B32, step - 5), now=now)
    assert not verify_totp(SECRET_B32, "abc123", now=now)


def test_totp_replay_is_refused(monkeypatch):
    monkeypatch.setattr(auth, "_last_used_step", 0)
    now = 1_700_000_000.0
    code = totp_code(SECRET_B32, int(now // 30))
    assert verify_totp(SECRET_B32, code, now=now)
    assert not verify_totp(SECRET_B32, code, now=now)


def _session_settings():
    return replace(
        auth.settings,
        session_secret="unit-test-secret",
        session_days=30,
    )


def test_session_roundtrip_and_expiry():
    with patch.object(auth, "settings", _session_settings()):
        now = time.time()
        token = create_session("gorm", now=now)
        assert verify_session(token, now=now) == "gorm"
        # Still valid a day before the deadline, dead after 30 days.
        assert verify_session(token, now=now + 29 * 86400) == "gorm"
        assert verify_session(token, now=now + 30 * 86400) is None


def test_session_tampering_rejected():
    with patch.object(auth, "settings", _session_settings()):
        token = create_session("gorm")
        body, signature = token.split(".", 1)
        assert verify_session(f"{body}x.{signature}") is None
        assert verify_session(f"{body}.{'0' * len(signature)}") is None
        assert verify_session("garbage") is None


def test_api_token_check():
    with patch.object(auth, "settings", replace(auth.settings, api_tokens=["tok-a", "tok-b"])):
        assert auth.verify_api_token("tok-b")
        assert not auth.verify_api_token("tok-c")
        assert not auth.verify_api_token("")


def test_throttle_kicks_in_after_ten_failures(monkeypatch):
    monkeypatch.setattr(auth, "_failures", {})
    now = 1000.0
    for _ in range(10):
        assert not throttled("1.2.3.4", now=now)
        record_failure("1.2.3.4", now=now)
    assert throttled("1.2.3.4", now=now)
    # Another client is unaffected; the window eventually expires.
    assert not throttled("5.6.7.8", now=now)
    assert not throttled("1.2.3.4", now=now + 901)


def test_login_requires_all_three_factors(monkeypatch):
    monkeypatch.setattr(auth, "_last_used_step", 0)
    configured = replace(
        auth.settings,
        auth_username="gorm",
        auth_password_hash=hash_password("hunter2", iterations=1000),
        totp_secret=SECRET_B32,
    )
    with patch.object(auth, "settings", configured):
        code = totp_code(SECRET_B32, int(time.time() // 30))
        assert not auth.login("wrong", "hunter2", code)
        assert not auth.login("gorm", "wrong", code)
        assert not auth.login("gorm", "hunter2", "000000")
        assert auth.login("gorm", "hunter2", code)
