"""Tests for the alert rules and the LAN access guard."""

from dataclasses import replace
from unittest.mock import patch

from app import alerts
from app.alerts import Notifier
from app.netguard import _is_allowed
from app.parser import parse_line


def _sent_by(line: str) -> bool:
    """Run one line through the notifier; report whether it would alert."""
    notifier = Notifier()
    entry = parse_line(line)
    assert entry is not None
    enabled_settings = replace(alerts.settings, ntfy_topic="test-topic")
    with (
        patch.object(alerts, "settings", enabled_settings),
        patch.object(notifier, "_post", return_value=True) as post,
    ):
        notifier.evaluate(entry)
    return post.called


def test_error_line_alerts():
    assert _sent_by('time="2026-07-14T05:00:00Z" level=error msg="Unable to update container"')


def test_warning_line_alerts():
    assert _sent_by('time="2026-07-14T05:00:00Z" level=warning msg="Could not do a head request"')


def test_failed_session_alerts():
    assert _sent_by(
        'time="2026-07-14T05:00:00Z" level=info msg="Session done" '
        "Failed=1 Scanned=3 Updated=0 notify=no"
    )


def test_clean_session_stays_quiet():
    assert not _sent_by(
        'time="2026-07-14T05:00:00Z" level=info msg="Session done" '
        "Failed=0 Scanned=3 Updated=1 notify=no"
    )


def test_plain_info_stays_quiet():
    assert not _sent_by('time="2026-07-14T05:00:00Z" level=info msg="Found new foo image"')


def test_first_alert_sends_even_right_after_boot(monkeypatch):
    """monotonic() is tiny on a fresh machine; the cooldown must not eat
    the first alert (regression test for the 0.0 sentinel bug)."""
    monkeypatch.setattr(alerts.time, "monotonic", lambda: 5.0)
    assert _sent_by('time="2026-07-14T05:00:00Z" level=error msg="boom"')


def test_duplicate_alert_suppressed_inside_cooldown():
    notifier = Notifier()
    entry = parse_line('time="2026-07-14T05:00:00Z" level=error msg="boom"')
    enabled_settings = replace(alerts.settings, ntfy_topic="test-topic")
    with (
        patch.object(alerts, "settings", enabled_settings),
        patch.object(notifier, "_post", return_value=True) as post,
    ):
        notifier.evaluate(entry)
        notifier.evaluate(entry)
    assert post.call_count == 1


def test_lan_addresses_allowed():
    assert _is_allowed("10.19.78.5")
    assert _is_allowed("192.168.1.10")
    assert _is_allowed("172.18.0.1")
    assert _is_allowed("127.0.0.1")
    assert _is_allowed("::ffff:10.19.78.5")


def test_public_addresses_blocked():
    assert not _is_allowed("87.52.105.97")
    assert not _is_allowed("8.8.8.8")
    assert not _is_allowed("not-an-ip")
