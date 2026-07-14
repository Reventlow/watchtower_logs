"""Tests for the logrus line parser against real watchtower output."""

from app.parser import parse_line


def test_session_done_line():
    entry = parse_line(
        'time="2026-07-14T05:37:19Z" level=info msg="Session done" '
        "Failed=0 Scanned=1 Updated=1 notify=no"
    )
    assert entry is not None
    assert entry.level == "info"
    assert entry.msg == "Session done"
    assert entry.fields == {"Failed": "0", "Scanned": "1", "Updated": "1", "notify": "no"}
    assert entry.ts.isoformat() == "2026-07-14T05:37:19+00:00"


def test_compose_prefix_is_stripped():
    entry = parse_line(
        'watchtower-1  | time="2026-07-14T05:37:17Z" level=info '
        'msg="Found new ghcr.io/reventlow/usb-creator-repo:latest image (8b509fe4dcfb)"'
    )
    assert entry is not None
    assert entry.msg.startswith("Found new ghcr.io/reventlow/usb-creator-repo")
    assert entry.fields == {}


def test_error_level():
    entry = parse_line(
        'time="2026-07-14T05:00:00Z" level=error '
        'msg="Unable to update container /foo" error="manifest unknown"'
    )
    assert entry is not None
    assert entry.level == "error"
    assert entry.fields["error"] == "manifest unknown"


def test_escaped_quotes_in_message():
    entry = parse_line('time="2026-07-14T05:00:00Z" level=info msg="said \\"hello\\""')
    assert entry is not None
    assert entry.msg == 'said "hello"'


def test_blank_line_is_ignored():
    assert parse_line("") is None
    assert parse_line("   \n") is None


def test_non_logrus_line_is_preserved():
    entry = parse_line("panic: runtime error: invalid memory address")
    assert entry is not None
    assert entry.level == "info"
    assert "panic: runtime error" in entry.msg
