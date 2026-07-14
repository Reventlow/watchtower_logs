"""Parser for watchtower's logrus text log lines.

Watchtower (containrrr/watchtower) logs in logrus text format:

    time="2026-07-14T05:37:19Z" level=info msg="Session done" Failed=0 Scanned=1 Updated=1 notify=no

Every line is a sequence of key=value pairs where values are either bare
tokens or double-quoted strings (with backslash escapes).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# key="quoted value" | key=bare-token
_PAIR_RE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')

# Docker compose prefixes lines with e.g. `watchtower-1  | ` when logs are
# fetched through compose; direct container logs do not have it. Strip both.
_PREFIX_RE = re.compile(r"^\S+\s+\|\s?")


@dataclass
class LogEntry:
    """One parsed log line."""

    ts: datetime
    level: str
    msg: str
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def to_dict(self) -> dict:
        """JSON-friendly representation used by the API and SSE stream."""
        return {
            "ts": self.ts.isoformat(),
            "level": self.level,
            "msg": self.msg,
            "fields": self.fields,
        }


def parse_line(line: str) -> LogEntry | None:
    """Parse a single watchtower log line, returning None for noise.

    Unparseable but non-empty lines are preserved as level=info entries with
    the raw text as the message, so nothing silently disappears.
    """
    line = _PREFIX_RE.sub("", line.strip())
    if not line:
        return None

    pairs: dict[str, str] = {}
    for match in _PAIR_RE.finditer(line):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[key] = value.replace('\\"', '"') if match.group(2) is not None else value

    ts = _parse_time(pairs.pop("time", ""))
    level = pairs.pop("level", "").lower()
    msg = pairs.pop("msg", "")

    if not msg and not level:
        # Not a logrus line at all (e.g. a panic traceback). Keep it visible.
        return LogEntry(
            ts=ts or datetime.now(timezone.utc),
            level="info",
            msg=line,
            raw=line,
        )

    return LogEntry(
        ts=ts or datetime.now(timezone.utc),
        level=level or "info",
        msg=msg,
        fields=pairs,
        raw=line,
    )


def _parse_time(value: str) -> datetime | None:
    """Parse logrus RFC3339 timestamps; tolerate missing/odd values."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
