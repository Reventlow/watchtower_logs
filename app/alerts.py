"""ntfy alerting for log entries that need attention.

An entry needs attention when:
  * its level is warning, error, fatal or panic, or
  * it is a "Session done" line reporting Failed > 0.

Alerts are POSTed to `{NTFY_URL}/{NTFY_TOPIC}`. Identical messages inside
the cooldown window are suppressed so a crash-looping watchtower does not
flood the phone.
"""

import logging
import threading
import time

import httpx

from app.config import settings
from app.parser import LogEntry

logger = logging.getLogger(__name__)

_ATTENTION_LEVELS = {"warning", "error", "fatal", "panic"}


class Notifier:
    """Sends attention-worthy log entries to ntfy with dedup + cooldown."""

    def __init__(self) -> None:
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(settings.ntfy_topic)

    def evaluate(self, entry: LogEntry) -> None:
        """Check one entry against the alert rules and notify if it matches."""
        if not self.enabled:
            return

        if entry.level in _ATTENTION_LEVELS:
            priority = "high" if entry.level != "warning" else "default"
            tags = "rotating_light" if entry.level != "warning" else "warning"
            self._send(
                title=f"Watchtower {entry.level}",
                message=self._format(entry),
                priority=priority,
                tags=tags,
            )
            return

        if entry.msg == "Session done":
            try:
                failed = int(entry.fields.get("Failed", "0"))
            except ValueError:
                failed = 0
            if failed > 0:
                self._send(
                    title="Watchtower: container update failed",
                    message=self._format(entry),
                    priority="high",
                    tags="rotating_light,package",
                )

    def send_test(self) -> bool:
        """Send a test notification, bypassing the cooldown."""
        if not self.enabled:
            return False
        return self._post(
            title="Watchtower logs: test alert",
            message="If you can read this, alerting from the log site works.",
            priority="default",
            tags="white_check_mark",
        )

    # ------------------------------------------------------------------

    def _format(self, entry: LogEntry) -> str:
        parts = [entry.msg]
        if entry.fields:
            parts.append(" ".join(f"{k}={v}" for k, v in sorted(entry.fields.items())))
        return "\n".join(parts)

    def _send(self, title: str, message: str, priority: str, tags: str) -> None:
        # time.monotonic() starts near zero on a freshly booted machine,
        # so "never sent" must be a sentinel, not 0.0 — otherwise every
        # first alert after boot would be swallowed by the cooldown.
        now = time.monotonic()
        with self._lock:
            last = self._recent.get(message)
            if last is not None and now - last < settings.alert_cooldown_seconds:
                return
            self._recent[message] = now
            # Keep the dedup map from growing forever.
            if len(self._recent) > 500:
                cutoff = now - settings.alert_cooldown_seconds
                self._recent = {m: t for m, t in self._recent.items() if t > cutoff}
        self._post(title, message, priority, tags)

    def _post(self, title: str, message: str, priority: str, tags: str) -> bool:
        headers = {"Title": title, "Priority": priority, "Tags": tags}
        if settings.ntfy_token:
            headers["Authorization"] = f"Bearer {settings.ntfy_token}"
        try:
            response = httpx.post(
                f"{settings.ntfy_url}/{settings.ntfy_topic}",
                content=message.encode(),
                headers=headers,
                timeout=10.0,
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            logger.exception("Failed to send ntfy alert")
            return False


notifier = Notifier()
