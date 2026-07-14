"""Application configuration.

All settings come from environment variables so the container can be
configured entirely from the compose file on ZimaOS.
"""

import os
from dataclasses import dataclass, field


def _csv(value: str) -> list[str]:
    """Split a comma-separated env value into a clean list."""
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Runtime settings, resolved once at import time."""

    # Docker daemon socket (mounted read-only into the container).
    docker_url: str = os.environ.get("DOCKER_URL", "unix:///var/run/docker.sock")

    # Container to tail. Empty means: auto-detect the container running
    # the containrrr/watchtower image.
    watchtower_container: str = os.environ.get("WATCHTOWER_CONTAINER", "")

    # Watchtower's --interval flag, used to compute the next-sweep countdown.
    scan_interval_seconds: int = int(os.environ.get("SCAN_INTERVAL_SECONDS", "600"))

    # How many parsed log entries to keep in memory.
    log_history: int = int(os.environ.get("LOG_HISTORY", "5000"))

    # How many historical lines to request from Docker on startup.
    log_tail: int = int(os.environ.get("LOG_TAIL", "2000"))

    # ntfy alerting. Alerts are disabled when the topic is empty.
    ntfy_url: str = os.environ.get("NTFY_URL", "https://ntfy.blacklog.net").rstrip("/")
    ntfy_topic: str = os.environ.get("NTFY_TOPIC", "")
    ntfy_token: str = os.environ.get("NTFY_TOKEN", "")

    # Suppress duplicate alerts with the same message inside this window.
    alert_cooldown_seconds: int = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "600"))

    # Networks allowed to reach the site. Unset -> RFC1918 + loopback
    # (LAN-only). Set to an explicit empty string to disable IP filtering
    # (only sensible when authentication is configured).
    allowed_networks: list[str] = field(
        default_factory=lambda: _csv(
            os.environ.get(
                "ALLOWED_NETWORKS",
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
                "127.0.0.0/8,::1/128,fc00::/7,fe80::/10",
            )
        )
    )

    # Authentication. Enabled when hash, TOTP secret and session secret are
    # all present; otherwise the app falls back to the LAN-only IP guard.
    auth_username: str = os.environ.get("AUTH_USERNAME", "gorm")
    auth_password_hash: str = os.environ.get("AUTH_PASSWORD_HASH", "")
    totp_secret: str = os.environ.get("TOTP_SECRET", "")
    session_secret: str = os.environ.get("SESSION_SECRET", "")
    session_days: int = int(os.environ.get("SESSION_DAYS", "30"))
    api_tokens: list[str] = field(
        default_factory=lambda: _csv(os.environ.get("API_TOKENS", ""))
    )
    # Mark the session cookie Secure (https-only). Off by default so login
    # still works over plain http on the LAN / tailnet.
    cookie_secure: bool = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

    # Human-readable host label shown in the dashboard header.
    host_label: str = os.environ.get("HOST_LABEL", "zima")

    @property
    def auth_enabled(self) -> bool:
        """Auth requires all three secrets to be configured."""
        return bool(self.auth_password_hash and self.totp_secret and self.session_secret)


settings = Settings()
