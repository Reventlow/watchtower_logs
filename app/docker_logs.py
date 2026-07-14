"""Background thread that tails the watchtower container's logs.

Connects to the Docker daemon through the mounted socket, finds the
watchtower container (by name or by image), streams its logs and feeds
every parsed line into the store and the alert evaluator. Reconnects with
backoff when the stream drops (e.g. watchtower restarts after updating
itself).
"""

import logging
import threading
import time
from datetime import datetime, timezone

import docker
from docker.models.containers import Container

from app.alerts import notifier
from app.config import settings
from app.parser import parse_line
from app.store import store

logger = logging.getLogger(__name__)


def _find_container(client: docker.DockerClient) -> Container | None:
    """Locate the watchtower container by configured name, then by image."""
    if settings.watchtower_container:
        try:
            return client.containers.get(settings.watchtower_container)
        except docker.errors.NotFound:
            pass
        # ZimaOS compose names containers like `watchtower-watchtower-1`,
        # so fall through to a fuzzy search as well.
    for container in client.containers.list():
        image = ",".join(container.image.tags or [])
        if "containrrr/watchtower" in image:
            return container
        if settings.watchtower_container and settings.watchtower_container in container.name:
            return container
    return None


def _tail(container: Container, since: datetime | None) -> None:
    """Stream logs until the stream ends or errors; entries go to the store."""
    kwargs: dict = {"stream": True, "follow": True}
    if since is not None:
        kwargs["since"] = since
    else:
        kwargs["tail"] = settings.log_tail

    buffer = b""
    for chunk in container.logs(**kwargs):
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            entry = parse_line(line.decode("utf-8", errors="replace"))
            if entry is not None and store.add(entry):
                notifier.evaluate(entry)


def run_forever() -> None:
    """Tailer loop: connect, tail, reconnect on failure. Never returns."""
    backoff = 2.0
    since: datetime | None = None

    while True:
        try:
            client = docker.DockerClient(base_url=settings.docker_url)
            container = _find_container(client)
            if container is None:
                store.connected = False
                logger.warning("Watchtower container not found; retrying")
                time.sleep(min(backoff, 30))
                backoff = min(backoff * 2, 30)
                continue

            store.container_name = container.name
            store.connected = True
            backoff = 2.0
            logger.info("Tailing logs of container %s", container.name)
            _tail(container, since)

            # Stream ended cleanly (container stopped/recreated). Resume
            # from "now" so we do not re-ingest the whole tail again.
            since = datetime.now(timezone.utc)
            store.connected = False
            logger.info("Log stream ended; reconnecting")
            time.sleep(2)
        except Exception:
            store.connected = False
            since = datetime.now(timezone.utc)
            logger.exception("Log tailer error; reconnecting in %.0fs", backoff)
            time.sleep(min(backoff, 30))
            backoff = min(backoff * 2, 30)


def start() -> threading.Thread:
    """Start the tailer as a daemon thread."""
    thread = threading.Thread(target=run_forever, name="docker-log-tailer", daemon=True)
    thread.start()
    return thread
