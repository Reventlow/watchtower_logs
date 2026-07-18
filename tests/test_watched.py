"""Tests for the watched-containers listing."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app import docker_logs


def _container(name: str, tags: list[str], status: str) -> SimpleNamespace:
    """Build a minimal stand-in for a docker-py Container."""
    return SimpleNamespace(
        name=name,
        image=SimpleNamespace(tags=tags),
        status=status,
        attrs={"Config": {"Image": tags[0] if tags else "sha256:abc"}},
    )


def test_watched_containers_sorted_and_shaped():
    client = MagicMock()
    client.containers.list.return_value = [
        _container("zulu", ["example/zulu:latest"], "running"),
        _container("alpha", ["example/alpha:1.0"], "exited"),
    ]
    with patch.object(docker_logs.docker, "DockerClient", return_value=client):
        listing = docker_logs.watched_containers()

    assert [c["name"] for c in listing] == ["alpha", "zulu"]
    assert listing[0] == {
        "name": "alpha",
        "image": "example/alpha:1.0",
        "state": "exited",
    }
    # The enable label is the filter — watchtower runs with --label-enable.
    client.containers.list.assert_called_once_with(
        all=True,
        filters={"label": "com.centurylinklabs.watchtower.enable=true"},
    )
    client.close.assert_called_once()


def test_watched_containers_untagged_image_falls_back_to_config():
    client = MagicMock()
    client.containers.list.return_value = [_container("pinned", [], "running")]
    with patch.object(docker_logs.docker, "DockerClient", return_value=client):
        listing = docker_logs.watched_containers()

    assert listing[0]["image"] == "sha256:abc"
