"""Deploy/update the watchtower-logs app on ZimaOS.

Renders compose.yaml by substituting __PLACEHOLDER__ markers with values
from .env.deploy (gitignored), then PUTs the result to the ZimaOS
app-management API (or POSTs it when the app is not installed yet).

Requires the zimaos-mcp credentials (~/projects/zimaos-mcp/.env) or the
ZIMAOS_API_URL / ZIMAOS_USERNAME / ZIMAOS_PASSWORD environment variables.

Usage:
    /home/gorm/projects/zimaos-mcp/.venv/bin/python scripts/deploy_zima.py
"""

import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

REPO = Path(__file__).resolve().parent.parent
APP_ID = "watchtower-logs"

# Deployment secrets first (they must win), then the ZimaOS credentials.
load_dotenv(REPO / ".env.deploy")
load_dotenv(os.path.expanduser("~/projects/zimaos-mcp/.env"))

from zimaos_mcp.client import _get_client, api_get  # noqa: E402


def render() -> str:
    """Fill __PLACEHOLDER__ markers from the environment."""
    yaml_body = (REPO / "compose.yaml").read_text()

    def substitute(match: re.Match) -> str:
        name = match.group(1)
        value = os.environ.get(name)
        if value is None:
            sys.exit(f"error: {name} missing from .env.deploy")
        return value

    return re.sub(r"__([A-Z0-9_]+)__", substitute, yaml_body)


def main() -> None:
    yaml_body = render()
    try:
        api_get(f"/v2/app_management/compose/{APP_ID}")
        path, method = f"/v2/app_management/compose/{APP_ID}", "PUT"
    except RuntimeError:
        path, method = "/v2/app_management/compose?dry_run=false", "POST"

    client, headers = _get_client()
    headers["Content-Type"] = "application/yaml"
    response = client.request(method, path, content=yaml_body, headers=headers, timeout=120.0)
    print(response.status_code, response.text[:500])
    sys.exit(0 if response.status_code < 400 else 1)


if __name__ == "__main__":
    main()
