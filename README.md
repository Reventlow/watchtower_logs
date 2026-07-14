# watchtower_logs

A LAN-only dashboard for [watchtower](https://containrrr.dev/watchtower/)
container logs, running on zima at
[watchtower.blacklog.net](https://watchtower.blacklog.net).

It tails the watchtower container through the Docker socket, parses the
logrus lines, and shows a live "night watch" dashboard: a beacon that
reflects overall health, a countdown to the next sweep, stat tiles
(last sweep, watched containers, updates and failures over 24 h) and a
searchable, filterable live log stream.

Log lines that need attention — warnings, errors, or a sweep that failed
to update a container — are pushed to
[ntfy.blacklog.net](https://ntfy.blacklog.net) so they reach the phone.

## Architecture

```
watchtower ── docker.sock (ro) ──> tailer thread ──> ring buffer ──> SSE ──> browser
                                        │
                                        └──> alert rules ──> ntfy.blacklog.net
```

* **FastAPI** app, one container, no database. History is an in-memory
  ring buffer (5000 entries) refilled from `docker logs --tail` on start.
* **SSE** (`/api/stream`) delivers live entries and stats; the frontend is
  dependency-free vanilla JS.
* **LAN-only**: every request is checked against `ALLOWED_NETWORKS`
  (RFC1918 + loopback by default). The check happens in the app itself,
  so even a misconfigured reverse proxy cannot expose the dashboard —
  external clients get a 403 because the proxy reports their public IP
  via `X-Real-IP`.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `WATCHTOWER_CONTAINER` | *(auto-detect)* | Container to tail; found by image `containrrr/watchtower` when empty |
| `SCAN_INTERVAL_SECONDS` | `600` | Watchtower's `--interval`, drives the countdown |
| `NTFY_URL` | `https://ntfy.blacklog.net` | ntfy server |
| `NTFY_TOPIC` | *(empty = alerts off)* | Topic to publish alerts to |
| `NTFY_TOKEN` | *(empty)* | Bearer token if the topic needs auth |
| `ALERT_COOLDOWN_SECONDS` | `600` | Suppress identical alerts inside this window |
| `ALLOWED_NETWORKS` | RFC1918 + loopback | CIDRs allowed to reach the site |
| `HOST_LABEL` | `zima` | Host name shown in the header |

## Alert rules

An entry is pushed to ntfy when:

* `level` is `warning`, `error`, `fatal` or `panic`, or
* a `Session done` line reports `Failed > 0`.

Identical messages within the cooldown window are sent once. The footer
has a **send test alert** button to verify the path end-to-end.
Subscribe to the topic in the ntfy app to receive alerts.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/pytest                # parser + alert rule + netguard tests
.venv/bin/uvicorn app.main:app --reload   # needs /var/run/docker.sock
```

## CI / deployment

Every push to `main` runs the tests and publishes
`ghcr.io/reventlow/watchtower_logs:latest` (GitHub Actions,
`.github/workflows/docker-image.yml`). On zima the app is installed from
`compose.yaml`; it carries the `com.centurylinklabs.watchtower.enable`
label, so watchtower updates the dashboard the same way it updates
everything else — and the update shows up in the dashboard's own log.
