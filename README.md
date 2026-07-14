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
* **Authentication**: username + password + TOTP (any authenticator app)
  on a single login page. Sessions are HMAC-signed cookies with a 30-day
  absolute expiry; scripts and Claude Code use `Authorization: Bearer`
  API tokens instead. Login attempts are throttled (10 failures / 15 min
  per client) and TOTP codes cannot be replayed. All crypto is Python
  stdlib: PBKDF2-HMAC-SHA256 passwords, RFC 6238 TOTP, HMAC-SHA256
  sessions.
* **Optional IP allowlist**: `ALLOWED_NETWORKS` (RFC1918 + loopback when
  unset) still applies underneath auth; set it to an empty string to rely
  on authentication alone. The app refuses to start with neither
  configured.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `WATCHTOWER_CONTAINER` | *(auto-detect)* | Container to tail; found by image `containrrr/watchtower` when empty |
| `SCAN_INTERVAL_SECONDS` | `600` | Watchtower's `--interval`, drives the countdown |
| `NTFY_URL` | `https://ntfy.blacklog.net` | ntfy server |
| `NTFY_TOPIC` | *(empty = alerts off)* | Topic to publish alerts to |
| `NTFY_TOKEN` | *(empty)* | Bearer token if the topic needs auth |
| `ALERT_COOLDOWN_SECONDS` | `600` | Suppress identical alerts inside this window |
| `ALLOWED_NETWORKS` | RFC1918 + loopback | CIDRs allowed to reach the site; `""` disables the IP guard |
| `AUTH_USERNAME` | `gorm` | Login username |
| `AUTH_PASSWORD_HASH` | *(empty = auth off)* | `pbkdf2_sha256:...` — generate with `python -c "from app.auth import hash_password; print(hash_password('...'))"` |
| `TOTP_SECRET` | *(empty)* | Base32 TOTP secret for the authenticator app |
| `SESSION_SECRET` | *(empty)* | Random secret signing the session cookies |
| `SESSION_DAYS` | `30` | Session lifetime |
| `API_TOKENS` | *(empty)* | Comma-separated bearer tokens for API access |
| `COOKIE_SECURE` | `false` | Set `true` to make the session cookie https-only |
| `HOST_LABEL` | `zima` | Host name shown in the header |

Deployment secrets live in `.env.deploy` (gitignored); `scripts/deploy_zima.py`
renders them into `compose.yaml`'s `__PLACEHOLDER__` markers and applies the
result through the ZimaOS API.

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
