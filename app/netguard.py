"""LAN-only access middleware.

The dashboard must only be reachable from the local network, regardless of
how DNS or the reverse proxy are configured. Every request is checked
against ALLOWED_NETWORKS (RFC1918 + loopback by default).

Client IP resolution, most trustworthy first:
  1. X-Real-IP     - set by nginx-proxy-manager to the TCP peer it saw.
  2. X-Forwarded-For (rightmost entry) - the address the proxy appended;
     leftmost entries are client-supplied and therefore spoofable.
  3. The direct TCP peer address.

Proxy headers are only honoured when the direct peer itself is on an
allowed network (i.e. the request actually came through our own proxy).
An external client cannot forge its way in: the proxy overwrites
X-Real-IP with the real public address, which fails the check.
"""

import ipaddress
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings

logger = logging.getLogger(__name__)

_NETWORKS = [ipaddress.ip_network(cidr, strict=False) for cidr in settings.allowed_networks]

# Proxy trust is independent of the (configurable) allowlist: forwarding
# headers are honoured only from private peers, i.e. our own reverse proxy.
_PRIVATE = [
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7")
]


def _in(address: str, networks: list) -> bool:
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in network for network in networks)


def _is_allowed(address: str) -> bool:
    """True when the address falls inside any allowed network."""
    return _in(address, _NETWORKS)


def client_ip(request: Request) -> str:
    """Resolve the effective client address (used by the IP guard and the
    login throttle)."""
    peer = request.client.host if request.client else ""

    # Only trust forwarding headers when the request came from inside
    # (i.e. from our own reverse proxy on the LAN / docker network).
    if peer and _in(peer, _PRIVATE):
        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return peer


async def lan_only_middleware(request: Request, call_next):
    """Reject requests whose effective client IP is not on the LAN."""
    address = client_ip(request)
    if not _is_allowed(address):
        logger.warning("Blocked request from %s to %s", address, request.url.path)
        return JSONResponse(
            status_code=403,
            content={"detail": "This dashboard is only available on the local network."},
        )
    return await call_next(request)
