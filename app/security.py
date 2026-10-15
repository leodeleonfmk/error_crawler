"""Outbound network policy. This module (plus the guarded transport it builds)
is the only place egress rules live.

Two layers, same rules:
  * validate_url(url): pre-check used by the API and before every crawler
    request (including each redirect hop).
  * GuardedBackend: an httpcore network backend that resolves the host itself,
    validates every resolved address, and connects to the validated IP. This
    closes the DNS-rebinding gap between the pre-check and the connection.
    TLS still uses the original hostname for SNI and certificate checks
    (httpcore passes server_hostname separately to start_tls).

Policy is default-deny for anything that isn't a public, routable address.
Unresolvable hosts are *not* blocked: they fall through to the crawler's
normal DNS-error reporting.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Union
from urllib.parse import urlsplit

import httpcore
import httpx

log = logging.getLogger(__name__)

# Shown to users and in reports. Never include resolved IPs or the reason.
BLOCKED_MESSAGE = "Blocked: not a public address"
NOT_ALLOWED_MESSAGE = "This address isn't allowed."

MAX_URL_LENGTH = 2048
DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
DNS_TIMEOUT_S = 5.0

BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata", "metadata.google.internal", "metadata.goog"})
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain", ".home.arpa")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
# Explicit list so behavior doesn't depend on the Python version's ipaddress tables.
BLOCKED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
    "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)]
NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

Resolver = Callable[[str], Awaitable[list]]


def private_hosts_allowed() -> bool:
    """Dev-only escape hatch. Read on every call so tests can toggle it."""
    return os.environ.get("ALLOW_PRIVATE_HOSTS") == "1"


def allowed_ports() -> frozenset:
    raw = os.environ.get("ALLOWED_PORTS", "")
    if not raw.strip():
        return DEFAULT_ALLOWED_PORTS
    return frozenset(int(p) for p in raw.split(",") if p.strip())


# --- Address rules -------------------------------------------------------------


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """IPv4 hidden inside an IPv6 address (mapped, compatible, 6to4, NAT64)."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if int(ip) >> 32 == 0:  # IPv4-compatible ::a.b.c.d (also covers :: and ::1)
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour:
        return ip.sixtofour
    if ip in NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_ip(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not is_public_ip(embedded):
            return False
    if any(ip in net for net in BLOCKED_NETWORKS if net.version == ip.version):
        return False
    return ip.is_global and not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def parse_ip_literal(host: str) -> Optional[IPAddress]:
    """Parse standard and legacy IP spellings (2130706433, 0x7f000001, 127.1, ...).

    inet_aton is what the OS resolver uses for these forms, so anything it
    accepts would be connected to as that address.
    """
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        pass
    if host and all(c in "0123456789abcdefxABCDEFX." for c in host):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            pass
    return None


def canonical_host(host: str) -> Optional[str]:
    """Lowercase ASCII (punycode) form with brackets and trailing dots removed."""
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return None
    if parse_ip_literal(host) is not None:
        return host
    try:
        # IDNA 2003 nameprep folds look-alikes such as fullwidth "ｌｏｃａｌｈｏｓｔ".
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def blocked_hostname(host: str) -> bool:
    return host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES)


async def system_resolver(host: str) -> list:
    """All A and AAAA addresses for host. Runs in a thread; raises socket.gaierror."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


async def resolve(host: str, resolver: Optional[Resolver] = None, timeout: Optional[float] = None) -> list:
    addresses = await asyncio.wait_for((resolver or system_resolver)(host), timeout or DNS_TIMEOUT_S)
    return [ipaddress.ip_address(str(a).split("%", 1)[0]) for a in addresses]


# --- Pre-check -----------------------------------------------------------------


@dataclass
class Verdict:
    allowed: bool
    reason: str  # internal only: logs, never responses


async def check_url(url: str, resolver: Optional[Resolver] = None) -> Verdict:
    if len(url) > MAX_URL_LENGTH:
        return Verdict(False, "url too long")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return Verdict(False, "unparseable url")
    if parts.scheme.lower() not in ("http", "https"):
        return Verdict(False, f"scheme {parts.scheme!r}")
    if "@" in parts.netloc:
        return Verdict(False, "userinfo in url")
    host = canonical_host(parts.hostname or "")
    if not host:
        return Verdict(False, "empty or invalid host")
    if private_hosts_allowed():
        return Verdict(True, "ALLOW_PRIVATE_HOSTS=1")
    effective_port = port if port is not None else (443 if parts.scheme.lower() == "https" else 80)
    if effective_port not in allowed_ports():
        return Verdict(False, f"port {effective_port} not allowed")
    if blocked_hostname(host):
        return Verdict(False, f"blocked hostname {host}")

    literal = parse_ip_literal(host)
    if literal is not None:
        return Verdict(is_public_ip(literal), f"ip literal {literal}")
    try:
        addresses = await resolve(host, resolver)
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError, OSError) as exc:
        # Not blocked: the crawler will report it as a DNS error.
        return Verdict(True, f"unresolvable ({type(exc).__name__}); left to DNS error path")
    if not addresses:
        return Verdict(True, "no addresses; left to DNS error path")
    blocked = [a for a in addresses if not is_public_ip(a)]
    if blocked:
        return Verdict(False, f"resolves to non-public address {blocked[0]}")
    return Verdict(True, "public")


async def validate_url(url: str, *, resolver: Optional[Resolver] = None) -> bool:
    verdict = await check_url(url, resolver)
    if not verdict.allowed:
        log.info("Blocked outbound URL %.200s: %s", url, verdict.reason)
    return verdict.allowed


# --- Connection-time guard -----------------------------------------------------


class BlockedAddressError(httpcore.ConnectError):
    """Raised at connect time; httpx re-raises it as httpx.ConnectError (from this)."""


class GuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        resolver: Optional[Resolver] = None,
        inner: Optional[httpcore.AsyncNetworkBackend] = None,
        allow_private: Optional[bool] = None,
    ) -> None:
        self._resolver = resolver
        self._inner = inner or httpcore.AnyIOBackend()
        self._allow_private = allow_private

    def _private_allowed(self) -> bool:
        return private_hosts_allowed() if self._allow_private is None else self._allow_private

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if self._private_allowed():
            return await self._inner.connect_tcp(host, port, timeout, local_address, socket_options)

        canon = canonical_host(host)
        if not canon or blocked_hostname(canon) or port not in allowed_ports():
            log.info("Blocked connection to %s:%s (hostname/port rule)", host, port)
            raise BlockedAddressError(BLOCKED_MESSAGE)

        literal = parse_ip_literal(canon)
        if literal is not None:
            addresses = [literal]
        else:
            try:
                addresses = await resolve(canon, self._resolver, timeout)
            except asyncio.TimeoutError as exc:
                raise httpcore.ConnectTimeout("DNS lookup timed out") from exc
            except (socket.gaierror, OSError) as exc:
                raise httpcore.ConnectError(str(exc)) from exc
            if not addresses:
                raise httpcore.ConnectError("No addresses found") from socket.gaierror(socket.EAI_NONAME, "no addresses")

        blocked = [a for a in addresses if not is_public_ip(a)]
        if blocked:
            log.warning("Blocked connection to %s: resolved to non-public address %s", host, blocked[0])
            raise BlockedAddressError(BLOCKED_MESSAGE)

        last_exc: Optional[Exception] = None
        for address in addresses:  # connect to the validated literal, never re-resolve
            try:
                return await self._inner.connect_tcp(str(address), port, timeout, local_address, socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        raise last_exc  # type: ignore[misc]

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedAddressError(BLOCKED_MESSAGE)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def make_guarded_transport(
    *,
    allow_private: Optional[bool] = None,
    resolver: Optional[Resolver] = None,
    inner_backend: Optional[httpcore.AsyncNetworkBackend] = None,
    limits: httpx.Limits = httpx.Limits(max_connections=20, max_keepalive_connections=10),
) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose every TCP connection goes through GuardedBackend."""
    # trust_env=False: no SSL_CERT_FILE etc. from the environment; proxies are
    # disabled on the client as well.
    transport = httpx.AsyncHTTPTransport(trust_env=False, limits=limits)
    # httpx has no public hook for the network backend, so rebuild the pool
    # with the same settings httpx uses (see httpx/_transports/default.py).
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(trust_env=False),
        max_connections=limits.max_connections,
        max_keepalive_connections=limits.max_keepalive_connections,
        keepalive_expiry=limits.keepalive_expiry,
        http1=True,
        http2=False,
        network_backend=GuardedBackend(resolver=resolver, inner=inner_backend, allow_private=allow_private),
    )
    return transport


def log_startup_warnings() -> None:
    if private_hosts_allowed():
        log.warning("!" * 72)
        log.warning("ALLOW_PRIVATE_HOSTS=1: SSRF protection is OFF. Private, loopback and")
        log.warning("metadata addresses can be crawled. Never enable this in production.")
        log.warning("!" * 72)
