"""Outbound URL checks. validate_url is the single choke point: the crawler calls
it before every request (including each redirect hop), and the API calls it
before accepting a job."""

from __future__ import annotations

from urllib.parse import urlsplit


async def validate_url(url: str) -> bool:
    # TODO(ssrf): this is a placeholder that only checks the scheme. Before the
    # app is public it must also resolve the host and reject private, loopback,
    # link-local, multicast and reserved addresses (IPv4 and IPv6, including
    # 169.254.169.254 metadata endpoints), non-standard ports if desired, and
    # hostnames like "localhost". Keep all of that here so every request goes
    # through one function.
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
