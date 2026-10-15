"""SSRF protection. No real network: DNS is a fake resolver, TCP is a recording backend.

ALLOW_PRIVATE_HOSTS is forced off for every test in this module.
"""

import asyncio
import socket
import time
from functools import partial

import httpcore
import httpx
import pytest

from app import security
from app.crawler import Crawler, classify_exception
from app.models import CrawlOptions, IssueType
from app.security import (
    BLOCKED_MESSAGE,
    BlockedAddressError,
    GuardedBackend,
    check_url,
    make_guarded_transport,
    validate_url,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


@pytest.fixture(autouse=True)
def private_hosts_off(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.delenv("ALLOWED_PORTS", raising=False)


class FakeDNS:
    """hostname -> list of addresses, or a list of answers consumed one per lookup."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    async def __call__(self, host):
        self.calls.append(host)
        answer = self.table.get(host)
        if answer is None:
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided, or not known")
        if answer and isinstance(answer[0], list):  # sequence of answers (rebinding)
            return answer.pop(0) if len(answer) > 1 else answer[0]
        return answer


DNS = {
    "example.com": [PUBLIC_V4, PUBLIC_V6],
    "private.test": ["10.0.0.5"],
    "mixed.test": [PUBLIC_V4, "192.168.1.10"],
    "mixed6.test": [PUBLIC_V6, "fd00::1"],
    "meta.test": ["169.254.169.254"],
    "loop6.test": ["::1"],
    "mapped.test": ["::ffff:10.0.0.1"],
    "xn--bcher-kva.test": ["10.0.0.9"],  # bücher.test
}


def run(coro):
    return asyncio.run(coro)


BLOCKED = [
    # loopback / unspecified / private / link-local / CGNAT / multicast / reserved
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/",
    "http://0.0.0.0/",
    "http://0/",
    "http://10.1.2.3/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",
    "http://224.0.0.1/",
    "http://240.0.0.1/",
    "http://255.255.255.255/",
    # IPv6, including forms that embed a blocked IPv4
    "http://[::1]/",
    "http://[::]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[fd12:3456::1]/",
    "http://[ff02::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[::ffff:169.254.169.254]/",
    "http://[::127.0.0.1]/",  # IPv4-compatible
    "http://[64:ff9b::a00:1]/",  # NAT64 of 10.0.0.1
    "http://[64:ff9b::7f00:1]/",  # NAT64 of 127.0.0.1
    "http://[2002:7f00:1::]/",  # 6to4 of 127.0.0.1
    "http://[2002:a9fe:a9fe::]/",  # 6to4 of 169.254.169.254
    "http://[2002:808:808::]/",  # 6to4 of public 8.8.8.8: the whole 6to4 range is blocked
    # legacy IPv4 spellings of 127.0.0.1
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://0x7f.1/",
    # names
    "http://localhost/",
    "http://LOCALHOST/",
    "http://localhost./",
    "http://localhost../",
    "http://foo.localhost/",
    "http://printer.local/",
    "http://db.internal/",
    "http://box.localdomain/",
    "http://router.home.arpa/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
    "http://ｌｏｃａｌｈｏｓｔ/",  # fullwidth, folds to localhost
    "http://１２７.０.０.１/",  # fullwidth digits
    # resolves to non-public addresses
    "http://private.test/",
    "http://mixed.test/",
    "http://mixed6.test/",
    "http://meta.test/",
    "http://loop6.test/",
    "http://mapped.test/",
    "http://bücher.test/",
    "http://xn--bcher-kva.test/",
    # schemes, userinfo, ports, length
    "file:///etc/passwd",
    "ftp://example.com/",
    "gopher://example.com/",
    "javascript:alert(1)",
    "http://user:pass@example.com/",
    "http://user@example.com/",
    "http://example.com:22/",
    "http://example.com:6379/",
    "http://example.com:3306/",
    "http://example.com:0/",
    "https://example.com/" + "a" * 2048,
    "http:///nohost",
]

ALLOWED = [
    f"http://{PUBLIC_V4}/",
    "http://8.8.8.8/",
    "http://134744072/",  # decimal 8.8.8.8
    f"http://[{PUBLIC_V6}]/",
    "https://example.com/",
    "https://EXAMPLE.com./path",
    "http://example.com:80/",
    "http://example.com:8080/",
    "https://example.com:8443/",
    "http://does-not-resolve.test/",  # unresolvable is NOT blocked: it becomes a DNS error
]


@pytest.mark.parametrize("url", BLOCKED)
def test_blocked(url):
    verdict = run(check_url(url, FakeDNS(dict(DNS))))
    assert not verdict.allowed, f"{url} allowed ({verdict.reason})"


@pytest.mark.parametrize("url", ALLOWED)
def test_allowed(url):
    verdict = run(check_url(url, FakeDNS(dict(DNS))))
    assert verdict.allowed, f"{url} blocked ({verdict.reason})"


@pytest.mark.parametrize("url", ["http://2130706433/", "http://127.1/", "http://[::ffff:127.0.0.1]/", "http://10.0.0.1/"])
def test_ip_literals_never_hit_dns(url):
    dns = FakeDNS({})
    run(check_url(url, dns))
    assert dns.calls == []


def test_unresolvable_host_is_allowed_with_reason():
    verdict = run(check_url("https://nope.invalid/", FakeDNS({})))
    assert verdict.allowed and "DNS error path" in verdict.reason


def test_dns_timeout_is_treated_as_unresolvable(monkeypatch):
    monkeypatch.setattr(security, "DNS_TIMEOUT_S", 0.05)

    async def hang(host):
        await asyncio.sleep(5)

    assert run(check_url("https://slow.test/", hang)).allowed


def test_system_resolver_does_not_block_event_loop(monkeypatch):
    def slow_getaddrinfo(*args, **kwargs):
        time.sleep(0.3)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_V4, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)

    async def main():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.01)

        t = asyncio.ensure_future(ticker())
        assert await validate_url("https://slow-dns.test/")
        t.cancel()
        return ticks

    assert run(main()) >= 10  # the loop kept running during the 300 ms lookup


def test_reason_is_internal_only():
    assert run(validate_url("http://private.test/", resolver=FakeDNS(dict(DNS)))) is False
    assert "10.0.0.5" not in BLOCKED_MESSAGE and "10.0.0.5" not in security.NOT_ALLOWED_MESSAGE


def test_allow_private_hosts_escape_hatch(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_HOSTS", "1")
    assert run(check_url("http://127.0.0.1:8765/", FakeDNS({}))).allowed
    assert run(check_url("http://localhost/", FakeDNS({}))).allowed
    # never relaxed: schemes and credentials
    assert not run(check_url("file:///etc/passwd", FakeDNS({}))).allowed
    assert not run(check_url("http://u:p@localhost/", FakeDNS({}))).allowed


def test_allow_private_hosts_must_be_exactly_1(monkeypatch):
    for value in ("0", "true", "yes", ""):
        monkeypatch.setenv("ALLOW_PRIVATE_HOSTS", value)
        assert not run(check_url("http://127.0.0.1/", FakeDNS({}))).allowed


def test_allowed_ports_configurable(monkeypatch):
    monkeypatch.setenv("ALLOWED_PORTS", "443")
    assert not run(check_url("http://example.com/", FakeDNS(dict(DNS)))).allowed
    assert run(check_url("https://example.com/", FakeDNS(dict(DNS)))).allowed


# --- Connection-time guard -----------------------------------------------------


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, log):
        self.log = log

    async def read(self, max_bytes, timeout=None):
        return b""

    async def write(self, buffer, timeout=None):
        raise httpcore.WriteError("test stream: stop here")

    async def aclose(self):
        pass

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.log.append(("start_tls", server_hostname))
        raise httpcore.ConnectError("test stream: stop after recording SNI")


class RecordingBackend(httpcore.AsyncNetworkBackend):
    """Stands in for real sockets: records what we'd connect to."""

    def __init__(self):
        self.log = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.log.append(("connect", host, port))
        return FakeStream(self.log)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise AssertionError("unix sockets not expected")

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


def connects(log):
    return [entry for entry in log if entry[0] == "connect"]


def test_backend_connects_to_validated_ip_not_hostname():
    inner = RecordingBackend()
    backend = GuardedBackend(resolver=FakeDNS({"example.com": [PUBLIC_V4]}), inner=inner)
    run(backend.connect_tcp("example.com", 443))
    assert inner.log == [("connect", PUBLIC_V4, 443)]


def test_tls_uses_original_hostname_for_sni():
    inner = RecordingBackend()

    async def main():
        transport = make_guarded_transport(resolver=FakeDNS({"example.com": [PUBLIC_V4]}), inner_backend=inner)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get("https://example.com/")

    run(main())
    assert inner.log == [("connect", PUBLIC_V4, 443), ("start_tls", "example.com")]


def test_dns_rebinding_refused_at_connect_time():
    # First lookup (pre-check) says public; second lookup (connect) says loopback.
    dns = FakeDNS({"rebind.test": [[PUBLIC_V4], ["127.0.0.1"]]})
    inner = RecordingBackend()
    assert run(validate_url("http://rebind.test/", resolver=dns)) is True
    with pytest.raises(BlockedAddressError):
        run(GuardedBackend(resolver=dns, inner=inner).connect_tcp("rebind.test", 80))
    assert inner.log == []  # never connected anywhere


def test_mixed_answers_refused_at_connect_time():
    inner = RecordingBackend()
    with pytest.raises(BlockedAddressError):
        run(GuardedBackend(resolver=FakeDNS(dict(DNS)), inner=inner).connect_tcp("mixed.test", 80))
    assert inner.log == []


@pytest.mark.parametrize("host,port", [
    ("127.0.0.1", 80), ("2130706433", 80), ("169.254.169.254", 80), ("::ffff:127.0.0.1", 80),
    ("localhost", 80), ("localhost.", 80), ("metadata.google.internal", 80), ("example.com", 6379),
])
def test_backend_blocks_direct_connections(host, port):
    inner = RecordingBackend()
    with pytest.raises(BlockedAddressError):
        run(GuardedBackend(resolver=FakeDNS(dict(DNS)), inner=inner).connect_tcp(host, port))
    assert inner.log == []


def test_backend_refuses_unix_sockets():
    with pytest.raises(BlockedAddressError):
        run(GuardedBackend(inner=RecordingBackend()).connect_unix_socket("/var/run/docker.sock"))


def test_blocked_connection_surfaces_as_generic_blocked_error():
    async def main():
        transport = make_guarded_transport(resolver=FakeDNS(dict(DNS)), inner_backend=RecordingBackend())
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.ConnectError) as info:
                await client.get("http://private.test/")
        return info.value

    exc = run(main())
    assert classify_exception(exc) == IssueType.BLOCKED
    assert "10.0.0.5" not in str(exc)


def test_unresolvable_host_surfaces_as_dns_error():
    async def main():
        transport = make_guarded_transport(resolver=FakeDNS({}), inner_backend=RecordingBackend())
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.ConnectError) as info:
                await client.get("https://nope.invalid/")
        return info.value

    assert classify_exception(run(main())) == IssueType.DNS_ERROR


# --- Through the crawler ---------------------------------------------------------


def test_crawler_redirect_to_internal_targets_blocked_at_hop():
    requested = []

    def handler(request):
        url = str(request.url)
        requested.append(url)
        routes = {
            "https://example.com/": (200, '<a href="/to-local">a</a><a href="/to-meta">b</a><a href="/to-v6">c</a>'),
            "https://example.com/to-local": (302, "http://127.0.0.1:8080/admin"),
            "https://example.com/to-meta": (301, "http://169.254.169.254/latest/meta-data/"),
            "https://example.com/to-v6": (307, "http://[::ffff:127.0.0.1]/"),
        }
        status, body = routes.get(url, (404, ""))
        if status in (301, 302, 307):
            return httpx.Response(status, headers={"location": body})
        return httpx.Response(status, headers={"content-type": "text/html"}, text=body)

    crawler = Crawler(
        "https://example.com/", CrawlOptions(delay=0),
        transport=httpx.MockTransport(handler),
        url_validator=partial(validate_url, resolver=FakeDNS(dict(DNS))),
    )
    result = run(crawler.run())
    blocked = {i.url: i for i in result.issues}
    assert set(blocked) == {"https://example.com/to-local", "https://example.com/to-meta", "https://example.com/to-v6"}
    for issue in blocked.values():
        assert issue.issue_type == IssueType.BLOCKED
        assert issue.is_warning
        assert issue.error == BLOCKED_MESSAGE
        assert len(issue.redirect_chain) == 2  # the hop that pointed inside is recorded
    assert not any(u.startswith(("http://127.", "http://169.254", "http://[")) for u in requested)


def test_crawler_rebinding_blocked_by_guarded_transport():
    # The pre-check passes (public), the connect-time lookup returns loopback.
    dns = FakeDNS({"rebind.test": [[PUBLIC_V4], ["127.0.0.1"]]})
    inner = RecordingBackend()
    crawler = Crawler(
        "http://rebind.test/", CrawlOptions(delay=0),
        transport=make_guarded_transport(resolver=dns, inner_backend=inner),
        url_validator=partial(validate_url, resolver=dns),
    )
    result = run(crawler.run())
    [issue] = [i for i in result.issues if i.url == "http://rebind.test/"]
    assert issue.issue_type == IssueType.BLOCKED
    assert issue.error == BLOCKED_MESSAGE
    assert connects(inner.log) == []


def test_crawler_ignores_proxy_env_vars(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    inner = RecordingBackend()
    crawler = Crawler(
        "http://example.com/", CrawlOptions(delay=0),
        transport=make_guarded_transport(resolver=FakeDNS({"example.com": [PUBLIC_V4]}), inner_backend=inner),
    )
    run(crawler.run())
    assert connects(inner.log) and all(host == PUBLIC_V4 for _, host, _ in connects(inner.log))
