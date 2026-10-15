import socket
import ssl

import httpx
import pytest

from app.crawler import (
    classify_exception,
    classify_status,
    extract_links,
    is_same_site,
    normalize_url,
    url_key,
)
from app.models import MAX_PAGES_HARD_CAP, CrawlOptions, IssueType

BASE = "https://example.com/blog/post"


# --- normalize_url ---


@pytest.mark.parametrize(
    "href, expected",
    [
        ("/about", "https://example.com/about"),
        ("other", "https://example.com/blog/other"),
        ("../top", "https://example.com/top"),
        ("//cdn.example.org/x.js", "https://cdn.example.org/x.js"),
        ("#section", "https://example.com/blog/post"),
        ("/page#frag", "https://example.com/page"),
        ("HTTPS://Example.COM/Path", "https://example.com/Path"),  # path case preserved
        ("https://example.com:443/a", "https://example.com/a"),
        ("http://example.com:80/a", "http://example.com/a"),
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("https://example.com", "https://example.com/"),
        ("https://user:pw@example.com/a", "https://example.com/a"),
        ("  /padded  ", "https://example.com/padded"),
        ("/a?b=1&utm_source=x&gclid=y", "https://example.com/a?b=1"),
        ("/a?utm_medium=email", "https://example.com/a"),
        ("/a?q=hello%20world", "https://example.com/a?q=hello%20world"),  # untouched if no tracking
    ],
)
def test_normalize_url(href, expected):
    assert normalize_url(href, BASE) == expected


@pytest.mark.parametrize(
    "href",
    ["mailto:a@example.com", "tel:+123", "javascript:void(0)", "ftp://example.com/f", "data:text/plain,hi", "http://[bad"],
)
def test_normalize_url_rejects_non_http(href):
    assert normalize_url(href, BASE) is None


def test_url_key_merges_trailing_slash_and_www():
    assert url_key("https://example.com/about/") == url_key("https://example.com/about")
    assert url_key("https://www.example.com/about") == url_key("https://example.com/about")
    assert url_key("https://example.com/") == "https://example.com/"
    assert url_key("https://example.com/a?x=1") != url_key("https://example.com/a?x=2")


# --- same-site ---


@pytest.mark.parametrize(
    "url, same",
    [
        ("https://example.com/a", True),
        ("https://www.example.com/a", True),
        ("http://EXAMPLE.com/a", True),
        ("https://blog.example.com/a", False),
        ("https://example.org/a", False),
        ("https://notexample.com/a", False),
        ("https://example.com.evil.com/a", False),
    ],
)
def test_is_same_site(url, same):
    assert is_same_site(url, "example.com") is same
    assert is_same_site(url, "www.example.com") is same


# --- extract_links ---

HTML = """
<html><body>
  <a href="/one">  First
     link </a>
  <a href="two#x">Two</a>
  <a href="https://other.org/">Other</a>
  <a href="mailto:hi@example.com">Mail</a>
  <a href="tel:123">Call</a>
  <a href="javascript:alert(1)">JS</a>
  <a href="/img-link"><img src="/i.png" alt="Logo"></a>
  <a href="/labelled" aria-label="Labelled"></a>
  <a>no href</a>
  <img src="/pic.jpg" alt="A picture">
</body></html>
"""


def test_extract_links_anchors():
    links = extract_links(HTML, BASE)
    assert [(l.url, l.text) for l in links] == [
        ("https://example.com/one", "First link"),
        ("https://example.com/blog/two", "Two"),
        ("https://other.org/", "Other"),
        ("https://example.com/img-link", "Logo"),
        ("https://example.com/labelled", "Labelled"),
    ]
    assert all(l.tag == "a" for l in links)


def test_extract_links_images_only_when_asked():
    imgs = [l for l in extract_links(HTML, BASE, include_images=True) if l.tag == "img"]
    assert [(l.url, l.text) for l in imgs] == [
        ("https://example.com/i.png", "Logo"),
        ("https://example.com/pic.jpg", "A picture"),
    ]


def test_extract_links_respects_base_tag():
    html = '<head><base href="https://example.com/docs/"></head><a href="intro">x</a>'
    assert extract_links(html, BASE)[0].url == "https://example.com/docs/intro"


def test_extract_links_from_bytes():
    html = '<a href="/caf\xe9">Caf\xe9</a>'.encode("latin-1")
    link = extract_links(html, BASE, encoding="latin-1")[0]
    assert link.text == "Café"


# --- classification ---


@pytest.mark.parametrize(
    "status, expected",
    [(200, None), (204, None), (301, None), (404, IssueType.HTTP_4XX), (410, IssueType.HTTP_4XX),
     (500, IssueType.HTTP_5XX), (503, IssueType.HTTP_5XX)],
)
def test_classify_status(status, expected):
    assert classify_status(status) == expected


def _chained(outer: Exception, cause: BaseException) -> Exception:
    outer.__cause__ = cause
    return outer


@pytest.mark.parametrize(
    "exc, expected",
    [
        (httpx.ConnectTimeout("timed out"), IssueType.TIMEOUT),
        (httpx.ReadTimeout("timed out"), IssueType.TIMEOUT),
        (httpx.TooManyRedirects("too many"), IssueType.TOO_MANY_REDIRECTS),
        (_chained(httpx.ConnectError("boom"), socket.gaierror(8, "nodename nor servname provided")), IssueType.DNS_ERROR),
        (_chained(httpx.ConnectError("boom"), ssl.SSLCertVerificationError(1, "CERTIFICATE_VERIFY_FAILED")), IssueType.SSL_ERROR),
        (httpx.ConnectError("[Errno -2] Name or service not known"), IssueType.DNS_ERROR),
        (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), IssueType.SSL_ERROR),
        (httpx.ConnectError("[Errno 61] Connection refused"), IssueType.CONNECTION_ERROR),
        (httpx.RemoteProtocolError("Server disconnected"), IssueType.CONNECTION_ERROR),
    ],
)
def test_classify_exception(exc, expected):
    assert classify_exception(exc) == expected


def test_options_caps_max_pages():
    assert CrawlOptions(max_pages=10_000).max_pages == MAX_PAGES_HARD_CAP
    assert CrawlOptions(max_pages=0).max_pages == 1
    assert CrawlOptions().max_pages == 100
