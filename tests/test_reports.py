import csv
import io
import re
from datetime import datetime, timezone

from app.jobs import Job, JobStatus
from app.models import CrawlOptions, CrawlResult, Issue, IssueType, LinkKind, RedirectHop
from app.reports import build_csv, build_html, group_issues, report_filename

WHEN = datetime(2026, 10, 15, 19, 14, tzinfo=timezone.utc)
XSS_TEXT = '<script>alert(1)</script> <img src=x onerror="alert(2)"> "quoted" & \'single\''


def issue(url, type_=IssueType.HTTP_4XX, status=404, found_on="https://example.com/", text="link", **kw):
    return Issue(url=url, issue_type=type_, kind=kw.pop("kind", LinkKind.PAGE), found_on=found_on,
                 link_text=text, status_code=status, response_time_ms=kw.pop("ms", 12.5), **kw)


def make_job(issues, status=JobStatus.DONE, url="https://example.com/", error_message=None):
    errors = sum(not i.is_warning for i in issues)
    result = CrawlResult(start_url=url, pages_crawled=3, links_checked=7, errors_found=errors,
                         warnings_found=len(issues) - errors, duration_s=4.2,
                         cancelled=status == JobStatus.CANCELLED, issues=issues)
    return Job(
        id="abc123defg", url=url, options=CrawlOptions(), status=status,
        created_at=WHEN, started_at=WHEN, finished_at=WHEN,
        stats={"pages_crawled": 3, "links_checked": 7, "errors_found": errors,
               "warnings_found": len(issues) - errors, "current_url": ""},
        issues=list(issues), result=result, error_message=error_message,
        cancel_event=None,  # reports never touch it; asyncio.Event() needs a loop on Python 3.9
    )


CHAIN = [RedirectHop("https://a.test/1", 301), RedirectHop("https://a.test/2", 302), RedirectHop("https://a.test/3", 200)]


def sample_issues():
    return [
        issue("https://example.com/gone", found_on="https://example.com/"),
        issue("https://example.com/gone", found_on="https://example.com/about", text="Gone again"),
        issue("https://other.test/", IssueType.DNS_ERROR, None, kind=LinkKind.EXTERNAL, error="nodename nor servname"),
        issue("https://a.test/1", IssueType.REDIRECT_CHAIN, 200, kind=LinkKind.EXTERNAL, redirect_chain=CHAIN),
    ]


# --- group_issues ---


def test_group_issues_groups_by_url_and_splits_warnings():
    grouped = group_issues(sample_issues())
    assert [g.url for g in grouped.errors] == ["https://example.com/gone", "https://other.test/"]
    gone = grouped.errors[0]
    assert [(s.page, s.link_text) for s in gone.sources] == [
        ("https://example.com/", "link"), ("https://example.com/about", "Gone again")]
    assert gone.page_count == 2 and gone.status == 404
    [chain] = grouped.warnings
    assert [h.status_code for h in chain.chain] == [301, 302, 200]


# --- CSV ---


def read_csv(text):
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:])))


def test_csv_header_and_one_row_per_occurrence():
    rows = read_csv(build_csv(make_job(sample_issues())))
    assert rows[0] == ["broken_url", "type", "status_code", "error_detail", "found_on_page",
                       "link_text", "response_time_ms", "redirect_chain", "severity"]
    assert len(rows) == 1 + 4
    assert rows[1][:3] == ["https://example.com/gone", "http_4xx", "404"]
    assert rows[1][8] == "error"
    assert rows[4][7] == "https://a.test/1 -> https://a.test/2 -> https://a.test/3"
    assert rows[4][8] == "warning"
    assert rows[3][2] == ""  # no status for DNS failures


def test_csv_neutralizes_formula_injection():
    bad = ["=HYPERLINK(\"http://evil\")", "+1+2", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"]
    issues = [issue(f"https://example.com/{i}", text=t) for i, t in enumerate(bad)]
    issues.append(issue("=cmd|'/C calc'!A0", found_on="+evil"))
    rows = read_csv(build_csv(make_job(issues)))
    assert [r[5] for r in rows[1:7]] == ["'" + t for t in bad]
    assert rows[7][0] == "'=cmd|'/C calc'!A0"
    assert rows[7][4] == "'+evil"
    for row in rows[1:]:
        for cell in row:
            assert not cell.startswith(("=", "+", "-", "@", "\t", "\r"))


def test_csv_round_trips_awkward_text():
    texts = ['Hello, "world"', "line one\nline two", "Café ✓ 日本語 🪁", XSS_TEXT]
    issues = [issue(f"https://example.com/{i}", text=t) for i, t in enumerate(texts)]
    rows = read_csv(build_csv(make_job(issues)))
    assert [r[5] for r in rows[1:]] == texts


# --- HTML ---


def test_html_escapes_crawled_data():
    evil_url = 'https://example.com/x?q="><script>alert(3)</script>'
    issues = [
        issue(evil_url, text=XSS_TEXT, found_on='https://example.com/p"><img src=x onerror=alert(4)>'),
        issue("https://example.com/y", IssueType.CONNECTION_ERROR, None, error="<b>boom</b>"),
    ]
    page = build_html(make_job(issues))
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "<b>boom" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "onerror=&quot;alert(2)&quot;" in page
    assert "&lt;b&gt;boom&lt;/b&gt;" in page
    # the quote in the URL can't break out of the href attribute
    for href in re.findall(r'href="([^"]*)"', page):
        assert "<" not in href and ">" not in href
    assert re.search(r"<(script|img|iframe|object|embed)\b", page, re.I) is None


def test_html_does_not_link_non_http_urls():
    issues = [
        issue("javascript:alert(1)", found_on="javascript:alert(2)"),
        issue("data:text/html,<script>alert(1)</script>"),
        issue("https://ok.example/"),
    ]
    page = build_html(make_job(issues))
    hrefs = re.findall(r'href="([^"]*)"', page)
    assert all(h.startswith(("http://", "https://")) for h in hrefs)
    assert "javascript:alert(1)" in page  # shown as text
    assert 'href="https://ok.example/"' in page
    assert all('rel="noopener noreferrer"' in a and 'target="_blank"' in a for a in re.findall(r"<a [^>]*>", page))


def test_html_is_self_contained():
    page = build_html(make_job(sample_issues()))
    assert "<script" not in page
    assert "<link" not in page
    assert "@import" not in page and "url(" not in page
    assert "prefers-color-scheme: dark" in page and "@media print" in page


def test_html_content_sections():
    page = build_html(make_job(sample_issues()), generated_at=WHEN)
    assert "example.com" in page and "15 Oct 2026, 19:14 UTC" in page
    assert "Broken links" in page and "Warnings" in page
    assert "Found on 2 pages" in page and "Gone again" in page
    assert "Redirect chain · 2 hops" in page and "https://a.test/2" in page
    assert "nodename nor servname" in page
    assert "up to 100 pages, external links checked, images not checked" in page
    assert "Partial results" not in page
    assert "No broken links found" not in page


def test_html_partial_notice_for_cancelled_jobs():
    page = build_html(make_job(sample_issues(), status=JobStatus.CANCELLED))
    assert "Partial results" in page
    timed_out = build_html(make_job([], status=JobStatus.CANCELLED,
                                    error_message="Stopped after the 10-minute time limit."))
    assert "10-minute time limit" in timed_out


def test_html_empty_state():
    page = build_html(make_job([]))
    assert "No broken links found" in page
    assert "<h2>Broken links" not in page


def test_html_handles_job_without_result():
    job = make_job([], status=JobStatus.CANCELLED)
    job.result = None  # cancelled while queued
    assert "Partial results" in build_html(job)


# --- filenames ---


def test_report_filename():
    assert report_filename(make_job([]), "csv") == "link-check_example.com_2026-10-15.csv"
    assert report_filename(make_job([], url="https://WWW.Bücher.example:8080/a"), "html") == \
        "link-check_www.b-cher.example_2026-10-15.html"
    assert report_filename(make_job([], url="http://[::1]:8000/"), "csv") == "link-check_--1_2026-10-15.csv"
