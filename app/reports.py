"""Report builders: CSV and standalone HTML. Pure functions, no web code.

Everything that came from a crawled site (URLs, link text, error details) is
untrusted: it is HTML-escaped in the HTML report and neutralized against
formula injection in the CSV.
"""

from __future__ import annotations

import csv
import html
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Iterable, Optional
from urllib.parse import urlsplit

from app.models import Issue, IssueType, LinkKind, RedirectHop

TYPE_LABELS = {
    IssueType.HTTP_4XX: "Client error",
    IssueType.HTTP_5XX: "Server error",
    IssueType.TIMEOUT: "Timeout",
    IssueType.DNS_ERROR: "DNS failure",
    IssueType.SSL_ERROR: "SSL error",
    IssueType.CONNECTION_ERROR: "Connection failed",
    IssueType.TOO_MANY_REDIRECTS: "Too many redirects",
    IssueType.REDIRECT_CHAIN: "Redirect chain",
    IssueType.BLOCKED: "Blocked",
}
TYPE_ORDER = list(TYPE_LABELS)
KIND_LABELS = {LinkKind.PAGE: "Page", LinkKind.EXTERNAL: "External", LinkKind.IMAGE: "Image"}

CSV_COLUMNS = [
    "broken_url", "type", "status_code", "error_detail", "found_on_page",
    "link_text", "response_time_ms", "redirect_chain", "severity",
]
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


# --- Grouping ----------------------------------------------------------------


@dataclass
class Source:
    page: Optional[str]  # None = the start URL itself
    link_text: str


@dataclass
class IssueGroup:
    url: str
    type: IssueType
    status: Optional[int]
    error: str
    kind: LinkKind
    response_time_ms: Optional[float]
    chain: list[RedirectHop]
    sources: list[Source] = field(default_factory=list)

    @property
    def is_warning(self) -> bool:
        return self.type.is_warning

    @property
    def page_count(self) -> int:
        return len({s.page for s in self.sources})


@dataclass
class GroupedIssues:
    errors: list[IssueGroup]
    warnings: list[IssueGroup]


def group_issues(issues: Iterable[Issue]) -> GroupedIssues:
    """Group issue occurrences by broken URL; errors and warnings separately."""
    groups: dict[str, IssueGroup] = {}
    for issue in issues:
        group = groups.get(issue.url)
        if group is None:
            group = groups[issue.url] = IssueGroup(
                url=issue.url,
                type=issue.issue_type,
                status=issue.status_code,
                error=issue.error,
                kind=issue.kind,
                response_time_ms=issue.response_time_ms,
                chain=list(issue.redirect_chain),
            )
        group.sources.append(Source(issue.found_on, issue.link_text))
    ordered = sorted(groups.values(), key=lambda g: (TYPE_ORDER.index(g.type), g.status or 0, g.url))
    return GroupedIssues(
        errors=[g for g in ordered if not g.is_warning],
        warnings=[g for g in ordered if g.is_warning],
    )


# --- Shared helpers ------------------------------------------------------------


def report_filename(job, ext: str) -> str:
    """link-check_<domain>_<YYYY-MM-DD>.<ext>, limited to [a-z0-9._-]."""
    domain = (urlsplit(job.url).hostname or "site").lower()
    when = job.finished_at or job.started_at or job.created_at
    name = f"link-check_{domain}_{when:%Y-%m-%d}.{ext}".lower()
    return re.sub(r"[^a-z0-9._-]", "-", name)


def issue_label(type_: IssueType, status: Optional[int]) -> str:
    if type_ in (IssueType.HTTP_4XX, IssueType.HTTP_5XX) and status:
        try:
            return f"{status} {HTTPStatus(status).phrase}"
        except ValueError:
            return f"{status} {TYPE_LABELS[type_]}"
    return TYPE_LABELS.get(type_, str(type_.value))


def _format_ms(ms: Optional[float]) -> str:
    if ms is None:
        return ""
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{round(ms)} ms"


def _format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{int(seconds // 60)}m {round(seconds % 60):02d}s"


def _format_when(dt: Optional[datetime]) -> str:
    if dt is None:
        return "—"
    dt = dt.astimezone(timezone.utc)
    return f"{dt.day} {dt:%b %Y, %H:%M} UTC"


def _plural(n: int, one: str, many: Optional[str] = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


# --- CSV -----------------------------------------------------------------------


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    # Spreadsheet apps execute cells starting with these as formulas.
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def build_csv(job) -> str:
    """One row per issue occurrence. Returned with a UTF-8 BOM for Excel."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for issue in job.issues:
        writer.writerow([_csv_cell(v) for v in (
            issue.url,
            issue.issue_type.value,
            issue.status_code,
            issue.error,
            issue.found_on,
            issue.link_text,
            issue.response_time_ms,
            " -> ".join(hop.url for hop in issue.redirect_chain),
            "warning" if issue.is_warning else "error",
        )])
    return "﻿" + out.getvalue()


# --- HTML ----------------------------------------------------------------------


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _link(url: Optional[str]) -> str:
    """Escaped URL as a link if it's http(s), otherwise as plain text."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = None
    if parts and parts.scheme.lower() in ("http", "https") and parts.netloc:
        return f'<a href="{_e(url)}" target="_blank" rel="noopener noreferrer">{_e(url)}</a>'
    return f'<span class="url">{_e(url)}</span>'


REPORT_CSS = """
:root {
  --navy: #1C1B3A; --plum: #611B35; --butter: #F4F27A; --lilac-deep: #7A5A92;
  --cream: #F6F1E7; --paper: #FFFFFF; --line: #D9CDB8; --ink: #1C1B3A; --ink-muted: #5E5A73;
  --error: #C62F3E; --error-bg: #FBE8EA; --error-ink: #9E1F2D;
  --warning: #B7791F; --warning-bg: #FBF1DC; --warning-ink: #74490B;
  --success-bg: #E2F4E7; --success-ink: #17652F;
  --bg: var(--cream); --surface: var(--paper); --surface-muted: #FBF8F1;
  --text: var(--ink); --text-muted: var(--ink-muted); --border: var(--line);
  --band-bg: var(--plum); --band-text: #FFFFFF; --band-muted: #EBD9E0;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: var(--navy); --surface: #27254C; --surface-muted: #221F44;
    --text: var(--cream); --text-muted: #C8C2D8; --border: #3D3A6B;
    --band-bg: #6A1E3A; --lilac-deep: #B9A0CC;
    --error-bg: #42192A; --error-ink: #FFB1BA; --error: #F07A88;
    --warning-bg: #302917; --warning-ink: #F6CF7A; --warning: #D9A440;
    --success-bg: #173B27; --success-ink: #8BE3A6;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--text); }
body { font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
h1, h2, .num { font-family: Georgia, "Times New Roman", serif; font-weight: 400; }
a { color: inherit; text-decoration: underline; text-decoration-color: color-mix(in srgb, currentColor 40%, transparent); text-underline-offset: 3px; }
.url, a { overflow-wrap: anywhere; word-break: break-word; }
.wrap { max-width: 980px; margin: 0 auto; padding: 0 20px; }
.eyebrow { font-size: 12px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; color: var(--text-muted); margin: 0 0 8px; }
.muted { color: var(--text-muted); }
.band { background: var(--band-bg); color: var(--band-text); padding: 36px 0 40px; }
.band .eyebrow { color: var(--butter); }
.band h1 { font-size: clamp(32px, 6vw, 52px); line-height: 1.1; margin: 4px 0 10px; overflow-wrap: anywhere; }
.band p { margin: 4px 0; color: var(--band-muted); }
.band a { color: var(--band-text); }
main { padding: 32px 0 48px; }
.notice { border: 1px solid; border-radius: 16px; padding: 14px 18px; margin: 0 0 24px; font-weight: 500; }
.notice-warning { background: var(--warning-bg); color: var(--warning-ink); border-color: color-mix(in srgb, var(--warning) 40%, transparent); }
.cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 0 0 36px; padding: 0; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 20px; padding: 16px 18px; margin: 0; }
.card dt { font-size: 11px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; color: var(--text-muted); }
.card .num { font-size: 40px; line-height: 1.1; margin: 8px 0 0; }
.card .sub { font-size: 12px; color: var(--text-muted); margin: 4px 0 0; }
.num-error { color: var(--error-ink); }
h2 { font-size: 30px; margin: 0 0 12px; display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
h2 small { font-family: system-ui, sans-serif; font-size: 14px; color: var(--text-muted); }
.list { list-style: none; margin: 0 0 40px; padding: 0; background: var(--surface); border: 1px solid var(--border); border-radius: 24px; overflow: hidden; }
.item { padding: 18px 22px; break-inside: avoid; }
.item + .item { border-top: 1px solid var(--border); }
.item-head { display: flex; gap: 12px; align-items: flex-start; }
.item-url { font-weight: 600; margin: 0; }
.meta { font-size: 13px; color: var(--text-muted); margin: 2px 0 0; }
.detail { font-size: 14px; margin: 12px 0 0; }
.badge { display: inline-block; flex: none; white-space: nowrap; border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 700; border: 1px solid; }
.badge-error { background: var(--error-bg); color: var(--error-ink); border-color: color-mix(in srgb, var(--error) 45%, transparent); }
.badge-warning { background: var(--warning-bg); color: var(--warning-ink); border-color: color-mix(in srgb, var(--warning) 45%, transparent); }
.badge-neutral { background: var(--surface-muted); color: var(--text-muted); border-color: var(--border); font-weight: 500; }
.label { font-size: 11px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; color: var(--text-muted); margin: 14px 0 6px; }
.sources, .chain { margin: 0; padding: 0; list-style: none; font-size: 14px; }
.sources li, .chain li { margin: 4px 0; }
.chain li { display: flex; gap: 8px; align-items: baseline; }
.chain .step { font-family: Georgia, serif; color: var(--lilac-deep); min-width: 1.5em; }
.quote { color: var(--text-muted); }
.warnings .list { background: var(--warning-bg); border-color: color-mix(in srgb, var(--warning) 35%, transparent); font-size: 14px; }
.warnings .item + .item { border-top-color: color-mix(in srgb, var(--warning) 25%, transparent); }
.warnings h2 { font-size: 24px; }
.all-clear { background: var(--success-bg); color: var(--success-ink); border-radius: 24px; padding: 44px 24px; text-align: center; margin: 0 0 40px; }
.all-clear p { margin: 6px 0 0; }
.all-clear .big { font-family: Georgia, serif; font-size: 40px; margin: 0; }
footer { border-top: 1px solid var(--border); padding: 20px 0 32px; font-size: 13px; color: var(--text-muted); }
footer p { margin: 4px 0; }
@media (max-width: 760px) {
  .cards { grid-template-columns: repeat(2, 1fr); }
  .cards .card:last-child { grid-column: span 2; }
  .item-head { flex-direction: column; gap: 6px; }
}
@media print {
  :root { --bg: #FFFFFF; --surface: #FFFFFF; --text: #1C1B3A; --text-muted: #4A465E; --border: #CCCCCC; }
  body { font-size: 11pt; }
  .band { background: none; color: var(--text); border-bottom: 3px solid var(--plum); padding: 0 0 12px; }
  .band .eyebrow, .band p, .band a { color: var(--text); }
  .card, .list { box-shadow: none; }
  a { text-decoration: none; }
  .item, .card { break-inside: avoid; }
}
"""


def _group_html(group: IssueGroup) -> str:
    tone = "warning" if group.is_warning else "error"
    meta = [KIND_LABELS.get(group.kind, str(group.kind)), _format_ms(group.response_time_ms),
            f"Found on {_plural(group.page_count, 'page')}"]
    parts = [
        '<li class="item"><div class="item-head">',
        f'<span class="badge badge-{tone}">{_e(issue_label(group.type, group.status))}</span>',
        f'<div><p class="item-url">{_link(group.url)}</p>',
        f'<p class="meta">{_e(" · ".join(m for m in meta if m))}</p></div></div>',
    ]
    if group.error and group.type not in (IssueType.HTTP_4XX, IssueType.HTTP_5XX):
        parts.append(f'<p class="detail muted">{_e(group.error)}</p>')
    if group.chain:
        parts.append(f'<p class="label">Redirect chain · {_plural(len(group.chain) - 1, "hop")}</p><ol class="chain">')
        for i, hop in enumerate(group.chain, 1):
            status = _e(hop.status_code) if hop.status_code else "?"
            parts.append(f'<li><span class="step">{i}.</span><span class="badge badge-neutral">{status}</span>{_link(hop.url)}</li>')
        parts.append("</ol>")
    parts.append('<p class="label">Found on</p><ul class="sources">')
    for source in group.sources:
        page = _link(source.page) if source.page else '<span class="muted">The start URL itself</span>'
        text = f' <span class="quote">“{_e(source.link_text)}”</span>' if source.link_text else ""
        parts.append(f"<li>{page}{text}</li>")
    parts.append("</ul></li>")
    return "".join(parts)


def _options_text(options) -> str:
    return (
        f"up to {options.max_pages} pages, external links "
        f"{'checked' if options.check_external else 'not checked'}, images "
        f"{'checked' if options.check_images else 'not checked'}"
    )


def build_html(job, generated_at: Optional[datetime] = None) -> str:
    """A self-contained HTML report: inline CSS, no JS, no external requests."""
    generated_at = generated_at or datetime.now(timezone.utc)
    grouped = group_issues(job.issues)
    result = job.result
    host = urlsplit(job.url).netloc or job.url
    occurrences = sum(len(g.sources) for g in grouped.errors)
    duration = result.duration_s if result else None

    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="light dark">',
        '<meta name="robots" content="noindex">',
        f"<title>Link check report · {_e(host)}</title>",
        f"<style>{REPORT_CSS}</style></head><body>",
        '<header class="band"><div class="wrap">',
        '<p class="eyebrow">Link check report · Fly More Kites</p>',
        f"<h1>{_e(host)}</h1>",
        f"<p>{_link(job.url)}</p>",
        f"<p>Scanned {_e(_format_when(job.started_at or job.created_at))}</p>",
        "</div></header>",
        '<main><div class="wrap">',
    ]

    if job.status.value == "cancelled":
        detail = job.error_message or "The scan was stopped early."
        out.append(f'<div class="notice notice-warning">Partial results. {_e(detail)}</div>')

    cards = [
        ("Pages crawled", f"{job.stats['pages_crawled']:,}", "", ""),
        ("Links checked", f"{job.stats['links_checked']:,}", "", ""),
        ("Broken links", f"{len(grouped.errors):,}", f"in {_plural(occurrences, 'place')}" if grouped.errors else "",
         "num-error" if grouped.errors else ""),
        ("Warnings", f"{len(grouped.warnings):,}", "redirect chains &amp; more" if grouped.warnings else "", ""),
        ("Duration", _format_duration(duration), "", ""),
    ]
    out.append('<dl class="cards">')
    for label, value, sub, cls in cards:
        sub_html = f'<dd class="sub">{sub}</dd>' if sub else ""
        out.append(f'<div class="card"><dt>{label}</dt><dd class="num {cls}">{_e(value)}</dd>{sub_html}</div>')
    out.append("</dl>")

    if not grouped.errors:
        sub = ("Every link we checked works. A few redirects could be tidied up below."
               if grouped.warnings else "Every link we checked works.")
        out.append(f'<div class="all-clear"><p class="big">No broken links found</p><p>{sub}</p></div>')
    else:
        out.append(f'<section><h2>Broken links <small>{_plural(len(grouped.errors), "URL")}</small></h2><ul class="list">')
        out.extend(_group_html(g) for g in grouped.errors)
        out.append("</ul></section>")

    if grouped.warnings:
        out.append(f'<section class="warnings"><h2>Warnings <small>{_plural(len(grouped.warnings), "URL")}</small></h2>')
        out.append('<p class="muted">These still work, but are worth tidying up.</p><ul class="list">')
        out.extend(_group_html(g) for g in grouped.warnings)
        out.append("</ul></section>")

    out.append("</div></main><footer><div class=\"wrap\">")
    out.append(f"<p>Generated {_e(_format_when(generated_at))} by Link Checker · Fly More Kites.</p>")
    out.append(f"<p>Options: {_e(_options_text(job.options))}.</p>")
    if result and result.page_limit_reached:
        out.append(f"<p>The {job.options.max_pages}-page limit was reached, so some pages weren’t checked.</p>")
    if result and result.url_cap_reached:
        out.append("<p>The per-scan link limit was reached, so some links weren’t checked.</p>")
    if result and result.external_cap_reached:
        out.append(f"<p>Only the first {job.options.max_external} external links were checked.</p>")
    if result and result.link_cap_pages:
        out.append(f"<p>{_plural(result.link_cap_pages, 'page')} had more than {job.options.max_links_per_page} links; the extras were skipped.</p>")
    if result and result.pages_truncated:
        out.append(f"<p>{_plural(result.pages_truncated, 'page')} exceeded 2 MB; only the first 2 MB was checked.</p>")
    if result and result.robots_skipped:
        out.append(f"<p>{_plural(result.robots_skipped, 'page')} skipped because of robots.txt.</p>")
    out.append("</div></footer></body></html>")
    return "\n".join(out)


def build_message_page(title: str, message: str, link_href: str, link_text: str) -> str:
    """Small branded page for 'not ready' / 'not found' on /report/{id}."""
    return "\n".join([
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="light dark"><meta name="robots" content="noindex">',
        f"<title>{_e(title)} · Link Checker</title>",
        f"<style>{REPORT_CSS}.msg{{max-width:560px;margin:48px auto;text-align:center}}"
        ".msg h1{font-size:36px;margin:0 0 12px}"
        ".btn{display:inline-block;margin-top:20px;padding:12px 24px;border-radius:999px;background:#1E7D3D;"
        "color:#fff;text-decoration:none;font-size:12px;font-weight:700;letter-spacing:.15em;text-transform:uppercase}</style>",
        "</head><body>",
        '<header class="band"><div class="wrap"><p class="eyebrow">Link Checker · Fly More Kites</p></div></header>',
        f'<main><div class="wrap msg"><h1>{_e(title)}</h1><p class="muted">{_e(message)}</p>',
        f'<a class="btn" href="{_e(link_href)}">{_e(link_text)}</a></div></main>',
        "</body></html>",
    ])
