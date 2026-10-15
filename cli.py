"""Command-line entry point: python cli.py https://example.com --max-pages 100"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import signal
import sys
from typing import Optional

from app.crawler import crawl
from app.models import MAX_PAGES_HARD_CAP, CrawlOptions, CrawlResult, CrawlStats, Issue


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def _describe(issue: Issue) -> str:
    return str(issue.status_code) if issue.status_code and not issue.issue_type.is_warning else issue.issue_type.value


class ProgressPrinter:
    """Rewrites one status line on a TTY and prints the newest issue above it."""

    def __init__(self) -> None:
        self.tty = sys.stderr.isatty()
        self.last_issue: Optional[Issue] = None

    def __call__(self, stats: CrawlStats) -> None:
        width = shutil.get_terminal_size((100, 20)).columns
        issue = stats.latest_issue
        if issue is not None and issue is not self.last_issue:
            self.last_issue = issue
            mark = "!" if issue.is_warning else "✗"
            line = f"  {mark} {_describe(issue):<18} {issue.url}  (on {issue.found_on or 'start'})"
            self._clear()
            print(_truncate(line, width), file=sys.stderr)
        if self.tty:
            status = (
                f"[{stats.pages_crawled} pages | {stats.links_checked} checked | "
                f"{stats.errors_found} errors | {stats.warnings_found} warnings | {stats.queued} queued] "
                f"{stats.current_url}"
            )
            print("\r" + _truncate(status, width - 1), end="", file=sys.stderr, flush=True)

    def _clear(self) -> None:
        if self.tty:
            print("\r\033[K", end="", file=sys.stderr)

    def done(self) -> None:
        self._clear()


def print_summary(result: CrawlResult, limit: int) -> None:
    print()
    print(f"Crawl of {result.start_url}" + (" (cancelled)" if result.cancelled else ""))
    rows = [
        ("Pages crawled", result.pages_crawled),
        ("URLs checked", result.links_checked),
        ("Errors", result.errors_found),
        ("Warnings", result.warnings_found),
        ("Skipped by robots.txt", result.robots_skipped),
        ("Duration", f"{result.duration_s}s"),
    ]
    rows += [(f"  {t}", n) for t, n in sorted(result.counts_by_type.items())]
    for label, value in rows:
        print(f"  {label:<24} {value:>8}")
    if result.page_limit_reached:
        print("  Page limit reached; some pages were not crawled.")

    if not result.issues:
        print("\nNo issues found.")
        return

    width = shutil.get_terminal_size((140, 20)).columns
    url_w = max(30, (width - 40) // 2)
    page_w = max(20, width - url_w - 40)
    header = f"{'Problem':<18} {'URL':<{url_w}} {'Found on':<{page_w}} {'Time':>8}"
    print("\n" + header)
    print("-" * len(header))
    issues = sorted(result.issues, key=lambda i: (i.is_warning, i.issue_type.value, i.url))
    for issue in issues[:limit]:
        time_ms = f"{issue.response_time_ms:.0f}ms" if issue.response_time_ms is not None else ""
        print(
            f"{_describe(issue):<18} {_truncate(issue.url, url_w):<{url_w}} "
            f"{_truncate(issue.found_on or '(start URL)', page_w):<{page_w}} {time_ms:>8}"
        )
        if issue.link_text:
            print(f"{'':<18} text: {_truncate(issue.link_text, url_w)}")
        if len(issue.redirect_chain) > 1:
            chain = " → ".join(f"{h.status_code or '?'} {h.url}" for h in issue.redirect_chain)
            print(f"{'':<18} chain: {chain}")
    if len(issues) > limit:
        print(f"... and {len(issues) - limit} more (use --json for the full list)")


async def main_async(args: argparse.Namespace) -> CrawlResult:
    cancel = asyncio.Event()  # created inside the loop (required on Python < 3.10)
    loop = asyncio.get_running_loop()

    def on_sigint() -> None:
        print("\nCancelling... (Ctrl+C again to force quit)", file=sys.stderr)
        cancel.set()
        loop.remove_signal_handler(signal.SIGINT)

    try:
        loop.add_signal_handler(signal.SIGINT, on_sigint)
    except NotImplementedError:  # Windows
        pass

    options = CrawlOptions(
        max_pages=args.max_pages,
        check_external=not args.no_external,
        check_images=args.check_images,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
    )
    printer = ProgressPrinter()
    try:
        result = await crawl(args.url, options, on_progress=printer, cancel_event=cancel)
    finally:
        printer.done()
    return result


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Crawl a site and report broken links.")
    p.add_argument("url")
    p.add_argument("--max-pages", type=int, default=100, help=f"default 100, capped at {MAX_PAGES_HARD_CAP}")
    p.add_argument("--no-external", action="store_true", help="don't check links to other sites")
    p.add_argument("--check-images", action="store_true", help="also check <img src>")
    p.add_argument("--concurrency", type=int, default=5)
    p.add_argument("--delay", type=float, default=0.25, help="seconds to wait after each request")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--limit", type=int, default=50, help="max issues to print in the summary")
    p.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        result = asyncio.run(main_async(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print_summary(result, args.limit)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\nFull report written to {args.json}")
    return 1 if result.errors_found else 0


if __name__ == "__main__":
    sys.exit(main())
