"""Post-deploy smoke test. Uses only httpx; no test framework.

    python scripts/smoke_test.py https://your-app.onrender.com
    python scripts/smoke_test.py https://your-app.onrender.com --scan-url https://example.com

Nothing is scanned unless --scan-url is given.
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://localhost:22",
    "file:///etc/passwd",
]
REPORT_HEADERS = {
    "content-security-policy": "default-src 'none'",
    "x-content-type-options": "nosniff",
    "x-robots-tag": "noindex",
    "referrer-policy": "no-referrer",
}
WAKE_TIMEOUT_S = 90
SCAN_TIMEOUT_S = 300

results: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def header_problems(resp: httpx.Response, expected: dict) -> list:
    return [f"{k} missing/wrong" for k, v in expected.items() if v not in resp.headers.get(k, "")]


def check_health(client: httpx.Client) -> bool:
    print(f"Waking the service if it's asleep (free tier); allowing up to {WAKE_TIMEOUT_S}s...", flush=True)
    started = time.monotonic()
    try:
        resp = client.get("/health", timeout=WAKE_TIMEOUT_S)
    except httpx.HTTPError as exc:
        return check("GET /health", False, f"{type(exc).__name__}: {exc}")
    latency = time.monotonic() - started
    ok = resp.status_code == 200 and resp.json() == {"status": "ok"}
    check("GET /health", ok, f"{resp.status_code}, {latency:.2f}s{' (cold start)' if latency > 5 else ''}")
    if ok:
        started = time.monotonic()
        client.get("/health")
        check("GET /health (warm)", True, f"{time.monotonic() - started:.2f}s")
    return ok


def check_index(client: httpx.Client) -> None:
    resp = client.get("/")
    ok = (resp.status_code == 200 and resp.headers.get("content-type", "").startswith("text/html")
          and "<title>Link Checker" in resp.text)
    check("GET / serves the app page", ok, f"{resp.status_code} {resp.headers.get('content-type')}")
    problems = header_problems(resp, {"x-content-type-options": "nosniff", "x-frame-options": "DENY",
                                      "referrer-policy": "no-referrer"})
    check("GET / security headers", not problems, ", ".join(problems))


def check_ssrf(client: httpx.Client) -> None:
    for url in SSRF_PAYLOADS:
        resp = client.post("/api/jobs", json={"url": url})
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        check(f"SSRF blocked: {url}", resp.status_code == 400, f"{resp.status_code} {body.get('error', '')}")


def run_scan(client: httpx.Client, scan_url: str) -> None:
    resp = client.post("/api/jobs", json={"url": scan_url, "max_pages": 10,
                                          "check_external": False, "check_images": False})
    if not check(f"POST /api/jobs {scan_url}", resp.status_code == 201, f"{resp.status_code} {resp.text[:200]}"):
        return
    job_id = resp.json()["id"]
    deadline = time.monotonic() + SCAN_TIMEOUT_S
    status = "queued"
    while time.monotonic() < deadline:
        resp = client.get(f"/api/jobs/{job_id}", params={"since": 10**9})
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("retry-after", "5")))
            continue
        status = resp.json().get("status")
        if status in ("done", "cancelled", "failed"):
            break
        time.sleep(1.5)
    stats = resp.json().get("stats", {}) if resp.status_code == 200 else {}
    if not check("scan finished", status == "done",
                 f"status={status}, pages={stats.get('pages_crawled')}, checked={stats.get('links_checked')}"):
        return

    csv = client.get(f"/api/jobs/{job_id}/report.csv")
    check("report.csv", csv.status_code == 200 and csv.headers.get("content-type", "").startswith("text/csv")
          and csv.headers.get("content-disposition", "").startswith("attachment"),
          f"{csv.status_code} {csv.headers.get('content-type')}")

    html = client.get(f"/api/jobs/{job_id}/report.html")
    problems = header_problems(html, REPORT_HEADERS)
    check("report.html", html.status_code == 200 and html.headers.get("content-type", "").startswith("text/html")
          and html.headers.get("content-disposition", "").startswith("attachment") and not problems,
          f"{html.status_code} {', '.join(problems)}")

    page = client.get(f"/report/{job_id}")
    problems = header_problems(page, REPORT_HEADERS)
    check(f"/report/{job_id}", page.status_code == 200 and page.headers.get("content-type", "").startswith("text/html")
          and "content-disposition" not in page.headers and not problems,
          f"{page.status_code} {', '.join(problems)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test a deployed Link Checker.")
    parser.add_argument("base_url", help="e.g. https://your-app.onrender.com")
    parser.add_argument("--scan-url", help="a site you're allowed to scan (10 pages, no external/image checks)")
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=20, follow_redirects=False) as client:
        if check_health(client):
            check_index(client)
            check_ssrf(client)
            if args.scan_url:
                run_scan(client, args.scan_url)
            else:
                print("SKIP  scan and report checks (pass --scan-url to run them)")

    failed = results.count(False)
    print(f"\n{'PASS' if not failed else 'FAIL'}: {len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
