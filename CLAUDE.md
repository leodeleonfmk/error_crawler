# Site Link Checker

A small web app: users paste a URL, it crawls the site, finds broken links and
page-loading errors, shows live progress, and offers a downloadable report.

## Stack
- Python 3.11+, FastAPI, httpx (async), BeautifulSoup4
- Frontend: a single HTML page with Tailwind (CDN) and vanilla JS, served by FastAPI. No build step.
- No database. Job state in memory; reports written to ./reports (ephemeral).

## Deployment constraints (Render free tier)
- 512 MB RAM, low CPU, filesystem is wiped on restart, service sleeps when idle
- Single uvicorn worker only (state is in memory)
- One active crawl at a time; others queue
- Progress via polling (1s), not SSE
- Hard cap of 500 pages per crawl

## Principles
- Keep it simple. No extra frameworks, no premature abstraction.
- Public page: SSRF protection and abuse limits are required (added in a later step).
- Crawler must be usable standalone (CLI) and from the web layer via callbacks.
- Write small tests for the core logic (pytest).

## Reports
- Built by pure functions in app/reports.py (group_issues, build_csv, build_html); no web code there.
- GET /api/jobs/{id}/report.csv and /report.html: downloads (Content-Disposition: attachment),
  named link-check_<domain>_<YYYY-MM-DD>.<ext>.
- GET /report/{id}: the same HTML inline, as a read-only share page (no JS).
- Only for done or cancelled jobs: 409 while queued/running/failed, 404 for unknown ids
  (JSON on /api routes, a branded HTML page on /report/{id}).
- Crawled data is untrusted: HTML-escape everything, link only http(s) URLs, neutralize CSV
  formula cells. HTML reports are served with a strict CSP (default-src 'none').
- Share links are temporary (in-memory jobs, 24h cleanup, lost on restart); downloads are permanent.
