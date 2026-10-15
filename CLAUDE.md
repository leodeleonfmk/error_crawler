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