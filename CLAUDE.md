# Site Link Checker

A small web app: users paste a URL, it crawls the site, finds broken links and
page-loading errors, shows live progress, and offers a downloadable report.

## Stack
- Python 3.12 (pinned: .python-version and PYTHON_VERSION in render.yaml), FastAPI, httpx (async), BeautifulSoup4
- Frontend: a single HTML page with Tailwind (CDN) and vanilla JS, served by FastAPI. No build step.
- No database. Job state in memory; reports are generated on request from the in-memory
  job (nothing is written to disk).

## Deployment constraints (Render free tier)
- 512 MB RAM, low CPU, filesystem is wiped on restart, service sleeps when idle
- Single uvicorn worker only (state is in memory)
- One active crawl at a time; others queue
- Progress via polling (1s), not SSE
- Hard cap of 500 pages per crawl

## Principles
- Keep it simple. No extra frameworks, no premature abstraction.
- Public page: SSRF protection and abuse limits are required (see Security).
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

## Security
- Network egress policy lives ONLY in app/security.py: validate_url (pre-check, used by the
  API and before every crawler request and redirect hop) and GuardedBackend/make_guarded_transport
  (connection-time check). Don't add allow/deny logic anywhere else.
- Default deny: http/https only, no userinfo, URL <= 2048 chars, ports 80/443/8080/8443, no
  localhost/.local/.internal/.localdomain/metadata names, and EVERY resolved address must be
  public (no loopback, private, link-local incl. 169.254.169.254, CGNAT, multicast, reserved,
  unspecified, fc00::/7, fe80::/10, or IPv4 embedded in mapped/compatible/6to4/NAT64 IPv6).
  Legacy IPv4 spellings (2130706433, 0x7f000001, 127.1) are parsed and checked like the OS would.
- "Resolves to a blocked address" = blocked. "Doesn't resolve" = allowed, so broken external
  links are still reported as DNS errors.
- DNS rebinding: the guarded transport resolves the host itself, validates every address and
  connects to the validated IP; TLS SNI/cert checks still use the hostname. The crawler uses it
  for every request (pass `transport=` only in tests). httpx clients use trust_env=False.
- Users and reports only ever see "This address isn't allowed." / "Blocked: not a public
  address". Reasons and resolved IPs go to server logs only.
- Crawler limits: 2 MB decoded HTML per page (gzip/deflate inflated with a cap), status-only
  checks read no body, 10s overall deadline per request, caps on unique URLs, links per page and
  external URLs, 2 concurrent requests per external host.
- Abuse limits (app/ratelimit.py, in memory): jobs per hour per IP, active jobs per IP and per
  target domain, API/report requests per minute per IP, 4 KB body limit on POST /api/jobs.
  429s carry Retry-After and a human message.
- Client IP: socket peer, or the Nth X-Forwarded-For entry from the RIGHT when
  TRUSTED_PROXY_HOPS=N. Run uvicorn with --no-proxy-headers so this is the only XFF logic.
- Env vars: ALLOW_PRIVATE_HOSTS (dev only, never in deploy config), ALLOWED_PORTS,
  TRUSTED_PROXY_HOPS, CONTACT_URL, RATE_LIMIT_*, MAX_URLS_PER_JOB, MAX_LINKS_PER_PAGE,
  MAX_EXTERNAL_PER_JOB, PER_HOST_CONCURRENCY. See the README table.
- Tests: set ALLOW_PRIVATE_HOSTS=1 only in specific fixtures (test_api, test_ratelimit, the e2e
  server launcher). tests/test_security.py runs with it unset. Never set it globally.

## Deployment
- Render free tier via the Blueprint in render.yaml (Python runtime, plan free, autoDeployTrigger:
  commit, healthCheckPath /health). Start command:
  `uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1 --no-proxy-headers`.
- tests/test_deploy.py guards render.yaml: never ALLOW_PRIVATE_HOSTS, exactly 1 worker,
  --no-proxy-headers present, PYTHON_VERSION matches .python-version.
- Every runtime dependency is pinned with == in requirements.txt. httpx/httpcore must match the
  pin (tests/test_versions.py) because app/security.py patches httpx internals.
- TRUSTED_PROXY_HOPS=1 on Render; verify it after every infra change (README checklist).
- CONTACT_URL is set in the dashboard (sync: false), not in the repo.
- Memory: at most MAX_FINISHED_JOBS (30) finished jobs are kept, plus 24h expiry.
- Post-deploy: python scripts/smoke_test.py <url> [--scan-url <site you may crawl>].

