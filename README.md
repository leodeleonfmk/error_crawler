# Site Link Checker

Paste a URL, crawl the site, and get a report of broken links and page-loading errors.

## Running locally

Requires Python 3.9+ (3.11+ recommended).

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

uvicorn app.main:app --reload
```

Then open http://localhost:8000. Run a single worker only: job state is kept in memory.

SSRF protection is on by default, so `localhost` and other private addresses can't be
scanned. To scan a local test site during development, opt out for that shell only:

```sh
ALLOW_PRIVATE_HOSTS=1 uvicorn app.main:app --reload
python -m http.server 8765 -d tests/e2e/fixtures/site   # then scan http://localhost:8765
```

In production, start it with `--no-proxy-headers` so the app's own `TRUSTED_PROXY_HOPS`
logic is the only thing that reads `X-Forwarded-For`:

```sh
uvicorn app.main:app --host 0.0.0.0 --port $PORT --no-proxy-headers
```

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALLOW_PRIVATE_HOSTS` | unset | `1` disables private-address, hostname and port blocking. **Local development only; never set in deploy config.** Logs a loud warning at startup. |
| `ALLOWED_PORTS` | `80,443,8080,8443` | Ports the crawler may connect to. |
| `TRUSTED_PROXY_HOPS` | `0` | `0`: rate-limit by socket peer. `N`: use the Nth `X-Forwarded-For` entry from the right (Render: `1`). The first 3 requests log the resolved IP so you can verify. |
| `CONTACT_URL` | unset | Appended to the User-Agent as `SiteLinkChecker/1.0 (+URL)` so site owners can reach you. |
| `RATE_LIMIT_JOBS_PER_HOUR` | `20` | New scans per IP per hour. |
| `RATE_LIMIT_ACTIVE_JOBS_PER_IP` | `2` | Running + queued scans per IP. |
| `RATE_LIMIT_ACTIVE_JOBS_PER_DOMAIN` | `1` | Running + queued scans per target site (www counts as the same site), across all users. |
| `RATE_LIMIT_API_PER_MINUTE` | `120` | `/api/*` and `/report/*` requests per IP per minute. |
| `MAX_URLS_PER_JOB` | `5000` | Unique URLs tracked per scan. |
| `MAX_LINKS_PER_PAGE` | `2000` | Links read from a single page. |
| `MAX_EXTERNAL_PER_JOB` | `300` | External URLs checked per scan. |
| `PER_HOST_CONCURRENCY` | `2` | Simultaneous requests to any one external host. |

Fixed limits: 500 pages per scan, 2 MB of HTML read per page, 10 s per request, 5 redirects,
4 KB request body on `POST /api/jobs`.

### API

```sh
# Start a crawl (scheme defaults to https://, max_pages is clamped to 1..500)
curl -X POST localhost:8000/api/jobs -H 'content-type: application/json' \
  -d '{"url": "example.com", "max_pages": 100, "check_external": true, "check_images": false}'

# Poll for progress; pass next_since back as ?since= to get only new issues
curl 'localhost:8000/api/jobs/<id>?since=0'

# Cancel a queued or running crawl (partial results are kept)
curl -X POST localhost:8000/api/jobs/<id>/cancel

# Reports (finished or cancelled jobs only)
curl -OJ localhost:8000/api/jobs/<id>/report.csv
curl -OJ localhost:8000/api/jobs/<id>/report.html
open http://localhost:8000/report/<id>     # shareable page, expires with the job

curl localhost:8000/health
```

Errors always come back as `{"error": "message"}`.

### CLI

```sh
python cli.py https://example.com --max-pages 100 [--check-images] [--no-external] [--json report.json]
python cli.py http://intranet.local --allow-private    # private hosts and any port, for local use
```

### Tests

```sh
pytest
```

Browser tests (Playwright) live in `tests/e2e/` and are skipped by default. They start
their own uvicorn (with `ALLOW_PRIVATE_HOSTS=1` and relaxed rate limits for that process only)
and fixture sites on free ports:

```sh
pytest -m e2e                                  # uses installed Google Chrome
PLAYWRIGHT_CHANNEL= pytest -m e2e              # or Playwright's Chromium (run `playwright install chromium` first)
E2E_SCREENSHOTS=/tmp/shots pytest -m e2e       # also save screenshots
```
