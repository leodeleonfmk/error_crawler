# Site Link Checker

Paste a URL, crawl the site, and get a report of broken links and page-loading errors.

## Running locally

Requires Python 3.12 (the version is pinned in `.python-version`; `uv python install 3.12`
works if you don't have it).

```sh
python3.12 -m venv .venv
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
| `CONTACT_URL` | unset | Added to the User-Agent, `Mozilla/5.0 (compatible; SiteLinkChecker/1.0; +URL)`, so site owners can reach you. |
| `RATE_LIMIT_JOBS_PER_HOUR` | `20` | New scans per IP per hour. |
| `RATE_LIMIT_ACTIVE_JOBS_PER_IP` | `2` | Running + queued scans per IP. |
| `RATE_LIMIT_ACTIVE_JOBS_PER_DOMAIN` | `1` | Running + queued scans per target site (www counts as the same site), across all users. |
| `RATE_LIMIT_API_PER_MINUTE` | `120` | `/api/*` and `/report/*` requests per IP per minute. |
| `MAX_URLS_PER_JOB` | `5000` | Unique URLs tracked per scan. |
| `MAX_LINKS_PER_PAGE` | `2000` | Links read from a single page. |
| `MAX_EXTERNAL_PER_JOB` | `300` | External URLs checked per scan. |
| `PER_HOST_CONCURRENCY` | `2` | Simultaneous requests to any one external host. |
| `MAX_FINISHED_JOBS` | `30` | Finished scans kept in memory (oldest dropped first), on top of the 24 h expiry. Keeps memory bounded on the 512 MB free tier. |
| `RENDER_GIT_COMMIT` | set by Render | Logged at startup so you can tell which commit is running. |

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

## Sites that block the scanner

Many sites put a firewall or bot protection (Cloudflare, Akamai, Sucuri, DataDome and others)
in front of their pages. These often challenge or refuse requests from datacenter IPs like
Render's, even though the same scan works from a laptop. The app reports this honestly
instead of trying to get around it:

- **External links** that answer 401, 403, 429 or 999 (LinkedIn's "go away" code), or carry a
  Cloudflare `cf-mitigated` header, are listed as **Blocked by site** warnings: "This site
  blocks automated checks, so we can't tell if the link works." They have their own filter
  chip and appear as warnings in the CSV and HTML reports. Real 404, 410 and 5xx responses are
  still errors.
- **If the start page itself is refused**, the scan ends as failed with an explanation, the
  detected protection (when we can tell), and what the site owner can do: allowlist the
  User-Agent token `SiteLinkChecker`. Allowlisting by IP isn't reliable because Render's free
  tier doesn't have a fixed outbound IP.
- Pages on the scanned site that return 403 **after** the start page loaded (e.g. a members
  area) stay normal errors.
- For every 4xx/5xx response we keep a small allowlist of response headers (`server`,
  `cf-ray`, `cf-mitigated`, `x-sucuri-id`, `x-datadome`, `x-akamai-*`, `via`, `retry-after`;
  never bodies or cookies) and derive a `protection_hint` (`cloudflare`, `akamai`, `sucuri`,
  `datadome` or `unknown`). Both appear in the issue details and the CSV.

The crawler identifies itself as `Mozilla/5.0 (compatible; SiteLinkChecker/1.0; +CONTACT_URL)`,
the same convention Googlebot uses, and sends ordinary `Accept`, `Accept-Language` and
`Accept-Encoding` headers. It never pretends to be a browser, solves CAPTCHAs, or retries with
a different identity. robots.txt rules for `User-agent: SiteLinkChecker` are honored.

## Deploying to Render

The repo includes a Blueprint (`render.yaml`): one free Python web service running a single
uvicorn worker, with `/health` as the health check.

1. Push this repo to GitHub.
2. In the Render dashboard choose **New > Blueprint**, connect the repo and pick the `main`
   branch. Render reads `render.yaml` and shows the `fmk-link-checker` service.
3. When asked, set `CONTACT_URL` (a page where site owners can reach you; it goes in the
   crawler's User-Agent). Leave everything else as is and click **Apply**.
4. Wait for the first build and deploy, then run the smoke test (below) and the
   post-deploy checklist.

Every push to `main` redeploys automatically. Python is pinned to 3.12.15 via
`PYTHON_VERSION` in `render.yaml` and `.python-version`.

What the free tier means for this app:

- **It sleeps.** After 15 minutes with no traffic the service spins down; the next visit
  takes about a minute while it wakes (the page shows "Waking up the server").
- **Reports are temporary.** Jobs live in memory, so share links disappear when the service
  sleeps, restarts or redeploys, and after 24 hours. Downloaded CSV/HTML files are permanent.
- **512 MB of RAM.** A 500-page scan of a heavy site peaked around 105 MB in testing, and
  at most 30 finished scans are kept in memory.
- **750 free instance hours per workspace per month.** One always-awake service uses about
  744 of them, so keeping it awake (see UptimeRobot below) leaves almost nothing for other
  free services in the same workspace.

### Smoke test

```sh
pip install httpx   # already installed if you used requirements.txt
python scripts/smoke_test.py https://fmk-link-checker.onrender.com
python scripts/smoke_test.py https://fmk-link-checker.onrender.com --scan-url https://example.com
```

It checks `/health` (allowing 90 s for a cold start), the main page and its security
headers, and that SSRF payloads are rejected with 400. With `--scan-url` it also runs a
10-page scan (no external or image checks) and verifies the CSV, HTML and share-page
responses. It never scans anything unless you pass `--scan-url`, so only use a site you're
allowed to crawl. Each check prints PASS or FAIL; the exit code is non-zero on any failure.

### Post-deploy checklist

- [ ] The smoke test passes (with and without `--scan-url`).
- [ ] Render's logs show `Starting Link Checker (commit ...)` with the commit you pushed,
      `TRUSTED_PROXY_HOPS=1`, and **no** `ALLOW_PRIVATE_HOSTS` warning.
- [ ] **Verify the client IP setting.** Rate limits are per client IP, so if this is wrong
      everyone on the team (or every visitor) shares one rate-limit bucket, and one person's
      scans can lock everyone out.
  1. Restart the service (Manual Deploy > Restart) so the "first 3 requests" logging resets.
  2. Open the site from two different networks, e.g. your laptop on office Wi-Fi and your
     phone on cellular (Wi-Fi off).
  3. In Render's logs, find the `Client IP check: resolved=... peer=... x-forwarded-for=...`
     lines (only the first 3 requests after startup are logged).
  4. Look up each device's public IP (search "what is my IP" on each) and confirm
     `resolved=` matches it for each device, and that the two devices show different IPs.
  5. If `resolved=` shows a Render or Cloudflare address, or the same IP for both devices,
     find the device's real IP in the raw `x-forwarded-for` list, count its position from
     the right (rightmost = 1), set `TRUSTED_PROXY_HOPS` to that number in the dashboard,
     redeploy and check again.
- [ ] `CONTACT_URL` is set (the crawler's User-Agent should end in `; +https://...)`).
- [ ] Optional: set up UptimeRobot (below).

### Keeping it awake with UptimeRobot (optional)

1. Create a free account at uptimerobot.com and add a new **HTTP(s)** monitor.
2. URL: `https://<your-service>.onrender.com/health`, interval **5 minutes**.
3. Optionally add an alert contact so you hear about outages.

`/health` is cheap and exempt from rate limits. A ping every 5 minutes keeps the service from
sleeping, at the cost of using up the workspace's free instance hours (see above). Leave it
off if a one-minute wake-up on the first visit is acceptable.

