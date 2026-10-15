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

### API

```sh
# Start a crawl (scheme defaults to https://, max_pages is clamped to 1..500)
curl -X POST localhost:8000/api/jobs -H 'content-type: application/json' \
  -d '{"url": "example.com", "max_pages": 100, "check_external": true, "check_images": false}'

# Poll for progress; pass next_since back as ?since= to get only new issues
curl 'localhost:8000/api/jobs/<id>?since=0'

# Cancel a queued or running crawl (partial results are kept)
curl -X POST localhost:8000/api/jobs/<id>/cancel

curl localhost:8000/health
```

Errors always come back as `{"error": "message"}`.

### CLI

```sh
python cli.py https://example.com --max-pages 100 [--check-images] [--no-external] [--json report.json]
```

### Tests

```sh
pytest
```
