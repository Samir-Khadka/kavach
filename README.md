# Kavach — कवच ("shield")

A web security scanner that grades a site **A–F** against the OWASP Top 10
basics, with fix guidance in **English and Nepali**. Pure Python standard
library — no dependencies for the scanner itself.

> **Only scan sites you own or have explicit permission to test.**
> Kavach makes read-only GET requests (about 10 per scan, 5s timeout each)
> with an honest User-Agent, and its two probes are non-destructive: a
> single quote (SQL-error detection) and one inert marker tag `<kavach>`
> (reflection detection). Nothing it sends can modify a site.

## What it checks

| Area | Checks |
| --- | --- |
| Transport | plain HTTP, HTTPS→HTTP downgrade, TLS version (< 1.2), certificate validity (a failed handshake is reported as an unverified check, never as a bad certificate) |
| Headers | HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Disclosure | `Server` and `X-Powered-By` headers |
| Cookies | missing `Secure`, `HttpOnly`, `SameSite` flags |
| CORS | `Access-Control-Allow-Origin: *` (worse with credentials) |
| Exposed files | `/.git/HEAD`, `/.git/config`, `/.env`, `backup.zip`, `db.sql`, `config.php.bak`, `.DS_Store`, `wp-config.php` |
| Probes | error-based SQL injection, reflected XSS, open redirect |
| Content | mixed content (HTTP subresources on an HTTPS page) |
| Info | `robots.txt` listing sensitive paths, missing `security.txt` (RFC 9116) |

Grading: start at 100, deduct critical 25, high 15, medium 8, low 3.
A 90+, B 80+, C 70+, D 60+, F below 60. A good grade only means the checks
run found nothing — the report says so on every run.

## Use it

```bash
# CLI (no install needed)
python -m kavach https://example.com
python -m kavach https://example.com --lang ne --json --output report.json
python -m kavach https://example.com --html report.html --badge grade.svg
python -m kavach https://example.com --max-pages 5   # crawl up to 5 pages
python -m kavach https://example.com/dashboard \
  --auth-url https://example.com/login --auth-user demo \
  --auth-pass demo123 --auth-check "Welcome"   # scan behind a login

# exit codes: 0 = A/B, 1 = C/D, 2 = F, 3 = bad URL / scan failed / login failed
# --insecure skips TLS certificate verification (test environments only)

# API (needs fastapi + uvicorn)
pip install .[api]
uvicorn kavach.api:app --port 8000
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
  -d '{"url": "https://example.com", "lang": "en"}'
```

## Demo

`python demo.py` scans three local sites: a deliberately vulnerable one
(grade F, 25 findings), the same site hardened (grade A, no findings),
and a mixed one — HTTPS and hardened except for mixed content and an
open redirect (grade C) — then crawls the vulnerable site (3 pages),
scans its authenticated dashboard (demo/demo123, 2 pages), and repeats
the single-page scan in Nepali. The demo server is local only — never
point it at the public internet.

## Authenticated scanning

Most real apps hide their interesting pages behind a login. With
`--auth-url` Kavach logs in through the site's own form — it finds the
form with the password field, keeps its hidden fields (CSRF tokens),
fills in the username and password, and scans with the session cookies
it gets back. `--auth-check` is a string that must appear after login
(a dashboard heading, a "Welcome" line) and proves the login worked.
When the login does not visibly succeed, Kavach stops with an error
instead of scanning unauthenticated and reporting a false grade.
Field names are auto-detected (username/email/login, password) or set
explicitly with `--auth-user-field` / `--auth-pass-field`. Put the
password in `KAVACH_AUTH_PASS` so it never lands in shell history.
The API takes the same credentials in an `auth` object on `POST /scan`.

## Crawling

By default Kavach scans one page. With `--max-pages N` it follows
same-origin links breadth-first, up to N pages (max 20), and runs the
per-page checks on each: headers, cookies, mixed content, and the three
probes. Site-wide checks (TLS, exposed files, robots.txt, security.txt)
run once. The score counts each distinct issue once — a missing header
on five pages is one problem, a probe that fires on two pages is two —
but the report lists every occurrence with its page, so you know
exactly where each finding lives. A short delay between pages keeps
the crawl polite.

## Why this exists

Built as a portfolio project for a cybersecurity master's application
([CYBERSURE](https://www.cybersure-master.eu/), Erasmus Mundus) — a
scanner that runs on the author's own sites and finds real things to
fix. The GitHub Action in `.github/workflows/scan.yml` scans
<https://samir-khadka.com.np> on every push and every Monday and keeps
the report as an artifact (non-blocking: it reports, it does not fail
the build).

## Tests

```bash
pip install pytest fastapi httpx
python -m pytest tests/ -q
```

Tests run against the local demo server — no internet needed.

## License

MIT. Author: Samir Khadka — <samirshirjan890@gmail.com>
