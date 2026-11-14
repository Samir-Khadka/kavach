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
crawls it again with form submission (4 pages — the search-results page
is only reachable by submitting the search form), scans its
authenticated dashboard (demo/demo123, 2 pages), and repeats the
single-page scan in Nepali. The demo server is local only — never point
it at the public internet.

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

## Scan history

Every scan is remembered in `~/.kavach/history` (one file per URL),
and the next scan of the same URL reports what changed: new findings,
fixed findings, and the grade and score change. That is the point of
re-scanning — you fix a header, run Kavach again, and see the finding
disappear from the list. `--no-history` skips it; `--history-dir`
points it somewhere else. The diff is in the text, JSON and HTML
reports alike.

## Fix priority

A list of findings does not say what to do first. Every report ends
with a ranked fix list: each rule is one fix action, ordered by the
score it gains when fixed everywhere, with the fix itself and the
score and grade you land on after fixing everything up to that rank.
A missing header on five pages is one fix; a probe that fires on
three pages is three. On Samir's portfolio the top three — HSTS, the
CORS wildcard, CSP — lift it from F 49 to B 80.

## Verify a fix

The loop is prioritise → fix → verify. After fixing a finding, run:

```bash
python -m kavach verify https://example.com --rule missing_hsts
```

and get a plain answer: `FIXED`, or `STILL PRESENT` with the pages
it is still on. `--page URL` restricts the check to one page (the
finding may be fixed there and present elsewhere); `--max-pages N`
crawls. Exit 0 = fixed, 1 = still present, 2 = scan failed,
3 = usage error (no `--rule`, or a rule name Kavach cannot produce —
a typo is rejected up front instead of scanning for something that
can never appear). `--json` prints the result as JSON.

## Scheduled report email

A scan on a schedule is only useful if someone reads it. `--email`
sends the report when it matters — by default only when the grade or
score fell since the last scan of that URL:

```bash
python -m kavach https://example.com --max-pages 5 --email
```

`--notify-on change` also emails on any difference (new or fixed
findings); `--notify-on always` emails every run. The email is the
full report — findings, fix priorities, and the diff — as plain text
with an HTML version alongside.

SMTP settings come from the environment only, so a password never
lands in a shell history or a log:

```bash
export KAVACH_SMTP_HOST=smtp.gmail.com   # port 587 by default, 465 = TLS
export KAVACH_SMTP_USER=you@gmail.com
export KAVACH_SMTP_PASS=xxxx xxxx xxxx xxxx   # a Gmail app password,
                                               # not the account password
export KAVACH_NOTIFY_TO=you@example.com
```

For Gmail: Google account → Security → 2-Step Verification →
App passwords → generate one for "Mail". The weekly GitHub Action
already has an email step that runs when the same values are set as
repo secrets (`KAVACH_SMTP_HOST`, `KAVACH_SMTP_PORT`,
`KAVACH_SMTP_USER`, `KAVACH_SMTP_PASS`, `KAVACH_NOTIFY_TO`), and it
keeps the scan history between runs with the Actions cache so the
drop detection works. A failed send is reported on stderr and never
changes the scan's exit code.

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

The crawl is form-aware: a page's GET forms (search boxes, filters,
category selectors) are submitted with safe test values, so results
pages no link points to are scanned too — the report marks those pages
"(via form)". POST forms are never submitted: they can change state.
Hidden fields (CSRF tokens) are kept, dropdowns use their first
option, and at most two forms per page are tried.

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
