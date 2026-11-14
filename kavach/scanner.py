"""Scan orchestration: fetch once, run every check, grade A–F.

Grading: start at 100, deduct critical 25, high 15, medium 8, low 3,
info 0. A 90+, B 80+, C 70+, D 60+, F below 60. A good grade only means
the checks run found nothing — the report disclaimer says so.

Scoring dedupes by (rule, evidence): a site-wide problem (a missing
header on every page, one exposed file) counts once, while a per-page
problem (a probe that fires on one page's input) counts per page.
The report still lists every occurrence, with its page.

Crawling (max_pages > 1): the seed page gets the full suite, including
the site-wide checks (TLS, exposed files, robots.txt, security.txt).
Each further page gets the per-page suite (headers, cookies, mixed
content, the three probes). Requests are polite: a short delay between
page fetches, an honest User-Agent, and a hard cap on pages.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from . import checks
from .crawl import extract_links
from .forms import form_submission_urls
from .http import Response, Session, fetch
from .model import DEDUCTIONS, Finding, ScanResult
from .ne import DISCLAIMER_NE

DISCLAIMER_EN = (
    "Kavach checks only the items listed. A good grade does not mean the "
    "site is fully secure — it is the result of the checks run."
)

MAX_REQUESTS_PER_PAGE = 4  # 1 fetch + 3 probes
DEFAULT_MAX_PAGES = 1
MAX_PAGES_LIMIT = 20
DEFAULT_DELAY = 0.2


def grade_of(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings: list[Finding]) -> int:
    """Score from the unique issues: dedupe by (rule, evidence)."""
    seen: set[tuple[str, str]] = set()
    total = 0
    for f in findings:
        key = (f.rule, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        total += DEDUCTIONS[f.severity]
    return max(0, 100 - total)


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("no URL given")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"not a valid http(s) URL: {url}")
    return url


def _tag(findings: list[Finding], page: str) -> list[Finding]:
    for f in findings:
        f.page = page
    return findings


def _page_checks(base: Response, lang: str,
                 verify_tls: bool,
                 session: Session | None = None) -> list[Finding]:
    """The per-page suite, run on one already-fetched response:
    headers, cookies, mixed content, and the three probes."""
    findings: list[Finding] = []
    findings += checks.check_headers(base, lang)
    findings += checks.check_cookies(base, lang)
    findings += checks.check_mixed_content(base, lang)
    findings += checks.check_sqli(base.final_url, lang,
                                  verify_tls=verify_tls, session=session)
    findings += checks.check_xss(base.final_url, lang,
                                 verify_tls=verify_tls, session=session)
    findings += checks.check_open_redirect(base.final_url, lang,
                                           verify_tls=verify_tls,
                                           session=session)
    return findings


def scan(url: str, lang: str = "en", verify_tls: bool = True,
         max_pages: int = DEFAULT_MAX_PAGES,
         delay: float = DEFAULT_DELAY,
         session: Session | None = None) -> ScanResult:
    """Scan one URL (max_pages=1), or crawl up to max_pages same-origin
    pages. Never raises for a bad target — an unreachable site comes
    back as a result with one critical finding. verify_tls=False skips
    certificate verification (test environments only). A Session (from
    kavach.auth.login) scans behind a login; without one the scan is
    unauthenticated."""
    if lang not in ("en", "ne"):
        raise ValueError("lang must be 'en' or 'ne'")
    if max_pages < 1 or max_pages > MAX_PAGES_LIMIT:
        raise ValueError(f"max_pages must be 1–{MAX_PAGES_LIMIT}")
    target = normalize_url(url)
    started = time.monotonic()
    requests = 0
    disclaimer = DISCLAIMER_NE if lang == "ne" else DISCLAIMER_EN

    seed = fetch(target, verify_tls=verify_tls, session=session)
    requests += 1
    if seed.status is None:
        finding = checks._finding(
            "unreachable", "critical", checks.A05, lang,
            "Site unreachable",
            f"The site could not be opened ({seed.error}) — check the "
            "address and the network.",
            "Check that the address is right and the site is up.",
            details={"error": seed.error}, error=seed.error)
        return ScanResult(url=target, final_url=target, findings=[finding],
                          score=0, grade="F", requests_made=requests,
                          duration_s=round(time.monotonic() - started, 2),
                          lang=lang, disclaimer=disclaimer,
                          pages=[target])

    findings: list[Finding] = []
    # site-wide checks, once, on the seed
    findings += _tag(checks.check_transport(target, seed, lang,
                                            verify_tls=verify_tls),
                     seed.final_url)
    findings += _tag(checks.check_sensitive_files(seed.final_url, lang,
                                                  verify_tls=verify_tls,
                                                  session=session),
                     seed.final_url)
    requests += 8
    findings += _tag(checks.check_robots(seed.final_url, lang,
                                         verify_tls=verify_tls,
                                         session=session),
                     seed.final_url)
    requests += 1
    findings += _tag(checks.check_security_txt(seed.final_url, lang,
                                               verify_tls=verify_tls,
                                               session=session),
                     seed.final_url)
    requests += 1

    # per-page checks, breadth-first from the seed
    pages: list[str] = []
    form_pages: list[str] = []
    queue = [seed.final_url]
    queued = {seed.final_url}
    from_forms = set()
    while queue and len(pages) < max_pages:
        page_url = queue.pop(0)
        if page_url == seed.final_url:
            base = seed
            page_findings = _page_checks(base, lang, verify_tls,
                                         session=session)
            requests += 3  # the three probes (the fetch is counted above)
        else:
            if delay:
                time.sleep(delay)
            base = fetch(page_url, verify_tls=verify_tls,
                         session=session)
            requests += MAX_REQUESTS_PER_PAGE
            if base.status is None:
                continue
            page_findings = _page_checks(base, lang, verify_tls,
                                         session=session)
        pages.append(page_url)
        if page_url in from_forms:
            form_pages.append(page_url)
        findings += _tag(page_findings, page_url)
        if max_pages > 1 and len(pages) < max_pages:
            candidates = extract_links(base.text, page_url)
            # GET forms too: a search box can lead somewhere no link
            # points to, so its submission is a crawl candidate as well
            form_urls = form_submission_urls(base.text, page_url)
            for url in form_urls:
                from_forms.add(url)
            candidates = candidates + form_urls
            for link in candidates:
                if link not in queued \
                        and len(pages) + len(queue) < max_pages:
                    queued.add(link)
                    queue.append(link)

    score = score_findings(findings)
    return ScanResult(url=target, final_url=seed.final_url,
                      findings=findings, score=score,
                      grade=grade_of(score), requests_made=requests,
                      duration_s=round(time.monotonic() - started, 2),
                      lang=lang, disclaimer=disclaimer,
                      pages=pages, form_pages=form_pages)
