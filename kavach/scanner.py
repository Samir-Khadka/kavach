"""Scan orchestration: fetch once, run every check, grade A–F.

Grading: start at 100, deduct critical 25, high 15, medium 8, low 3,
info 0. A 90+, B 80+, C 70+, D 60+, F below 60. A good grade only means
the checks run found nothing — the report disclaimer says so.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from . import checks
from .http import Response, fetch
from .model import DEDUCTIONS, Finding, ScanResult
from .ne import DISCLAIMER_NE

DISCLAIMER_EN = (
    "Kavach checks only the items listed. A good grade does not mean the "
    "site is fully secure — it is the result of the checks run."
)

MAX_REQUESTS = 12


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


def scan(url: str, lang: str = "en", verify_tls: bool = True) -> ScanResult:
    """Scan one URL. Never raises for a bad target — an unreachable site
    comes back as a result with one critical finding. verify_tls=False
    skips certificate verification (test environments only)."""
    if lang not in ("en", "ne"):
        raise ValueError("lang must be 'en' or 'ne'")
    target = normalize_url(url)
    started = time.monotonic()
    requests = 0

    base = fetch(target, verify_tls=verify_tls)
    requests += 1
    if base.status is None:
        finding = checks._finding(
            "unreachable", "critical", checks.A05, lang,
            "Site unreachable",
            f"The site could not be opened ({base.error}) — check the "
            "address and the network.",
            "Check that the address is right and the site is up.",
            details={"error": base.error}, error=base.error)
        return ScanResult(url=target, final_url=target, findings=[finding],
                          score=0, grade="F", requests_made=requests,
                          duration_s=round(time.monotonic() - started, 2),
                          lang=lang,
                          disclaimer=DISCLAIMER_NE if lang == "ne"
                          else DISCLAIMER_EN)

    findings: list[Finding] = []
    findings += checks.check_transport(target, base, lang,
                                       verify_tls=verify_tls)
    findings += checks.check_headers(base, lang)
    findings += checks.check_cookies(base, lang)
    findings += checks.check_sensitive_files(base.final_url, lang,
                                             verify_tls=verify_tls)
    requests += 6
    findings += checks.check_sqli(base.final_url, lang,
                                  verify_tls=verify_tls)
    requests += 1
    findings += checks.check_xss(base.final_url, lang,
                                 verify_tls=verify_tls)
    requests += 1
    findings += checks.check_robots(base.final_url, lang,
                                    verify_tls=verify_tls)
    requests += 1

    score = max(0, 100 - sum(DEDUCTIONS[f.severity] for f in findings))
    return ScanResult(url=target, final_url=base.final_url,
                      findings=findings, score=score,
                      grade=grade_of(score), requests_made=requests,
                      duration_s=round(time.monotonic() - started, 2),
                      lang=lang,
                      disclaimer=DISCLAIMER_NE if lang == "ne"
                      else DISCLAIMER_EN)
