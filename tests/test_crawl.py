"""Crawl tests: link extraction, multi-page scanning, score dedupe."""
from __future__ import annotations

import pytest

from kavach.crawl import extract_links
from kavach.demo_server import serve_all
from kavach.model import Finding
from kavach.scanner import score_findings
from kavach.scanner import scan as scan_fn

BASE = "http://127.0.0.1:8080/"


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def test_extract_links_same_origin_only():
    html = """
    <a href="/about">About</a>
    <a href="login">Login</a>
    <a href="https://other.example.com/">External</a>
    <a href="mailto:me@example.com">Mail</a>
    <a href="/logo.png">Logo</a>
    <a href="/style.css">CSS</a>
    <a href="/about#team">Anchor</a>
    <a href="/about">About again</a>
    <a href="javascript:void(0)">JS</a>
    """
    links = extract_links(html, BASE)
    assert links == ["http://127.0.0.1:8080/about",
                     "http://127.0.0.1:8080/login"]


def test_extract_links_handles_broken_html():
    assert extract_links("<a href=/about><a href=", BASE) == \
        ["http://127.0.0.1:8080/about"]


def _finding(rule, severity, evidence=""):
    return Finding(rule=rule, severity=severity, title="", message="",
                   fix="", evidence=evidence)


def test_score_dedupes_site_wide_findings():
    # a missing header on two pages is one issue, not two
    findings = [_finding("missing_csp", "medium", ""),
                _finding("missing_csp", "medium", "")]
    assert score_findings(findings) == 92


def test_score_counts_per_page_probes_separately():
    # a probe that fires on two different pages is two issues
    findings = [_finding("sqli_error", "high", "http://a/?id=1'"),
                _finding("sqli_error", "high", "http://b/?id=1'"),
                _finding("missing_csp", "medium", "")]
    assert score_findings(findings) == 100 - 15 - 15 - 8


def test_score_floor_is_zero():
    findings = [_finding("git_exposed", "critical", f"/.git/{i}")
                for i in range(10)]
    assert score_findings(findings) == 0


def test_crawl_scans_linked_pages(demo):
    vuln_url, _, _ = demo
    result = scan_fn(vuln_url, max_pages=3)
    assert len(result.pages) == 3
    assert result.pages[0] == vuln_url
    assert any(p.endswith("/about") for p in result.pages)
    assert any(p.endswith("/login") for p in result.pages)
    assert result.grade == "F"
    # more findings than the single-page scan
    assert len(result.findings) > 25


def test_crawl_shows_page_specific_differences(demo):
    vuln_url, _, _ = demo
    result = scan_fn(vuln_url, max_pages=3)
    xfo_pages = [f.page for f in result.findings
                 if f.rule == "missing_x_frame_options"]
    # /about sends X-Frame-Options, the seed and /login do not
    assert len(xfo_pages) == 2
    assert not any(p.endswith("/about") for p in xfo_pages)
    assert any(p.endswith("/login") for p in xfo_pages)


def test_sqli_probe_ignores_a_page_that_mentions_mysql(demo):
    """The /about page says 'Built with Python, MySQL and SQLite' —
    a mention of a database is not a database error. Only the pages
    that return a real SQL error message fire sqli_error."""
    vuln_url, _, _ = demo
    result = scan_fn(vuln_url, max_pages=3)
    sqli_pages = [f.page for f in result.findings
                  if f.rule == "sqli_error"]
    assert not any(p.endswith("/about") for p in sqli_pages)
    assert any(p == vuln_url for p in sqli_pages)
    assert any(p.endswith("/login") for p in sqli_pages)


def test_crawl_respects_max_pages(demo):
    vuln_url, _, _ = demo
    result = scan_fn(vuln_url, max_pages=1)
    assert len(result.pages) == 1
    assert result.pages[0] == vuln_url


def test_crawl_hardened_site_stays_grade_a(demo):
    _, secure_url, _ = demo
    result = scan_fn(secure_url, verify_tls=False, max_pages=3)
    assert result.grade == "A"
    assert result.score == 100
    assert result.findings == []
    assert any(p.endswith("/secure/about") for p in result.pages)


def test_max_pages_limit():
    import pytest
    with pytest.raises(ValueError):
        scan_fn("http://example.com/", max_pages=0)
    with pytest.raises(ValueError):
        scan_fn("http://example.com/", max_pages=21)
