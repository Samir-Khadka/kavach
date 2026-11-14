"""Scan history: save, load, and diff against the previous scan."""
from __future__ import annotations

import pytest

from kavach.demo_server import serve_all
from kavach.history import (diff_results, history_path, load_previous,
                            save_scan)
from kavach.model import Finding, ScanResult
from kavach.scanner import scan


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def _result(grade="F", score=0, findings=None):
    return ScanResult(url="http://example.com/", final_url="http://example.com/",
                      findings=findings or [], score=score, grade=grade,
                      requests_made=1, duration_s=0.1)


def _finding(rule, severity="high", evidence="", page=""):
    return Finding(rule=rule, severity=severity, title=rule,
                   message="", fix="", evidence=evidence, page=page)


def test_diff_finds_new_and_fixed_findings():
    prev = {"grade": "F", "score": 0, "scanned_at": "2026-11-14T00:00:00Z",
            "findings": [
                {"rule": "missing_hsts", "severity": "high",
                 "title": "Missing HSTS", "message": "", "fix": "",
                 "evidence": "", "page": ""},
                {"rule": "sqli_error", "severity": "high",
                 "title": "SQLi", "message": "", "fix": "",
                 "evidence": "http://a/?id=1'", "page": ""},
            ]}
    curr = _result(grade="D", score=60, findings=[
        _finding("missing_hsts"),
        _finding("xss_reflected", evidence="http://a/?id=<kavach>"),
    ])
    d = diff_results(prev, curr)
    assert d.previous_grade == "F" and d.previous_score == 0
    assert d.score_change == 60
    assert d.grade_change == "F → D"
    assert [f.rule for f in d.new_findings] == ["xss_reflected"]
    assert [f.rule for f in d.fixed_findings] == ["sqli_error"]
    assert d.has_changes


def test_diff_same_scan_has_no_changes():
    prev = {"grade": "A", "score": 100, "scanned_at": "2026-11-14T00:00:00Z",
            "findings": []}
    d = diff_results(prev, _result(grade="A", score=100))
    assert not d.has_changes
    assert d.grade_change == "" and d.score_change == 0


def test_history_path_is_stable_and_safe():
    p1 = history_path("/tmp/h", "https://samir-khadka.com.np")
    p2 = history_path("/tmp/h", "https://samir-khadka.com.np")
    assert p1 == p2
    assert p1.name.startswith("samir-khadka.com.np-")
    assert p1.suffix == ".json"
    p3 = history_path("/tmp/h", "https://samir-khadka.com.np/projects.html")
    assert p3 != p1  # different URL, different file


def test_history_round_trip_first_scan_has_no_diff(demo, tmp_path):
    vuln_url, _, _ = demo
    result = scan(vuln_url, history_dir=str(tmp_path))
    assert result.diff is None
    assert load_previous(str(tmp_path), vuln_url) is not None
    # a second identical scan diffs to no changes
    again = scan(vuln_url, history_dir=str(tmp_path))
    assert again.diff is not None
    assert not again.diff.has_changes
    assert again.diff.previous_grade == "F"


def test_history_diff_shows_new_findings_on_a_bigger_crawl(demo, tmp_path):
    vuln_url, _, _ = demo
    scan(vuln_url, max_pages=1, history_dir=str(tmp_path))
    bigger = scan(vuln_url, max_pages=3, history_dir=str(tmp_path))
    assert bigger.diff is not None
    assert bigger.diff.has_changes
    # the crawl found findings on /about and /login that the
    # single-page scan never saw
    new_rules = {f.rule for f in bigger.diff.new_findings}
    assert "sqli_error" in new_rules
    assert any("/login" in f.page for f in bigger.diff.new_findings)
    assert bigger.diff.fixed_findings == []
    assert bigger.diff.score_change == 0  # score was already 0 (floor)
