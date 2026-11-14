"""Scanner tests against the local demo site (vulnerable + hardened).

No internet needed: the demo server runs on 127.0.0.1.
"""
from __future__ import annotations

import pytest

from kavach.demo_server import serve_both
from kavach.report import to_dict, to_json, to_text
from kavach.scanner import grade_of, normalize_url, scan

VULN_RULES = {
    "http_not_https", "missing_hsts", "missing_csp",
    "missing_x_frame_options", "missing_x_content_type_options",
    "missing_referrer_policy", "missing_permissions_policy",
    "server_header", "x_powered_by", "cors_wildcard",
    "cookie_no_httponly", "cookie_no_samesite",
    "git_exposed", "env_exposed", "backup_file_exposed",
    "sqli_error", "xss_reflected", "robots_sensitive",
}


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, stop = serve_both()
    yield vuln_url, secure_url
    stop()


def rules(result) -> set[str]:
    return {f.rule for f in result.findings}


def test_vulnerable_site_fires_every_expected_finding(demo):
    vuln_url, _ = demo
    result = scan(vuln_url)
    assert result.grade == "F"
    assert result.score == 0
    assert VULN_RULES <= rules(result), (
        "missing: " + ", ".join(sorted(VULN_RULES - rules(result))))
    assert result.counts["critical"] == 4  # http + .git x2 + .env
    assert result.counts["high"] == 7
    # every finding carries a fix and an OWASP mapping
    assert all(f.fix and f.owasp for f in result.findings)
    # no finding ever claims the site is secure
    assert not any("secure" in f.message.lower() and
                   "not secure" not in f.message.lower()
                   for f in result.findings)


def test_hardened_site_is_grade_a(demo):
    _, secure_url = demo
    result = scan(secure_url, verify_tls=False)
    assert result.grade == "A"
    assert result.score == 100
    assert result.findings == []


def test_nepali_report(demo):
    vuln_url, _ = demo
    result = scan(vuln_url, lang="ne")
    text = to_text(result)
    assert "साधारण HTTP" in text
    assert "कवच" in result.disclaimer or "Kavach" in result.disclaimer
    assert "पूर्ण रूपमा सुरक्षित" in result.disclaimer


def test_unreachable_site_is_one_critical_finding():
    result = scan("http://127.0.0.1:1/")
    assert result.grade == "F"
    assert result.score == 0
    assert [f.rule for f in result.findings] == ["unreachable"]
    assert result.findings[0].severity == "critical"


def test_bad_url_raises():
    with pytest.raises(ValueError):
        scan("")
    with pytest.raises(ValueError):
        scan("ftp://example.com/")


def test_normalize_adds_https():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com/") == "http://example.com/"


def test_grade_boundaries():
    assert grade_of(100) == "A" and grade_of(90) == "A"
    assert grade_of(89) == "B" and grade_of(80) == "B"
    assert grade_of(79) == "C" and grade_of(70) == "C"
    assert grade_of(69) == "D" and grade_of(60) == "D"
    assert grade_of(59) == "F" and grade_of(0) == "F"


def test_report_formats(demo):
    vuln_url, _ = demo
    result = scan(vuln_url)
    text = to_text(result)
    assert "Grade F" in text and "score 0/100" in text
    data = to_dict(result)
    assert data["grade"] == "F" and len(data["findings"]) >= 18
    assert data["counts"]["critical"] == 4
    import json
    assert json.loads(to_json(result))["url"] == vuln_url
