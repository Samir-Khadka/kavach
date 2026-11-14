"""Fix prioritisation: ranked by gain, deduped, cumulative grade."""
from __future__ import annotations

import pytest

from kavach.demo_server import serve_all
from kavach.model import Finding
from kavach.priorities import prioritise, raw_score
from kavach.scanner import scan


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def _finding(rule, severity, evidence="", page="", fix="fix it"):
    return Finding(rule=rule, severity=severity, title=rule,
                   message="", fix=fix, evidence=evidence, page=page)


def test_ranked_by_gain_descending():
    findings = [
        _finding("missing_csp", "medium"),
        _finding("git_exposed", "critical", evidence=".git/HEAD"),
        _finding("git_exposed", "critical", evidence=".git/config"),
        _finding("sqli_error", "high", evidence="http://a/?id=1'"),
    ]
    priorities, total, raw = prioritise(findings)
    assert [p.rule for p in priorities] == [
        "git_exposed", "sqli_error", "missing_csp"]
    assert priorities[0].gain == 50  # two exposed files
    assert priorities[1].gain == 15
    assert priorities[2].gain == 8
    assert total == 73
    assert raw == 100 - 73
    # cumulative: fixing git alone lands at 100-73+50 = 77 (C)
    assert priorities[0].cumulative_score == 77
    assert priorities[0].cumulative_grade == "C"
    assert priorities[-1].cumulative_score == 100
    assert priorities[-1].cumulative_grade == "A"


def test_site_wide_issue_counts_once_even_on_many_pages():
    findings = [_finding("missing_csp", "medium", page=f"http://a/p{i}")
                for i in range(5)]
    priorities, total, _ = prioritise(findings)
    assert len(priorities) == 1
    assert priorities[0].gain == 8  # one fix, not five
    assert len(priorities[0].pages) == 5


def test_per_page_probe_counts_per_page():
    findings = [_finding("sqli_error", "high",
                         evidence=f"http://a/p{i}?id=1'",
                         page=f"http://a/p{i}") for i in range(3)]
    priorities, total, _ = prioritise(findings)
    assert priorities[0].gain == 45  # three separate fixes
    assert len(priorities[0].pages) == 3


def test_empty_findings_give_no_priorities():
    priorities, total, raw = prioritise([])
    assert priorities == [] and total == 0 and raw == 100


def test_vulnerable_site_top_priority_is_the_git_exposure(demo):
    vuln_url, _, _ = demo
    result = scan(vuln_url)
    assert result.priorities
    top = result.priorities[0]
    assert top.rule == "git_exposed"
    assert top.gain == 50
    # fixing everything ends at A/100
    assert result.priorities[-1].cumulative_score == 100
    assert result.priorities[-1].cumulative_grade == "A"
    # the score is floored at 0, so early cumulative scores stay 0 —
    # the raw score is negative and the fix does not pretend otherwise
    assert top.cumulative_score == 0


def test_portfolio_priorities_are_actionable():
    """On the real portfolio (F 49), the top fixes are the headers —
    and fixing the top three lifts it to a C."""
    result = scan("https://samir-khadka.com.np")
    assert result.grade == "F" and result.score == 49
    top = result.priorities[0]
    assert top.gain == 15  # the highest single gain is a high finding
    # fixing the top three (15+8+8) lifts 49 to 80 (B)
    third = result.priorities[2]
    assert third.cumulative_score == 80
    assert third.cumulative_grade == "B"
