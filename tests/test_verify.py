"""Fix verification: re-scan and confirm one finding is gone."""
from __future__ import annotations

import pytest

from kavach.cli import main as cli_main
from kavach.demo_server import serve_all
from kavach.verify import verify


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def test_verify_rule_present_on_vulnerable_site(demo):
    vuln_url, _, _ = demo
    result = verify(vuln_url, "missing_hsts")
    assert not result.fixed
    assert len(result.occurrences) == 1
    assert result.pages == [vuln_url]
    assert result.scan.grade == "F"


def test_verify_rule_absent_on_hardened_site(demo):
    _, secure_url, _ = demo
    result = verify(secure_url, "missing_hsts", verify_tls=False)
    assert result.fixed
    assert result.occurrences == []
    assert result.scan.grade == "A"


def test_verify_page_specific(demo):
    vuln_url, _, _ = demo
    # /about sends X-Frame-Options, so missing_x_frame_options is
    # fixed THERE — but it is still present on the home page
    about = vuln_url + "about"
    assert verify(vuln_url, "missing_x_frame_options",
                  page=about, max_pages=3).fixed
    assert not verify(vuln_url, "missing_x_frame_options",
                      page=vuln_url, max_pages=3).fixed


def test_verify_unknown_rule_raises(demo):
    vuln_url, _, _ = demo
    with pytest.raises(ValueError, match="unknown rule"):
        verify(vuln_url, "not_a_rule")


def test_verify_crawl_finds_rule_on_a_later_page(demo):
    vuln_url, _, _ = demo
    # sqli_error is on the home page and /login, but not on /about
    # (which never reflects input) — a crawl still finds it
    result = verify(vuln_url, "sqli_error", max_pages=3)
    assert not result.fixed
    assert len(result.pages) == 2


def test_cli_verify_fixed_exits_0(demo, capsys):
    _, secure_url, _ = demo
    assert cli_main(["verify", secure_url, "--rule", "missing_hsts",
                     "--insecure", "--no-history"]) == 0
    assert "FIXED" in capsys.readouterr().out


def test_cli_verify_still_present_exits_1(demo, capsys):
    vuln_url, _, _ = demo
    assert cli_main(["verify", vuln_url, "--rule", "missing_hsts",
                     "--no-history"]) == 1
    assert "STILL PRESENT" in capsys.readouterr().out


def test_cli_verify_unknown_rule_exits_3(demo):
    vuln_url, _, _ = demo
    assert cli_main(["verify", vuln_url, "--rule", "not_a_rule",
                     "--no-history"]) == 3


def test_cli_verify_json(demo, capsys):
    vuln_url, _, _ = demo
    assert cli_main(["verify", vuln_url, "--rule", "missing_hsts",
                     "--json", "--no-history"]) == 1
    data = __import__("json").loads(capsys.readouterr().out)
    assert data["rule"] == "missing_hsts" and data["fixed"] is False
    assert data["grade"] == "F"


def test_cli_scan_still_works_without_subcommand(demo, capsys):
    vuln_url, _, _ = demo
    assert cli_main([vuln_url, "--no-history"]) == 2
    assert "Grade F" in capsys.readouterr().out
