"""Authenticated scanning: login flow, session use, failure modes."""
from __future__ import annotations

import pytest

from kavach.auth import AuthError, find_login_form, login
from kavach.demo_server import serve_all
from kavach.scanner import scan


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def test_find_login_form_keeps_hidden_fields(demo):
    vuln_url, _, _ = demo
    from kavach.http import fetch
    page = fetch(vuln_url + "login")
    form = find_login_form(page.text, page.final_url)
    assert form is not None
    assert form["method"] == "post"
    assert form["action"] == vuln_url + "login"
    names = {i["name"] for i in form["inputs"]}
    assert {"username", "password", "csrf"} <= names
    csrf = next(i for i in form["inputs"] if i["name"] == "csrf")
    assert csrf["type"] == "hidden" and csrf["value"] == "demo-csrf-token"


def test_find_login_form_returns_none_without_password():
    html = ('<form action="/search"><input name="q"></form>')
    assert find_login_form(html, "http://example.com/") is None


def test_login_succeeds_and_sets_a_cookie(demo):
    vuln_url, _, _ = demo
    session, resp = login(vuln_url + "login", "demo", "demo123",
                          auth_check="Welcome, demo")
    assert session.cookie_count >= 1
    assert resp.final_url == vuln_url + "dashboard"
    assert "Welcome, demo" in resp.text


def test_login_wrong_password_raises(demo):
    vuln_url, _, _ = demo
    with pytest.raises(AuthError, match="did not succeed"):
        login(vuln_url + "login", "demo", "wrong")


def test_login_bad_auth_check_raises(demo):
    vuln_url, _, _ = demo
    with pytest.raises(AuthError, match="not found"):
        login(vuln_url + "login", "demo", "demo123",
              auth_check="No such text here")


def test_login_no_form_raises(demo):
    vuln_url, _, _ = demo
    with pytest.raises(AuthError, match="no form"):
        login(vuln_url, "demo", "demo123")


def test_authenticated_scan_reaches_the_dashboard(demo):
    vuln_url, _, _ = demo
    session, _ = login(vuln_url + "login", "demo", "demo123")
    result = scan(vuln_url + "dashboard", session=session, max_pages=2)
    assert result.pages == [vuln_url + "dashboard",
                            vuln_url + "dashboard/settings"]
    assert result.grade == "F"
    # the dashboard reflects input and answers a quote with a database
    # error — only visible once logged in
    rules = {f.rule for f in result.findings}
    assert "sqli_error" in rules and "xss_reflected" in rules


def test_unauthenticated_scan_cannot_see_the_dashboard(demo):
    vuln_url, _, _ = demo
    result = scan(vuln_url + "dashboard")
    # the dashboard redirects to /login, so the scan only sees the
    # login page — no dashboard findings at all
    assert result.final_url == vuln_url + "login"
    assert not any("dashboard" in f.page for f in result.findings)


def test_session_cookie_is_sent_on_later_requests(demo):
    vuln_url, _, _ = demo
    session, _ = login(vuln_url + "login", "demo", "demo123")
    assert "session=authenticated" in session.cookie_header(
        vuln_url + "dashboard")
