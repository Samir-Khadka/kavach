"""Form-aware crawling: GET forms are submitted, POST forms are not."""
from __future__ import annotations

import pytest

from kavach.demo_server import serve_all
from kavach.forms import form_submission_urls
from kavach.scanner import scan


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def test_get_form_becomes_a_submission_url():
    html = ('<form method="get" action="/search">'
            '<input name="q"><input type="submit" value="Go"></form>')
    assert form_submission_urls(html, "http://example.com/") == \
        ["http://example.com/search?q=test"]


def test_post_form_is_never_submitted():
    html = ('<form method="post" action="/delete">'
            '<input name="id" value="1"></form>')
    assert form_submission_urls(html, "http://example.com/") == []


def test_hidden_fields_are_kept_and_selects_use_first_option():
    html = ('<form method="get" action="/filter">'
            '<input type="hidden" name="csrf" value="abc">'
            '<select name="cat"><option value="">All</option>'
            '<option value="books">Books</option></select>'
            '<input type="checkbox" name="sale" value="1">'
            '<input name="q"></form>')
    urls = form_submission_urls(html, "http://example.com/")
    assert len(urls) == 1
    assert "csrf=abc" in urls[0]
    assert "cat=books" in urls[0]
    assert "sale=1" in urls[0]
    assert "q=test" in urls[0]


def test_form_without_method_defaults_to_get():
    html = ('<form action="/search"><input name="q"></form>')
    assert form_submission_urls(html, "http://example.com/") == \
        ["http://example.com/search?q=test"]


def test_external_form_action_is_skipped():
    html = ('<form method="get" action="https://other.example.com/x">'
            '<input name="q"></form>')
    assert form_submission_urls(html, "http://example.com/") == []


def test_crawl_reaches_the_form_only_search_page(demo):
    vuln_url, _, _ = demo
    # /search has no link pointing at it — only the home page's
    # search form reaches it
    result = scan(vuln_url, max_pages=4)
    assert len(result.pages) == 4
    search = [p for p in result.pages if "/search" in p]
    assert len(search) == 1
    assert result.form_pages == search
    # and the search page is genuinely vulnerable (reflects + SQL error)
    rules = {f.rule for f in result.findings
             if f.page == search[0]}
    assert "sqli_error" in rules and "xss_reflected" in rules


def test_crawl_without_enough_pages_never_reaches_the_form(demo):
    vuln_url, _, _ = demo
    result = scan(vuln_url, max_pages=3)
    assert result.form_pages == []
    assert not any("/search" in p for p in result.pages)


def test_secure_site_stays_grade_a_through_forms(demo):
    _, secure_url, _ = demo
    result = scan(secure_url, verify_tls=False, max_pages=3)
    assert result.grade == "A"
    assert result.score == 100
    assert result.findings == []
    assert len(result.form_pages) == 1  # /secure/search?q=test
