"""Form-aware crawling: submit a page's GET forms with safe test
values, so the crawl reaches results pages no link points to.

Only GET forms are ever submitted — a POST form can change state
(create, delete, send), so it is never touched. The values are inert
("test", "1") and the form's own hidden fields are kept, so a search
box, a filter or a category selector is exercised the way a visitor
would use it, without doing anything destructive.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

MAX_FORMS_PER_PAGE = 2

# test values per input type — inert, but shaped so a form that
# validates its fields still accepts them
TEST_VALUES = {
    "email": "test@example.com",
    "number": "1",
    "date": "2026-01-01",
    "tel": "1234567890",
    "url": "https://example.com",
    "time": "12:00",
}
DEFAULT_TEST_VALUE = "test"

SKIP_TYPES = ("submit", "button", "reset", "file", "image", "password")


class _FormParser(HTMLParser):
    """Collects every <form> on a page: action, method, inputs,
    selects (with their options) and textareas."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None
        self._select: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_d = dict(attrs)
        if tag == "form":
            self._current = {"action": attrs_d.get("action", ""),
                             "method": (attrs_d.get("method", "get")
                                        .lower()),
                             "inputs": [], "selects": []}
            self.forms.append(self._current)
            self._select = None
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({
                "name": attrs_d.get("name", ""),
                "type": (attrs_d.get("type", "text").lower()),
                "value": attrs_d.get("value", ""),
            })
        elif tag == "textarea" and self._current is not None:
            self._current["inputs"].append({
                "name": attrs_d.get("name", ""),
                "type": "textarea", "value": "",
            })
        elif tag == "select" and self._current is not None:
            self._select = {"name": attrs_d.get("name", ""),
                            "options": []}
            self._current["selects"].append(self._select)
        elif tag == "option" and self._select is not None:
            self._select["options"].append(attrs_d.get("value", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None
            self._select = None
        elif tag == "select":
            self._select = None


def _fill(form: dict) -> dict:
    """A GET form's submission payload: hidden fields keep their
    values, everything else gets a safe test value."""
    payload: dict[str, str] = {}
    for i in form["inputs"]:
        name, kind = i["name"], i["type"]
        if not name or kind in SKIP_TYPES:
            continue
        if kind == "hidden":
            payload[name] = i["value"]
        elif kind in ("checkbox", "radio"):
            if name not in payload and i["value"]:
                payload[name] = i["value"]
        else:
            payload[name] = TEST_VALUES.get(kind, DEFAULT_TEST_VALUE)
    for s in form["selects"]:
        if not s["name"]:
            continue
        options = [o for o in s["options"] if o]
        if options:
            payload[s["name"]] = options[0]
    return payload


def form_submission_urls(html: str, base_url: str,
                         max_forms: int = MAX_FORMS_PER_PAGE) -> list[str]:
    """The URLs a visitor would reach by submitting this page's GET
    forms with test values, in first-seen order. POST forms are never
    returned. Same-origin only, fragments stripped."""
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    base = urlsplit(base_url)
    origin = (base.scheme, base.netloc)
    out: list[str] = []
    seen: set[str] = set()
    for form in parser.forms[:max_forms]:
        if form["method"] != "get":
            continue
        payload = _fill(form)
        if not payload:
            continue
        action = urljoin(base_url, form["action"] or base_url)
        parts = urlsplit(action)
        if (parts.scheme, parts.netloc) != origin:
            continue
        if parts.scheme not in ("http", "https"):
            continue
        query = urlencode(payload)
        if parts.query:
            query = parts.query + "&" + query
        url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                          query, ""))
        if url in seen or url == base_url:
            continue
        seen.add(url)
        out.append(url)
    return out
