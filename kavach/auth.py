"""Authenticated scanning: log in through a site's own form, then scan
with the session.

The login flow is deliberately boring: fetch the login page, find the
form with a password field, keep its hidden fields (CSRF tokens),
fill in the username and password, submit it, and keep the cookies
the site sets. Nothing is guessed — if there is no password form, or
the login does not visibly succeed, login() raises AuthError instead
of letting the scan run unauthenticated and report a false grade.

Credentials belong to the user: pass them on the command line, or put
the password in KAVACH_AUTH_PASS so it never lands in shell history.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin

from .http import Response, Session, fetch

LOGIN_USER_HINTS = ("user", "email", "login", "name", "account")


class AuthError(Exception):
    """The login did not succeed, or no login form could be found."""


class _FormParser(HTMLParser):
    """Collects every <form> on a page: action, method, inputs."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_d = dict(attrs)
        if tag == "form":
            self._current = {"action": attrs_d.get("action", ""),
                             "method": (attrs_d.get("method", "get")
                                        .lower()),
                             "inputs": []}
            self.forms.append(self._current)
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

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def find_login_form(html: str, base_url: str) -> dict | None:
    """The first form on the page with a password field, with its
    action resolved to an absolute URL. None when there is no such
    form."""
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        return None
    for form in parser.forms:
        if any(i["type"] == "password" and i["name"]
               for i in form["inputs"]):
            form = dict(form)
            form["action"] = urljoin(base_url, form["action"] or base_url)
            return form
    return None


def _pick_field(form: dict, wanted: str | None, kind: str) -> str:
    """The input name to fill for the username or the password."""
    if wanted:
        if any(i["name"] == wanted for i in form["inputs"]):
            return wanted
        raise AuthError(f"no input named {wanted!r} in the login form")
    if kind == "password":
        for i in form["inputs"]:
            if i["type"] == "password" and i["name"]:
                return i["name"]
        raise AuthError("the login form has no password field")
    for i in form["inputs"]:
        if i["type"] in ("text", "email") and i["name"] and \
                any(h in i["name"].lower() for h in LOGIN_USER_HINTS):
            return i["name"]
    for i in form["inputs"]:
        if i["type"] in ("text", "email") and i["name"]:
            return i["name"]
    raise AuthError("the login form has no username field")


def login(auth_url: str, username: str, password: str,
          user_field: str | None = None,
          password_field: str | None = None,
          auth_check: str | None = None,
          verify_tls: bool = True) -> tuple[Session, Response]:
    """Log in and return (session, post-login response). Raises
    AuthError when the login page cannot be fetched, no login form is
    found, or the login does not visibly succeed. auth_check is a
    string that must appear on the page after login (a dashboard
    heading, a 'Welcome' line) — when given, it is the success test;
    otherwise success is a redirect away from the login page or a
    cookie the site set."""
    session = Session(verify_tls=verify_tls)
    page = fetch(auth_url, verify_tls=verify_tls, session=session)
    if page.status is None:
        raise AuthError(f"could not open the login page ({page.error})")
    form = find_login_form(page.text, page.final_url)
    if form is None:
        raise AuthError("no form with a password field on the login page")
    user_name = _pick_field(form, user_field, "username")
    pass_name = _pick_field(form, password_field, "password")
    payload = {}
    for i in form["inputs"]:
        if i["name"] and i["type"] == "hidden":
            payload[i["name"]] = i["value"]  # CSRF tokens and the like
    payload[user_name] = username
    payload[pass_name] = password
    body = urlencode(payload).encode()
    cookies_before = session.cookie_count  # the login page itself may
    # already have set a cookie — only a NEW one counts as a login
    if form["method"] == "post":
        result = fetch(form["action"], verify_tls=verify_tls,
                       session=session, method="POST", data=body,
                       extra_headers={
                           "Content-Type":
                               "application/x-www-form-urlencoded"})
    else:
        result = fetch(form["action"] + "?" + urlencode(payload),
                       verify_tls=verify_tls, session=session)
    if result.status is None:
        raise AuthError(f"the login submission failed ({result.error})")
    if auth_check is not None:
        if auth_check not in result.text:
            raise AuthError(
                f"login did not succeed — {auth_check!r} not found "
                "on the page after login")
    elif result.final_url == page.final_url and \
            session.cookie_count == cookies_before:
        raise AuthError(
            "login did not succeed — the page did not redirect and no "
            "new session cookie was set")
    return session, result
