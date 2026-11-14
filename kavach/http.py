"""HTTP fetching for Kavach: proxy-aware, short timeouts, honest UA.

Localhost always bypasses the proxy (the test/demo server runs there);
everything else honours the environment proxy, so the scanner works
behind a corporate proxy and on a plain connection alike.
"""
from __future__ import annotations

import os
import socket
import ssl
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (HTTPCookieProcessor, HTTPSHandler, Request,
                            build_opener)

USER_AGENT = ("Kavach/0.4 (web security scanner; only scan sites you own "
              "or have explicit permission to test)")
TIMEOUT = 5

_NO_PROXY_HOSTS = ("localhost", "127.0.0.1", "::1")


def _ensure_localhost_bypass() -> None:
    current = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
    parts = [p.strip() for p in current.split(",") if p.strip()]
    for host in _NO_PROXY_HOSTS:
        if host not in parts:
            parts.append(host)
    os.environ["NO_PROXY"] = ",".join(parts)
    os.environ["no_proxy"] = ",".join(parts)


_ensure_localhost_bypass()


@dataclass
class Response:
    url: str
    final_url: str
    status: int | None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def cookies(self) -> list[str]:
        out = []
        for k, v in self.headers.items():
            if k.lower() == "set-cookie":
                out.append(v)
        return out


class Session:
    """A persistent cookie session: every fetch through it sends the
    cookies the site set earlier (a login session). One Session = one
    login; build it with kavach.auth.login()."""

    def __init__(self, verify_tls: bool = True) -> None:
        self.jar = CookieJar()
        self.verify_tls = verify_tls
        self.opener = build_opener(HTTPCookieProcessor(self.jar))
        if not verify_tls:
            ctx = ssl._create_unverified_context()
            self.opener = build_opener(HTTPCookieProcessor(self.jar),
                                       HTTPSHandler(context=ctx))

    @property
    def cookie_count(self) -> int:
        return len(self.jar)

    def cookie_header(self, url: str) -> str:
        """The Cookie header this session would send for a URL."""
        req = Request(url)
        self.jar.add_cookie_header(req)
        return req.get_header("Cookie") or ""


def fetch(url: str, timeout: int = TIMEOUT,
          verify_tls: bool = True, session: Session | None = None,
          method: str = "GET", data: bytes | None = None,
          extra_headers: dict | None = None) -> Response:
    """One request (GET by default, POST with data). Never raises for
    HTTP errors — they are data (a 404 on /.git/HEAD is a good sign).
    Network failures come back as status None with an error string.
    verify_tls=False skips certificate verification (test environments
    only — the default verifies). A Session carries the login cookies."""
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    headers.update(extra_headers or {})
    req = Request(url, data=data, headers=headers, method=method)
    if session is not None:
        opener = session.opener
    else:
        opener = build_opener()
        if not verify_tls:
            ctx = ssl._create_unverified_context()
            opener = build_opener(HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as r:
            return Response(url=url, final_url=r.geturl(),
                            status=r.status,
                            headers=dict(r.headers.items()),
                            body=r.read(1_000_000))
    except HTTPError as e:
        try:
            body = e.read(1_000_000)
        except Exception:
            body = b""
        return Response(url=url, final_url=e.geturl(), status=e.code,
                        headers=dict(e.headers.items()), body=body)
    except (URLError, OSError, ValueError) as e:
        return Response(url=url, final_url=url, status=None,
                        error=str(e) or e.__class__.__name__)


def tls_info(host: str, port: int = 443,
             timeout: int = TIMEOUT, verify_tls: bool = True) -> dict | None:
    """One TLS handshake: version + certificate. Returns None when the
    TCP/TLS connection itself fails (network), or a dict with a 'kind':
    'ok' (verified), 'cert' (the certificate failed verification — a
    real finding), or 'handshake' (the TLS handshake itself failed for
    another reason, e.g. an intercepting proxy — not a certificate
    problem, so the caller must not report it as one).
    verify_tls=False skips certificate verification (test environments
    only) but still reports the TLS version."""
    ctx = (ssl.create_default_context() if verify_tls
           else ssl._create_unverified_context())
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {"kind": "ok", "version": ssock.version(),
                        "cert": cert, "error": ""}
    except ssl.SSLCertVerificationError as e:
        return {"kind": "cert", "version": "", "cert": {},
                "error": f"certificate: {e.verify_message}"}
    except ssl.SSLError as e:
        return {"kind": "handshake", "version": "", "cert": {},
                "error": f"TLS: {e}"}
    except (OSError, ValueError):
        return None


def host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    return parsed.hostname or "", parsed.port or (
        443 if parsed.scheme == "https" else 80)
