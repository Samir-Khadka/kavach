"""A deliberately insecure demo site, in three variants, for Kavach.

- vulnerable: plain HTTP, no security headers, Server/X-Powered-By
  disclosure, CORS *, cookies without flags, /.git/HEAD and /.env
  exposed, a reflective ?q= parameter, a ?id= parameter that answers
  a quote with a database error, robots.txt listing /admin/ and /backup/.
  Has a login form (demo/demo123) that sets a session cookie and
  opens /dashboard — the authenticated area.
- secure: HTTPS (self-signed cert, generated on the fly), every good
  header, flagged cookies, 404s for the sensitive files, escaped
  reflection, no SQL error, clean robots.txt.
- mixed: HTTPS, hardened except for mixed content + an open redirect.

Used by demo.py and by the test suite. NEVER point this at the public
internet — it is a local teaching target only.
"""
from __future__ import annotations

import html
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

DEMO_USER = "demo"
DEMO_PASS = "demo123"
SESSION_COOKIE = "session=authenticated"
CSRF_TOKEN = "demo-csrf-token"

VULN_HEADERS = [
    ("Server", "Apache/2.4.49 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.4.3"),
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Credentials", "true"),
    ("Content-Type", "text/html; charset=utf-8"),
]

SECURE_HEADERS = [
    ("Strict-Transport-Security",
     "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Content-Type", "text/html; charset=utf-8"),
]

GIT_HEAD = "ref: refs/heads/main\n"
GIT_CONFIG = "[core]\n\trepositoryformatversion = 0\n"
ENV_FILE = "SECRET_KEY=supersecret123\nDB_PASSWORD=hunter2\n"
DB_SQL = "CREATE TABLE users (id INT, name VARCHAR(50));\nINSERT INTO users VALUES (1, 'admin');\n"
PHP_BAK = "<?php $db_pass = 'hunter2';\n"
DS_STORE = b"\x00\x00\x00\x01Bud1" + b"x" * 100
WP_CONFIG = "<?php define('DB_NAME', 'site');\ndefine('DB_PASSWORD', 'hunter2');\n"
SECURITY_TXT = "Contact: security@example.com\nExpires: 2027-01-01T00:00:00Z\n"


def generate_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """One-day self-signed cert for 127.0.0.1 (openssl must exist)."""
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-nodes",
         "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    return cert, key


class DemoHandler(BaseHTTPRequestHandler):
    variant = "vulnerable"  # "vulnerable" | "secure" | "mixed"

    def log_message(self, *args):  # keep test output clean
        pass

    def send_response(self, code, message=None):  # no default Server/Date
        self.send_response_only(code, message)

    def _send(self, status: int, body: bytes,
              headers: list[tuple[str, str]], ctype: str = "text/html",
              extra: list[tuple[str, str]] | None = None):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    @property
    def secure(self) -> bool:
        return self.variant in ("secure", "mixed")

    def _headers(self):
        return SECURE_HEADERS if self.secure else VULN_HEADERS

    def _cookie(self):
        if self.secure:
            return ("session=abc123; Secure; HttpOnly; SameSite=Lax")
        return "session=abc123"

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_POST(self):
        self._handle_post()

    def _is_authenticated(self) -> bool:
        cookie = self.headers.get("Cookie") or ""
        return SESSION_COOKIE in cookie

    def _handle_post(self):
        """POST /login: the demo login. demo/demo123 sets the session
        cookie and redirects to /dashboard; anything else gets the
        login page back with an error."""
        parts = urlsplit(self.path)
        if parts.path != "/login":
            self._send(404, b"Not found", VULN_HEADERS)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = dict(parse_qsl(body, keep_blank_values=True))
        if params.get("username") == DEMO_USER and \
                params.get("password") == DEMO_PASS:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", SESSION_COOKIE)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        html_body = ("<html><body><h1>Login</h1>"
                     "<p>Invalid username or password.</p>"
                     "<form method=\"post\" action=\"/login\">"
                     "<input name=\"username\">"
                     "<input type=\"password\" name=\"password\">"
                     f"<input type=\"hidden\" name=\"csrf\" "
                     f"value=\"{CSRF_TOKEN}\">"
                     "<input type=\"submit\" value=\"Log in\"></form>"
                     "</body></html>")
        self._send(200, html_body.encode(), VULN_HEADERS)
        return

    def _handle(self):
        parts = urlsplit(self.path)
        path = parts.path
        variant = self.variant
        if path.startswith("/secure"):
            path = path[len("/secure"):] or "/"
            variant = "secure"
        if path.startswith("/mixed"):
            path = path[len("/mixed"):] or "/"
            variant = "mixed"
        secure = variant in ("secure", "mixed")
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        headers = SECURE_HEADERS if secure else VULN_HEADERS
        cookie = self._cookie()

        # open redirect (vulnerable + mixed only): a `next` parameter
        # pointing at an external URL is followed without question.
        nxt = params.get("next")
        if variant in ("vulnerable", "mixed") and nxt and (
                nxt.startswith("http://") or nxt.startswith("https://")):
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        sensitive = {
            "/.git/HEAD": (GIT_HEAD, "text/plain"),
            "/.git/config": (GIT_CONFIG, "text/plain"),
            "/.env": (ENV_FILE, "text/plain"),
            "/backup.zip": ("PK\x03\x04" + "x" * 200, "application/zip"),
            "/db.sql": (DB_SQL, "text/plain"),
            "/config.php.bak": (PHP_BAK, "text/plain"),
            "/.DS_Store": (DS_STORE, "application/octet-stream"),
            "/wp-config.php": (WP_CONFIG, "text/plain"),
        }
        if path in sensitive:
            if secure and variant == "secure":
                self._send(404, b"Not found", headers)
            elif secure and variant == "mixed":
                # the mixed site is hardened except for mixed content
                # and the open redirect — its files stay hidden
                self._send(404, b"Not found", headers)
            else:
                body, ctype = sensitive[path]
                self._send(200, body.encode("utf-8", "surrogateescape")
                           if isinstance(body, str) else body,
                           headers, ctype)
            return

        if path == "/robots.txt":
            body = ("User-agent: *\nDisallow: /\n" if secure else
                    "User-agent: *\nDisallow: /admin/\n"
                    "Disallow: /backup/\n")
            self._send(200, body.encode(), headers, "text/plain")
            return

        if path == "/.well-known/security.txt":
            if variant == "secure":
                self._send(200, SECURITY_TXT.encode(), headers,
                           "text/plain")
            else:
                self._send(404, b"Not found", headers)
            return

        # /dashboard: the authenticated area. Without the session
        # cookie it redirects to /login; with it, it is a vulnerable
        # page (reflects input, answers a quote with a database error)
        # that links to /dashboard/settings.
        if path in ("/dashboard", "/dashboard/settings"):
            if not self._is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            params_list = parse_qsl(parts.query, keep_blank_values=True)
            ident = params.get("id")
            if variant == "vulnerable" and ident is not None \
                    and "'" in ident:
                body = ("<html><body><h1>Error</h1><p>You have an error "
                        "in your SQL syntax near ''' at line 1</p>"
                        "</body></html>")
                self._send(200, body.encode(), headers)
                return
            reflected = ""
            if params_list:
                reflected = params_list[0][1]
                if secure:
                    reflected = html.escape(reflected)
            if path == "/dashboard":
                body = ("<html><body><h1>Dashboard</h1>"
                        "<p>Welcome, demo</p>"
                        f"<p>Search: {reflected}</p>"
                        "<p><a href=\"/dashboard/settings\">Settings</a> "
                        "<a href=\"/\">Home</a></p></body></html>")
            else:
                body = ("<html><body><h1>Settings</h1>"
                        f"<p>Search: {reflected}</p>"
                        "<p><a href=\"/dashboard\">Dashboard</a></p>"
                        "</body></html>")
            self._send(200, body.encode(), headers)
            return

        # /about: same site, but this page DOES send X-Frame-Options —
        # so a crawl sees a page-specific difference. It mentions
        # MySQL and SQLite as text but never reflects input or returns
        # a database error, so the SQLi/XSS probes must stay silent
        # here (regression test for the false-positive fix).
        if path == "/about":
            about_headers = headers
            if not any(k.lower() == "x-frame-options"
                       for k, _ in headers):
                about_headers = headers + [("X-Frame-Options", "DENY")]
            body = ("<html><body><h1>About</h1>"
                    "<p>Built with Python, MySQL and SQLite.</p>"
                    "<p><a href=\"/\">Home</a></p></body></html>")
            self._send(200, body.encode(),
                       about_headers + [("Set-Cookie", cookie)])
            return

        # /login: a real login form (demo/demo123). Reflects input and
        # answers a quote with a database error, like home.
        if path == "/login":
            params_list = parse_qsl(parts.query, keep_blank_values=True)
            ident = params.get("id")
            if variant == "vulnerable" and ident is not None \
                    and "'" in ident:
                body = ("<html><body><h1>Error</h1><p>You have an error "
                        "in your SQL syntax near ''' at line 1</p>"
                        "</body></html>")
                self._send(200, body.encode(), headers)
                return
            reflected = ""
            if params_list:
                reflected = params_list[0][1]
                if secure:
                    reflected = html.escape(reflected)
            body = ("<html><body><h1>Login</h1>"
                    f"<p>Search: {reflected}</p>"
                    "<form method=\"post\" action=\"/login\">"
                    "<input name=\"username\">"
                    "<input type=\"password\" name=\"password\">"
                    f"<input type=\"hidden\" name=\"csrf\" "
                    f"value=\"{CSRF_TOKEN}\">"
                    "<input type=\"submit\" value=\"Log in\"></form>"
                    "<p><a href=\"/\">Home</a></p></body></html>")
            self._send(200, body.encode(),
                       headers + [("Set-Cookie", cookie)])
            return

        # home page: reflection + SQL-error simulation. Reflects the
        # first query parameter's value, whatever its name is.
        params_list = parse_qsl(parts.query, keep_blank_values=True)
        ident = params.get("id")
        if variant == "vulnerable" and ident is not None and "'" in ident:
            body = ("<html><body><h1>Error</h1><p>You have an error in "
                    "your SQL syntax near ''' at line 1</p></body></html>")
            self._send(200, body.encode(), headers)
            return
        reflected = ""
        if params_list:
            reflected = params_list[0][1]
            if secure:
                reflected = html.escape(reflected)
        mixed = ""
        if variant == "mixed":
            mixed = ('<script src="http://example.com/tracker.js">'
                     '</script><img src="http://example.com/logo.png">')
        links = ""
        if variant == "vulnerable":
            links = ('<p><a href="/about">About</a> '
                     '<a href="/login">Login</a></p>')
        elif variant == "secure":
            links = '<p><a href="/secure/about">About</a></p>'
        body = (f"<html><body><h1>Kavach demo</h1>{mixed}"
                f"<p>Search: {reflected}</p>{links}</body></html>")
        self._send(200, body.encode(),
                   headers + [("Set-Cookie", cookie)])
        return


def make_server(port: int = 0, variant: str = "vulnerable",
                certfile: str | None = None,
                keyfile: str | None = None) -> ThreadingHTTPServer:
    """A demo server on 127.0.0.1. variant is 'vulnerable' (HTTP),
    'secure' (HTTPS, hardened) or 'mixed' (HTTPS, hardened except for
    mixed content + an open redirect). HTTPS variants need a self-signed
    cert/key."""
    handler = type("Handler", (DemoHandler,), {"variant": variant})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    if variant in ("secure", "mixed"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def serve_all(tmpdir: str | None = None):
    """Start the vulnerable (HTTP), secure (HTTPS) and mixed (HTTPS)
    demo servers and return (vuln_url, secure_url, mixed_url, stop)."""
    tmp = Path(tmpdir) if tmpdir else Path(tempfile.mkdtemp())
    cert, key = generate_self_signed_cert(tmp)
    vuln = make_server(0, variant="vulnerable")
    secure = make_server(0, variant="secure", certfile=str(cert),
                         keyfile=str(key))
    mixed = make_server(0, variant="mixed", certfile=str(cert),
                        keyfile=str(key))
    import threading
    for srv in (vuln, secure, mixed):
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
    vuln_url = f"http://127.0.0.1:{vuln.server_address[1]}/"
    secure_url = (f"https://127.0.0.1:{secure.server_address[1]}/secure/"
                  f"?q=test")
    mixed_url = f"https://127.0.0.1:{mixed.server_address[1]}/mixed/"

    def stop():
        for srv in (vuln, secure, mixed):
            srv.shutdown()
            srv.server_close()

    return vuln_url, secure_url, mixed_url, stop


def serve_both(tmpdir: str | None = None):
    """Backwards-compatible wrapper: only the vulnerable + secure URLs."""
    vuln_url, secure_url, _mixed_url, stop = serve_all(tmpdir)
    return vuln_url, secure_url, stop


if __name__ == "__main__":
    vuln_url, secure_url, mixed_url, stop = serve_all()
    print("Vulnerable:", vuln_url)
    print("Secure:    ", secure_url)
    print("Mixed:     ", mixed_url)
    print("Press Ctrl-C to stop.")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop()
