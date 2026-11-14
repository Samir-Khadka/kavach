"""A deliberately insecure demo site, in two variants, for Kavach.

- vulnerable: plain HTTP, no security headers, Server/X-Powered-By
  disclosure, CORS *, cookies without flags, /.git/HEAD and /.env
  exposed, a reflective ?q= parameter, a ?id= parameter that answers
  a quote with a database error, robots.txt listing /admin/ and /backup/.
- secure: HTTPS (self-signed cert, generated on the fly), every good
  header, flagged cookies, 404s for the sensitive files, escaped
  reflection, no SQL error, clean robots.txt.

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
    secure = False  # set per server instance

    def log_message(self, *args):  # keep test output clean
        pass

    def send_response(self, code, message=None):  # no default Server/Date
        self.send_response_only(code, message)

    def _send(self, status: int, body: bytes,
              headers: list[tuple[str, str]], ctype: str = "text/html"):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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

    def _handle(self):
        parts = urlsplit(self.path)
        path = parts.path
        secure = self.secure or path.startswith("/secure")
        if path.startswith("/secure"):
            path = path[len("/secure"):] or "/"
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        headers = self._headers()
        cookie = self._cookie()

        sensitive = {
            "/.git/HEAD": (GIT_HEAD, "text/plain"),
            "/.git/config": (GIT_CONFIG, "text/plain"),
            "/.env": (ENV_FILE, "text/plain"),
            "/backup.zip": ("PK\x03\x04" + "x" * 200, "application/zip"),
            "/db.sql": (DB_SQL, "text/plain"),
            "/config.php.bak": (PHP_BAK, "text/plain"),
        }
        if path in sensitive:
            if secure:
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

        # home page: reflection + SQL-error simulation. Reflects the
        # first query parameter's value, whatever its name is.
        params_list = parse_qsl(parts.query, keep_blank_values=True)
        ident = params.get("id")
        if not secure and ident is not None and "'" in ident:
            body = ("<html><body><h1>Error</h1><p>You have an error in "
                    "your SQL syntax near ''' at line 1</p></body></html>")
            self._send(200, body.encode(), headers)
            return
        reflected = ""
        if params_list:
            reflected = params_list[0][1]
            if secure:
                reflected = html.escape(reflected)
        body = (f"<html><body><h1>Kavach demo</h1>"
                f"<p>Search: {reflected}</p></body></html>")
        self._send(200, body.encode(),
                   headers + [("Set-Cookie", cookie)])
        return


def make_server(port: int = 0, secure: bool = False,
                certfile: str | None = None,
                keyfile: str | None = None) -> ThreadingHTTPServer:
    """A demo server on 127.0.0.1. secure=True wraps it in TLS with the
    given self-signed cert/key."""
    handler = type("Handler", (DemoHandler,), {"secure": secure})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    if secure:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def serve_both(tmpdir: str | None = None):
    """Start the vulnerable (HTTP) and secure (HTTPS) demo servers and
    return (vuln_url, secure_url, stop). Used by demo.py and tests."""
    tmp = Path(tmpdir) if tmpdir else Path(tempfile.mkdtemp())
    cert, key = generate_self_signed_cert(tmp)
    vuln = make_server(0, secure=False)
    secure = make_server(0, secure=True, certfile=str(cert),
                         keyfile=str(key))
    import threading
    threads = []
    for srv in (vuln, secure):
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    vuln_url = f"http://127.0.0.1:{vuln.server_address[1]}/"
    secure_url = (f"https://127.0.0.1:{secure.server_address[1]}/secure/"
                  f"?q=test")

    def stop():
        vuln.shutdown()
        secure.shutdown()
        vuln.server_close()
        secure.server_close()

    return vuln_url, secure_url, stop


if __name__ == "__main__":
    vuln_url, secure_url, stop = serve_both()
    print("Vulnerable:", vuln_url)
    print("Secure:    ", secure_url)
    print("Press Ctrl-C to stop.")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop()
