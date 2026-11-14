"""The checks: headers, TLS, cookies, CORS, exposed files, safe probes.

Every check returns a list of Finding. Messages are English here; the
Nepali templates live in ne.py and are selected by lang. Nothing here
claims a site is secure — a finding says what was observed, a fix says
what to do, and the report disclaimer says the rest.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .http import Response, fetch, host_port, tls_info
from .model import Finding
from .ne import FIX_NE, MESSAGE_NE

# --- OWASP Top 10:2021 mappings -------------------------------------------
A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"

SQL_ERROR_SIGNS = (
    "SQL syntax", "mysql_fetch", "mysql_num_rows", "Warning: mysql",
    "ORA-01756", "ORA-00933", "ORA-00936", "PostgreSQL", "pg_query",
    "sqlite3.OperationalError", "Unclosed quotation mark", "SQLSTATE",
    "Microsoft OLE DB", "ODBC SQL Server Driver", "syntax error at or near",
    "You have an error in your SQL syntax",
)

SENSITIVE_FILES = (
    (".git/HEAD", "git_exposed"),
    (".git/config", "git_exposed"),
    (".env", "env_exposed"),
    ("backup.zip", "backup_file_exposed"),
    ("db.sql", "backup_file_exposed"),
    ("config.php.bak", "backup_file_exposed"),
    (".DS_Store", "ds_store_exposed"),
    ("wp-config.php", "wp_config_exposed"),
)

# Subresource tags loading an http:// URL on an HTTPS page.
MIXED_CONTENT_RE = re.compile(
    r"<(?:script|img|iframe|link|video|audio|source|embed|object)\b"
    r"[^>]*(?:src|href|data)\s*=\s*[\"'](http://[^\"']+)",
    re.IGNORECASE)
CSS_URL_RE = re.compile(r"url\(\s*[\"']?(http://[^\"')]+)",
                        re.IGNORECASE)

SENSITIVE_ROBOTS_PATHS = ("/admin", "/backup", "/config", "/.git",
                          "/private", "/db", "/wp-admin")

XSS_MARKER = "<kavach>"


def _msg(rule: str, lang: str, english: str, **kwargs) -> str:
    if lang == "ne":
        return MESSAGE_NE[rule].format(**kwargs)
    return english


def _fix(rule: str, lang: str, english: str) -> str:
    return FIX_NE[rule] if lang == "ne" else english


def _finding(rule: str, severity: str, owasp: str, lang: str,
             title: str, message_en: str, fix_en: str,
             evidence: str = "", details: dict | None = None,
             **kwargs) -> Finding:
    return Finding(rule=rule, severity=severity, title=title,
                   message=_msg(rule, lang, message_en, **kwargs),
                   fix=_fix(rule, lang, fix_en), evidence=evidence,
                   owasp=owasp, details=details or {})


# --- transport ------------------------------------------------------------

def check_transport(url: str, base: Response, lang: str,
                    verify_tls: bool = True) -> list[Finding]:
    out: list[Finding] = []
    scheme = urlsplit(base.final_url).scheme
    if scheme == "http":
        if urlsplit(url).scheme == "https":
            out.append(_finding(
                "https_downgrade", "high", A02, lang,
                "HTTPS downgraded to HTTP",
                "An HTTPS address redirected to HTTP — the secure "
                "connection was dropped.",
                "Remove the HTTPS-to-HTTP redirect; keep all traffic on "
                "HTTPS."))
        else:
            out.append(_finding(
                "http_not_https", "critical", A02, lang,
                "Site served over plain HTTP",
                "This site runs on plain HTTP — logins, cookies and all "
                "traffic can be read and modified.",
                "Move the site to HTTPS and redirect HTTP to HTTPS."))
        return out
    # HTTPS: verify the certificate and TLS version with one handshake.
    host, port = host_port(base.final_url)
    info = tls_info(host, port, verify_tls=verify_tls)
    if info is None:
        out.append(_finding(
            "tls_check_failed", "info", A02, lang,
            "TLS check failed (network)",
            "The TLS check could not run (network) — the certificate and "
            "TLS version were not verified.",
            "Check the network and scan again."))
        return out
    if info["kind"] == "cert":
        out.append(_finding(
            "cert_invalid", "high", A02, lang,
            "Certificate invalid",
            f"The site certificate is not valid: {info['error']}. "
            "Browsers show a warning and users lose trust.",
            "Install a valid certificate (Let's Encrypt is free) and "
            "renew it before it expires.",
            details={"error": info["error"]}, error=info["error"]))
        return out
    if info["kind"] == "handshake":
        # The handshake itself failed — a proxy, a reset connection, a
        # server that cannot speak TLS. That is not a certificate
        # problem, so report it as an unverified check, not a finding
        # about the certificate.
        out.append(_finding(
            "tls_check_failed", "info", A02, lang,
            "TLS check failed (handshake)",
            "The TLS handshake did not complete, so the certificate and "
            "TLS version were not verified.",
            "Check the network and scan again.",
            evidence=info["error"],
            details={"error": info["error"]}))
        return out
    if info["version"] and info["version"] in ("TLSv1", "TLSv1.1",
                                               "SSLv3"):
        out.append(_finding(
            "tls_old", "high", A02, lang,
            "Old TLS version",
            f"The server uses old {info['version']} — anything below "
            "TLS 1.2 is considered unsafe.",
            "Enable only TLS 1.2 and 1.3 on the server; disable older "
            "versions.",
            details={"version": info["version"]}, version=info["version"]))
    return out


# --- headers --------------------------------------------------------------

def check_headers(base: Response, lang: str) -> list[Finding]:
    out: list[Finding] = []
    h = base.headers
    low = {k.lower(): v for k, v in h.items()}

    hsts = low.get("strict-transport-security")
    if not hsts:
        out.append(_finding(
            "missing_hsts", "high", A05, lang, "Missing HSTS",
            "No Strict-Transport-Security header — a browser may still "
            "open this site over HTTP, which opens the door to attacks.",
            "Add Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains."))
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        if not m or int(m.group(1)) < 31536000:
            out.append(_finding(
                "hsts_weak", "low", A05, lang, "HSTS max-age too short",
                f"HSTS is present but max-age is only "
                f"{m.group(1) if m else 'unset'} seconds — it should be "
                "at least one year (31536000).",
                "Set max-age to 31536000 (one year) or more.",
                details={"max_age": m.group(1) if m else ""},
                max_age=m.group(1) if m else "unset"))

    csp = low.get("content-security-policy")
    if not csp:
        out.append(_finding(
            "missing_csp", "medium", A05, lang, "Missing CSP",
            "No Content-Security-Policy header — the main defence against "
            "XSS and injection attacks is missing.",
            "Add a Content-Security-Policy header — start with "
            "default-src 'self'."))
    elif "unsafe-inline" in csp:
        out.append(_finding(
            "csp_weak", "low", A05, lang, "CSP allows unsafe-inline",
            "The Content-Security-Policy contains 'unsafe-inline', which "
            "weakens the policy.",
            "Remove 'unsafe-inline'; use a nonce or hash for scripts."))

    xfo = low.get("x-frame-options")
    if not xfo and not (csp and "frame-ancestors" in csp):
        out.append(_finding(
            "missing_x_frame_options", "medium", A05, lang,
            "Missing X-Frame-Options",
            "No X-Frame-Options header — this site can be framed by "
            "another site for clickjacking.",
            "Add X-Frame-Options: DENY or SAMEORIGIN."))

    if not low.get("x-content-type-options"):
        out.append(_finding(
            "missing_x_content_type_options", "low", A05, lang,
            "Missing X-Content-Type-Options",
            "No X-Content-Type-Options: nosniff — a browser may guess a "
            "file's type and run it the wrong way.",
            "Add X-Content-Type-Options: nosniff."))

    if not low.get("referrer-policy"):
        out.append(_finding(
            "missing_referrer_policy", "low", A05, lang,
            "Missing Referrer-Policy",
            "No Referrer-Policy header — clicking a link can send the "
            "full address to another site.",
            "Add Referrer-Policy: strict-origin-when-cross-origin."))

    if not low.get("permissions-policy"):
        out.append(_finding(
            "missing_permissions_policy", "low", A05, lang,
            "Missing Permissions-Policy",
            "No Permissions-Policy header — powerful browser features "
            "(camera, microphone, location) are not controlled.",
            "Add a Permissions-Policy header (e.g. camera=(), "
            "microphone=(), geolocation=())."))

    server = low.get("server")
    if server:
        out.append(_finding(
            "server_header", "low", A05, lang, "Server header discloses "
            "software",
            f"The Server header reveals the software ({server}) — an "
            "attacker can look up which version has which weakness.",
            "Do not send a Server header, or send it without a version.",
            evidence=server, details={"value": server}, value=server))

    powered = low.get("x-powered-by")
    if powered:
        out.append(_finding(
            "x_powered_by", "low", A05, lang, "X-Powered-By discloses stack",
            f"The X-Powered-By header reveals the stack ({powered}) — "
            "helpful to an attacker.",
            "Remove the X-Powered-By header.",
            evidence=powered, details={"value": powered}, value=powered))

    acao = low.get("access-control-allow-origin")
    if acao == "*":
        creds = low.get("access-control-allow-credentials", "").lower() \
            == "true"
        out.append(_finding(
            "cors_wildcard", "high" if creds else "medium", A05, lang,
            "CORS allows any origin",
            "Access-Control-Allow-Origin: *"
            + (" with credentials — any site can read authenticated "
               "responses." if creds else
               " — any site can read this site's responses."),
            "Put the exact allowed domains in "
            "Access-Control-Allow-Origin instead of *.",
            details={"credentials": creds},
            credentials=(" with credentials" if creds else "")))
    return out


# --- cookies --------------------------------------------------------------

def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split(";", 1)[0].split("=", 1)[0].strip()


def check_cookies(base: Response, lang: str) -> list[Finding]:
    out: list[Finding] = []
    cookies = base.cookies()
    if not cookies:
        return out
    is_https = urlsplit(base.final_url).scheme == "https"
    no_secure, no_httponly, no_samesite = [], [], []
    for c in cookies:
        name = _cookie_name(c)
        attrs = c.lower()
        if is_https and "secure" not in attrs:
            no_secure.append(name)
        if "httponly" not in attrs:
            no_httponly.append(name)
        if "samesite" not in attrs:
            no_samesite.append(name)
    if no_secure:
        out.append(_finding(
            "cookie_no_secure", "medium", A05, lang,
            "Cookie without Secure flag",
            f"Cookie {', '.join(no_secure)} has no Secure flag — it can "
            "be sent over HTTP and stolen.",
            "Add the Secure flag to every cookie.",
            details={"names": no_secure}, names=", ".join(no_secure)))
    if no_httponly:
        out.append(_finding(
            "cookie_no_httponly", "medium", A05, lang,
            "Cookie without HttpOnly flag",
            f"Cookie {', '.join(no_httponly)} has no HttpOnly flag — "
            "JavaScript can read it, which makes XSS attacks easier.",
            "Add the HttpOnly flag to every cookie.",
            details={"names": no_httponly}, names=", ".join(no_httponly)))
    if no_samesite:
        out.append(_finding(
            "cookie_no_samesite", "low", A05, lang,
            "Cookie without SameSite flag",
            f"Cookie {', '.join(no_samesite)} has no SameSite flag — it "
            "can be sent on requests from another site (CSRF risk).",
            "Add SameSite=Lax (or Strict) to every cookie.",
            details={"names": no_samesite}, names=", ".join(no_samesite)))
    return out


# --- exposed files --------------------------------------------------------

def _looks_like_git_head(body: bytes) -> bool:
    return body.decode("utf-8", errors="ignore").strip().startswith("ref:")


def _looks_like_git_config(body: bytes) -> bool:
    text = body.decode("utf-8", errors="ignore")
    return "[core]" in text and "repositoryformatversion" in text


def _looks_like_env(body: bytes) -> bool:
    text = body.decode("utf-8", errors="ignore")
    return bool(re.search(r"^[A-Z][A-Z0-9_]{2,}=[^\n]{1,}", text,
                          re.MULTILINE))


def check_sensitive_files(base_url: str, lang: str,
                          verify_tls: bool = True) -> list[Finding]:
    out: list[Finding] = []
    for path, rule in SENSITIVE_FILES:
        r = fetch(urljoin(base_url, "/" + path), verify_tls=verify_tls)
        if r.status != 200 or not r.body:
            continue
        exposed = False
        if path == ".git/HEAD":
            exposed = _looks_like_git_head(r.body)
        elif path == ".git/config":
            exposed = _looks_like_git_config(r.body)
        elif path == ".env":
            exposed = _looks_like_env(r.body)
        elif path == "backup.zip":
            exposed = r.body[:4] == b"PK\x03\x04"
        elif path == "db.sql":
            exposed = bool(re.search(rb"CREATE TABLE|INSERT INTO",
                                     r.body, re.IGNORECASE))
        elif path == "config.php.bak":
            exposed = b"<?php" in r.body or _looks_like_env(r.body)
        elif path == ".DS_Store":
            exposed = r.body[:8] == b"\x00\x00\x00\x01Bud1"
        elif path == "wp-config.php":
            exposed = (b"DB_PASSWORD" in r.body
                       or b"define('DB_" in r.body
                       or b'define("DB_' in r.body)
        if not exposed:
            continue
        if rule == "git_exposed":
            out.append(_finding(
                "git_exposed", "critical", A01, lang, "Git repository exposed",
                "/.git/HEAD is publicly accessible — the source code and "
                "history can be downloaded.",
                "Block /.git on the web server (or do not deploy it).",
                evidence=path))
        elif rule == "env_exposed":
            out.append(_finding(
                "env_exposed", "critical", A05, lang, ".env file exposed",
                "/.env is publicly accessible — it may hold passwords and "
                "API keys. Change them at once.",
                "Block /.env on the web server and change every password "
                "and key inside it at once.",
                evidence=path))
        elif rule == "ds_store_exposed":
            out.append(_finding(
                "ds_store_exposed", "low", A05, lang, ".DS_Store exposed",
                "/.DS_Store is publicly accessible — it reveals the "
                "names of files in the folder.",
                "Block /.DS_Store on the web server or do not deploy it.",
                evidence=path))
        elif rule == "wp_config_exposed":
            out.append(_finding(
                "wp_config_exposed", "critical", A05, lang,
                "wp-config.php exposed",
                "wp-config.php is publicly accessible — it may hold the "
                "database password. Change it at once.",
                "Block wp-config.php on the web server and change the "
                "database password inside it at once.",
                evidence=path))
        else:
            out.append(_finding(
                "backup_file_exposed", "high", A01, lang,
                "Backup file exposed",
                f"Backup file /{path} is publicly accessible — it may "
                "hold the database or source code.",
                "Remove backup files from the web root or block access to "
                "them.",
                evidence=path, details={"path": path}, path="/" + path))
    return out


# --- safe probes ----------------------------------------------------------

def _probe_url(base_url: str, param_value: str,
               param: str | None = None) -> str:
    """Build a probe URL. With param given, set (or add) that named
    parameter; otherwise reuse the first existing query param, else add
    one. The probe value is inert — a quote for SQL errors, a marker tag
    for reflection, a benign external URL for open redirects."""
    parts = urlsplit(base_url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if param:
        params = [(k, v) for k, v in params if k != param]
        params.append((param, param_value))
    elif params:
        key = params[0][0]
        params[0] = (key, param_value)
    else:
        params = [("id", param_value)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(params), parts.fragment))


def check_sqli(base_url: str, lang: str,
               verify_tls: bool = True) -> list[Finding]:
    probe = _probe_url(base_url, "1'")
    r = fetch(probe, verify_tls=verify_tls)
    if r.status is None:
        return []
    for sign in SQL_ERROR_SIGNS:
        if sign.lower() in r.text.lower():
            return [_finding(
                "sqli_error", "high", A03, lang,
                "Possible SQL injection",
                f"A ' in a parameter produced a database error ({sign}) "
                "— SQL injection may be possible.",
                "Use prepared statements / parameterised queries for SQL, "
                "and never show database errors to users.",
                evidence=probe, details={"evidence": sign}, sign=sign)]
    return []


def check_xss(base_url: str, lang: str,
              verify_tls: bool = True) -> list[Finding]:
    probe = _probe_url(base_url, XSS_MARKER)
    r = fetch(probe, verify_tls=verify_tls)
    if r.status is None:
        return []
    if XSS_MARKER in r.text:
        return [_finding(
            "xss_reflected", "high", A03, lang,
            "Possible reflected XSS",
            f"The {XSS_MARKER} sent in a parameter came back unencoded "
            "in the response — reflected XSS may be possible.",
            "Always escape user input when showing it (or use your "
            "framework's auto-escaping).",
            evidence=probe, details={"marker": XSS_MARKER},
            marker=XSS_MARKER)]
    return []


def check_robots(base_url: str, lang: str,
                 verify_tls: bool = True) -> list[Finding]:
    r = fetch(urljoin(base_url, "/robots.txt"), verify_tls=verify_tls)
    if r.status != 200:
        return []
    found = sorted({p for p in SENSITIVE_ROBOTS_PATHS
                    if f"Disallow: {p}" in r.text})
    if not found:
        return []
    return [_finding(
        "robots_sensitive", "info", A05, lang,
        "robots.txt lists sensitive paths",
        f"robots.txt lists sensitive paths ({', '.join(found)}) — "
        "attackers look there first.",
        "Do not list sensitive paths in robots.txt; protect them with "
        "access control, not robots.txt.",
        details={"paths": found}, paths=", ".join(found))]


# --- new in v0.2 ----------------------------------------------------------

def check_mixed_content(base: Response, lang: str) -> list[Finding]:
    """Only meaningful on HTTPS: subresources loaded over plain HTTP
    can be read and modified. Free — it reuses the base page's HTML."""
    if urlsplit(base.final_url).scheme != "https":
        return []
    found = MIXED_CONTENT_RE.findall(base.text)
    found += CSS_URL_RE.findall(base.text)
    if not found:
        return []
    examples = ", ".join(sorted(set(found))[:3])
    return [_finding(
        "mixed_content", "medium", A02, lang,
        "Mixed content on HTTPS page",
        f"The HTTPS page loads {len(found)} resource(s) over HTTP "
        f"({examples}) — those resources can be read and modified.",
        "Load every resource (scripts, images, styles) over HTTPS.",
        evidence=examples,
        details={"count": len(found), "examples": examples},
        count=len(found), examples=examples)]


def check_open_redirect(base_url: str, lang: str,
                        verify_tls: bool = True) -> list[Finding]:
    """One safe probe: ask the site to redirect to example.com (a benign
    public test domain). If the fetch ends on a different host, the site
    follows a caller-supplied redirect target."""
    probe = _probe_url(base_url, "https://example.com", param="next")
    r = fetch(probe, verify_tls=verify_tls)
    if r.status is None:
        return []
    final_host = urlsplit(r.final_url).netloc
    if final_host and final_host != urlsplit(base_url).netloc:
        return [_finding(
            "open_redirect", "high", A01, lang,
            "Possible open redirect",
            f"The site redirected a caller-supplied address ({r.final_url}) "
            "— an attacker can send users to a fake site.",
            "Do not accept external addresses in redirect parameters — "
            "allow only a list of permitted addresses.",
            evidence=probe,
            details={"target": r.final_url}, target=r.final_url)]
    return []


def check_security_txt(base_url: str, lang: str,
                       verify_tls: bool = True) -> list[Finding]:
    """RFC 9116: a security.txt gives researchers a contact point. Its
    absence is an info nudge, not a penalty."""
    r = fetch(urljoin(base_url, "/.well-known/security.txt"),
              verify_tls=verify_tls)
    if r.status == 200 and "Contact:" in r.text:
        return []
    return [_finding(
        "missing_security_txt", "info", A05, lang,
        "No security.txt",
        "No security.txt — someone who finds a security problem has no "
        "contact address to report it to.",
        "Add a Contact: address in /.well-known/security.txt (RFC 9116).")]
