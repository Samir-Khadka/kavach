"""Demo: scan the deliberately vulnerable site, the hardened one, and
the mixed one (HTTPS but with mixed content + an open redirect), crawl
the vulnerable site, scan the authenticated dashboard (demo/demo123),
and print the graded reports (EN, then NE for the vulnerable one).

Run: python demo.py
"""
from __future__ import annotations

from kavach.auth import login
from kavach.demo_server import serve_all
from kavach.report import to_text
from kavach.scanner import scan


def main() -> None:
    vuln_url, secure_url, mixed_url, stop = serve_all()
    try:
        print("== Vulnerable demo site (English) ==")
        print(to_text(scan(vuln_url)))
        print("== Hardened demo site (English) ==")
        print(to_text(scan(secure_url, verify_tls=False)))
        print("== Mixed demo site (English) ==")
        print(to_text(scan(mixed_url, verify_tls=False)))
        print("== Vulnerable demo site, crawled (3 pages, English) ==")
        print(to_text(scan(vuln_url, max_pages=3)))
        print("== Vulnerable demo site, form-aware crawl (4 pages) ==")
        print(to_text(scan(vuln_url, max_pages=4)))
        print("== Authenticated dashboard (demo/demo123, English) ==")
        session, _ = login(vuln_url + "login", "demo", "demo123",
                           auth_check="Welcome, demo")
        print(to_text(scan(vuln_url + "dashboard", session=session,
                           max_pages=2)))
        print("== Vulnerable demo site (Nepali) ==")
        print(to_text(scan(vuln_url, lang="ne")))
    finally:
        stop()


if __name__ == "__main__":
    main()
