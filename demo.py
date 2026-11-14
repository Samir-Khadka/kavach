"""Demo: scan the deliberately vulnerable site, then the hardened one,
and print both graded reports (EN, then NE for the vulnerable one).

Run: python demo.py
"""
from __future__ import annotations

from kavach.demo_server import serve_both
from kavach.report import to_text
from kavach.scanner import scan


def main() -> None:
    vuln_url, secure_url, stop = serve_both()
    try:
        print("== Vulnerable demo site (English) ==")
        print(to_text(scan(vuln_url)))
        print("== Hardened demo site (English) ==")
        print(to_text(scan(secure_url, verify_tls=False)))
        print("== Vulnerable demo site (Nepali) ==")
        print(to_text(scan(vuln_url, lang="ne")))
    finally:
        stop()


if __name__ == "__main__":
    main()
