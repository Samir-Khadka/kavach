"""CLI: python -m kavach <url> [--lang ne] [--json] [--output report.json]

Exit codes: 0 = grade A or B, 1 = grade C or D, 2 = grade F,
3 = scan failed (unreachable / bad URL / login failed).
Only scan sites you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import os
import sys

from .auth import AuthError, login
from .report import badge_svg, to_html, to_json, to_text
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kavach",
        description="Web security scanner — only scan sites you own or "
                    "have explicit permission to test.")
    parser.add_argument("url", help="URL to scan (https://example.com)")
    parser.add_argument("--lang", default="en", choices=("en", "ne"),
                        help="report language (default: en)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--output", help="write the report to a file")
    parser.add_argument("--html", help="write an HTML report to a file")
    parser.add_argument("--badge", help="write an SVG grade badge to a file")
    parser.add_argument("--max-pages", type=int, default=1,
                        help="crawl up to N same-origin pages "
                             "(default 1, max 20)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="seconds between page fetches while crawling "
                             "(default 0.2)")
    parser.add_argument("--auth-url",
                        help="login page URL — scan behind a login")
    parser.add_argument("--auth-user", help="login username")
    parser.add_argument("--auth-pass",
                        help="login password (or set KAVACH_AUTH_PASS)")
    parser.add_argument("--auth-user-field",
                        help="username input name (auto-detected by default)")
    parser.add_argument("--auth-pass-field",
                        help="password input name (auto-detected by default)")
    parser.add_argument("--auth-check",
                        help="text that must appear after login "
                             "(proves the login worked)")
    parser.add_argument("--history-dir", default="~/.kavach/history",
                        help="where to store scan history (default: "
                             "~/.kavach/history)")
    parser.add_argument("--no-history", action="store_true",
                        help="do not store this scan or diff against "
                             "a previous one")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification "
                             "(test environments only)")
    args = parser.parse_args(argv)
    history_dir = None if args.no_history else \
        os.path.expanduser(args.history_dir)
    session = None
    if args.auth_url:
        password = args.auth_pass or os.environ.get("KAVACH_AUTH_PASS")
        if not args.auth_user or not password:
            print("kavach: --auth-url needs --auth-user and --auth-pass "
                  "(or KAVACH_AUTH_PASS)", file=sys.stderr)
            return 3
        try:
            session, _ = login(args.auth_url, args.auth_user, password,
                               user_field=args.auth_user_field,
                               password_field=args.auth_pass_field,
                               auth_check=args.auth_check,
                               verify_tls=not args.insecure)
        except AuthError as e:
            print(f"kavach: login failed — {e}", file=sys.stderr)
            return 3
    try:
        result = scan(args.url, lang=args.lang,
                      verify_tls=not args.insecure,
                      max_pages=args.max_pages, delay=args.delay,
                      session=session, history_dir=history_dir)
    except ValueError as e:
        print(f"kavach: {e}", file=sys.stderr)
        return 3
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(to_html(result))
    if args.badge:
        with open(args.badge, "w", encoding="utf-8") as f:
            f.write(badge_svg(result.grade))
    text = to_json(result) if args.json else to_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    print(text, end="" if args.output else "\n")
    if result.grade in ("A", "B"):
        return 0
    if result.grade in ("C", "D"):
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
