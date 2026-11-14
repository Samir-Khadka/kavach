"""CLI.

Scan:   python -m kavach <url> [--lang ne] [--json] [--output report.json]
Verify: python -m kavach verify <url> --rule missing_hsts [--page URL]

Scan exit codes: 0 = grade A or B, 1 = grade C or D, 2 = grade F,
3 = scan failed (unreachable / bad URL / login failed).
Verify exit codes: 0 = fixed, 1 = still present, 2 = scan failed,
3 = usage error (no --rule, unknown rule).
Only scan sites you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .auth import AuthError, login
from .report import badge_svg, to_html, to_json, to_text
from .scanner import scan
from .verify import ALL_RULES, verify


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lang", default="en", choices=("en", "ne"),
                        help="report language (default: en)")
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


def _login_session(args) -> object:
    """A login session from the --auth-* flags, or None. Exits 3 on a
    bad login (printed, not raised, so the CLI can use it)."""
    if not args.auth_url:
        return None
    password = args.auth_pass or os.environ.get("KAVACH_AUTH_PASS")
    if not args.auth_user or not password:
        print("kavach: --auth-url needs --auth-user and --auth-pass "
              "(or KAVACH_AUTH_PASS)", file=sys.stderr)
        raise SystemExit(3)
    try:
        session, _ = login(args.auth_url, args.auth_user, password,
                           user_field=args.auth_user_field,
                           password_field=args.auth_pass_field,
                           auth_check=args.auth_check,
                           verify_tls=not args.insecure)
    except AuthError as e:
        print(f"kavach: login failed — {e}", file=sys.stderr)
        raise SystemExit(3)
    return session


def scan_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kavach",
        description="Web security scanner — only scan sites you own or "
                    "have explicit permission to test.")
    parser.add_argument("url", help="URL to scan (https://example.com)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--output", help="write the report to a file")
    parser.add_argument("--html", help="write an HTML report to a file")
    parser.add_argument("--badge", help="write an SVG grade badge to a file")
    _add_common(parser)
    args = parser.parse_args(argv)
    try:
        session = _login_session(args)
    except SystemExit as e:
        return e.code
    history_dir = None if args.no_history else \
        os.path.expanduser(args.history_dir)
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


def verify_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kavach verify",
        description="Re-scan and confirm one finding is fixed.")
    parser.add_argument("url", help="URL to re-scan")
    parser.add_argument("--rule", required=True,
                        help="the rule to verify (e.g. missing_hsts)")
    parser.add_argument("--page",
                        help="only check this page (default: anywhere)")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON")
    _add_common(parser)
    args = parser.parse_args(argv)
    if args.rule not in ALL_RULES:
        print(f"kavach: unknown rule {args.rule!r}", file=sys.stderr)
        print("known rules: " + ", ".join(sorted(ALL_RULES)),
              file=sys.stderr)
        return 3
    try:
        session = _login_session(args)
    except SystemExit as e:
        return e.code
    history_dir = None if args.no_history else \
        os.path.expanduser(args.history_dir)
    try:
        result = verify(args.url, args.rule, page=args.page,
                        lang=args.lang, verify_tls=not args.insecure,
                        max_pages=args.max_pages, delay=args.delay,
                        session=session, history_dir=history_dir)
    except ValueError as e:
        print(f"kavach: {e}", file=sys.stderr)
        return 3
    scan_result = result.scan
    if args.json:
        out = {
            "url": args.url, "rule": args.rule, "fixed": result.fixed,
            "pages": result.pages,
            "occurrences": len(result.occurrences),
            "grade": scan_result.grade, "score": scan_result.score,
        }
        print(json.dumps(out, indent=2))
    elif result.fixed:
        scope = f" on {args.page}" if args.page else ""
        print(f"FIXED: {args.rule} is no longer found{scope} "
              f"(grade {scan_result.grade}, score {scan_result.score})")
    else:
        scope = f" on {args.page}" if args.page else ""
        print(f"STILL PRESENT: {args.rule} found "
              f"{len(result.occurrences)} time(s){scope} "
              f"(grade {scan_result.grade}, score {scan_result.score})")
        for page in result.pages:
            print(f"  {page}")
    return 0 if result.fixed else 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "verify":
        return verify_main(argv[1:])
    return scan_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
