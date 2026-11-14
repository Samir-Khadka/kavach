"""Scheduled report email: tell the owner when a grade drops.

A scan on a schedule (a cron, or the weekly GitHub Action) is only
useful if someone reads it. `--email` sends the report when it
matters: by default only when the grade or score fell since the last
scan of that URL. `--notify-on change` also emails on any change
(new or fixed findings); `--notify-on always` emails every run.

SMTP settings come from the environment only — never from a file or
the command line, so a password never lands in a shell history or a
log:

    KAVACH_SMTP_HOST   (e.g. smtp.gmail.com)
    KAVACH_SMTP_PORT   (default 587; 465 uses implicit TLS)
    KAVACH_SMTP_USER   (e.g. you@gmail.com)
    KAVACH_SMTP_PASS   (for Gmail, an app password — not the account
                        password; Google account → Security → App
                        passwords)
    KAVACH_SMTP_FROM   (default: the SMTP user)
    KAVACH_NOTIFY_TO   (who gets the report)

A failed send is reported on stderr and never changes the scan's
exit code — the scan result is the truth, the email is a courtesy.
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from urllib.parse import urlsplit

from .model import ScanResult
from .report import to_html, to_text

GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

MODES = ("drop", "change", "always")


def should_notify(result: ScanResult, mode: str = "drop") -> bool:
    """Whether this scan is worth an email, given the mode and the
    diff against the previous scan (result.diff, None on a first
    scan)."""
    if mode not in MODES:
        raise ValueError(f"unknown notify mode {mode!r} "
                         f"(expected one of {', '.join(MODES)})")
    if mode == "always":
        return True
    diff = result.diff
    if diff is None:
        return False  # nothing to compare with — no regression to report
    if mode == "change":
        return diff.has_changes
    # drop: the score fell, or the grade got worse
    return (diff.current_score < diff.previous_score
            or GRADE_RANK[diff.current_grade]
            > GRADE_RANK[diff.previous_grade])


def build_message(result: ScanResult, to_addr: str,
                  from_addr: str) -> EmailMessage:
    """The report as a multipart email: plain text + HTML."""
    host = urlsplit(result.url).hostname or result.url
    diff = result.diff
    if diff is not None:
        subject = (f"Kavach: {host} grade {diff.previous_grade} → "
                   f"{diff.current_grade} (score {diff.previous_score} "
                   f"→ {diff.current_score})")
    else:
        subject = (f"Kavach: {host} grade {result.grade} "
                   f"(score {result.score})")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(to_text(result))
    msg.add_alternative(to_html(result), subtype="html")
    return msg


def send_message(msg: EmailMessage, host: str, port: int,
                 user: str | None, password: str | None) -> None:
    """Send via SMTP. Port 465 uses implicit TLS; anything else uses
    STARTTLS. Logs in only when a user is given."""
    if port == 465:
        smtp = smtplib.SMTP_SSL(host, port, timeout=30)
    else:
        smtp = smtplib.SMTP(host, port, timeout=30)
        smtp.starttls()
    try:
        if user:
            smtp.login(user, password or "")
        smtp.send_message(msg)
    finally:
        smtp.quit()


def config_from_env() -> dict | None:
    """SMTP settings from the environment, or None when the host or
    the recipient is missing (so --email can fail with a clear
    message instead of a connection error)."""
    host = os.environ.get("KAVACH_SMTP_HOST", "").strip()
    to_addr = os.environ.get("KAVACH_NOTIFY_TO", "").strip()
    if not host or not to_addr:
        return None
    user = os.environ.get("KAVACH_SMTP_USER", "").strip()
    return {
        "host": host,
        "port": int(os.environ.get("KAVACH_SMTP_PORT", "587")),
        "user": user or None,
        "password": os.environ.get("KAVACH_SMTP_PASS") or None,
        "from_addr": (os.environ.get("KAVACH_SMTP_FROM", "").strip()
                      or user or "kavach@localhost"),
        "to_addr": to_addr,
    }
