"""Scheduled report email: when to send, what it contains, and that
it is only sent when the grade actually drops."""
from __future__ import annotations

import json
from unittest import mock

import pytest

from kavach.cli import main as cli_main
from kavach.demo_server import serve_all
from kavach.history import DiffResult, save_scan
from kavach.model import Finding, ScanResult
from kavach.notify import build_message, config_from_env, send_message, \
    should_notify
from kavach.scanner import scan


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def _result(grade="F", score=0, diff=None, url="https://example.com"):
    return ScanResult(url=url, final_url=url, findings=[], score=score,
                      grade=grade, requests_made=1, duration_s=0.1,
                      lang="en", disclaimer="", diff=diff)


def _diff(prev_grade="A", prev_score=95, curr_grade="F", curr_score=0):
    return DiffResult(previous_at="2026-11-14T00:00:00+00:00",
                      previous_grade=prev_grade,
                      previous_score=prev_score,
                      current_grade=curr_grade,
                      current_score=curr_score)


def test_drop_mode_sends_on_a_grade_drop():
    assert should_notify(_result(diff=_diff()), "drop")


def test_drop_mode_sends_on_a_score_fall_with_the_same_grade():
    # 85 → 82 is still a B, but the score fell — worth knowing about
    diff = _diff(prev_grade="B", prev_score=85,
                 curr_grade="B", curr_score=82)
    assert should_notify(_result(grade="B", score=82, diff=diff), "drop")


def test_drop_mode_stays_silent_on_an_improvement():
    diff = _diff(prev_grade="F", prev_score=0,
                 curr_grade="B", curr_score=82)
    assert not should_notify(_result(grade="B", score=82, diff=diff),
                             "drop")


def test_drop_mode_stays_silent_with_no_previous_scan():
    assert not should_notify(_result(), "drop")


def test_change_mode_sends_on_any_difference():
    diff = _diff(prev_grade="B", prev_score=82,
                 curr_grade="B", curr_score=82)
    diff.new_findings = [Finding(rule="missing_csp", severity="medium",
                                 title="t", message="m", fix="f")]
    assert should_notify(_result(grade="B", score=82, diff=diff),
                         "change")
    assert not should_notify(_result(grade="B", score=82,
                                     diff=_diff(prev_grade="B",
                                                prev_score=82,
                                                curr_grade="B",
                                                curr_score=82)),
                             "change")


def test_always_mode_sends_even_on_a_first_scan():
    assert should_notify(_result(), "always")


def test_unknown_mode_raises():
    with pytest.raises(ValueError, match="unknown notify mode"):
        should_notify(_result(), "sometimes")


def test_build_message_subject_and_parts(demo):
    vuln_url, _, _ = demo
    result = scan(vuln_url)
    result.diff = _diff()
    msg = build_message(result, "samir@example.com", "kavach@example.com")
    assert "grade A → F" in msg["Subject"]
    assert "score 95 → 0" in msg["Subject"]
    assert msg["To"] == "samir@example.com"
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    assert plain is not None and "Grade F" in plain.get_content()
    # the HTML report renders the grade as a badge, not the words
    # "Grade F" — check the badge letter and the score instead
    assert html is not None
    html_body = html.get_content()
    assert ">F</span>" in html_body and "score 0/100" in html_body


def test_build_message_without_a_previous_scan():
    msg = build_message(_result(), "samir@example.com",
                        "kavach@example.com")
    assert "grade F (score 0)" in msg["Subject"]


def test_send_message_uses_starttls_and_logs_in():
    msg = build_message(_result(), "samir@example.com",
                        "kavach@example.com")
    with mock.patch("kavach.notify.smtplib.SMTP") as smtp_cls:
        send_message(msg, "smtp.example.com", 587, "user", "pass")
        smtp = smtp_cls.return_value
        smtp.starttls.assert_called_once_with()
        smtp.login.assert_called_once_with("user", "pass")
        smtp.send_message.assert_called_once_with(msg)
        smtp.quit.assert_called_once_with()


def test_send_message_uses_implicit_tls_on_port_465():
    msg = build_message(_result(), "samir@example.com",
                        "kavach@example.com")
    with mock.patch("kavach.notify.smtplib.SMTP_SSL") as ssl_cls, \
            mock.patch("kavach.notify.smtplib.SMTP") as smtp_cls:
        send_message(msg, "smtp.example.com", 465, "user", "pass")
        ssl_cls.assert_called_once_with("smtp.example.com", 465,
                                        timeout=30)
        smtp_cls.assert_not_called()


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("KAVACH_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("KAVACH_SMTP_PORT", "465")
    monkeypatch.setenv("KAVACH_SMTP_USER", "samir@gmail.com")
    monkeypatch.setenv("KAVACH_SMTP_PASS", "app-password")
    monkeypatch.setenv("KAVACH_NOTIFY_TO", "samir@example.com")
    config = config_from_env()
    assert config["host"] == "smtp.gmail.com"
    assert config["port"] == 465
    assert config["from_addr"] == "samir@gmail.com"
    assert config["to_addr"] == "samir@example.com"


def test_config_from_env_returns_none_without_host_or_recipient(
        monkeypatch):
    monkeypatch.delenv("KAVACH_SMTP_HOST", raising=False)
    monkeypatch.setenv("KAVACH_NOTIFY_TO", "samir@example.com")
    assert config_from_env() is None


def _seed_history(history_dir, url, grade, score):
    """A previous scan of this URL, stored the way the scanner does."""
    result = ScanResult(url=url, final_url=url, findings=[], score=score,
                        grade=grade, requests_made=1, duration_s=0.1,
                        lang="en", disclaimer="")
    save_scan(history_dir, result)


def test_cli_email_sent_when_the_grade_drops(demo, tmp_path, monkeypatch):
    vuln_url, _, _ = demo
    history = tmp_path / "history"
    _seed_history(history, vuln_url, "A", 95)
    monkeypatch.setenv("KAVACH_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("KAVACH_NOTIFY_TO", "samir@example.com")
    with mock.patch("kavach.notify.smtplib.SMTP") as smtp_cls:
        code = cli_main([vuln_url, "--email",
                         "--history-dir", str(history)])
        # the seeded history grades A, this scan grades F — the drop
        # sends an email, and the scan still exits with its own code
        smtp_cls.return_value.send_message.assert_called_once()
        assert code == 2  # the scan itself still grades F


def test_cli_email_not_sent_when_nothing_dropped(
        demo, tmp_path, monkeypatch):
    vuln_url, _, _ = demo
    history = tmp_path / "history"
    _seed_history(history, vuln_url, "F", 0)
    monkeypatch.setenv("KAVACH_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("KAVACH_NOTIFY_TO", "samir@example.com")
    with mock.patch("kavach.notify.smtplib.SMTP") as smtp_cls:
        code = cli_main([vuln_url, "--email",
                         "--history-dir", str(history)])
        smtp_cls.return_value.send_message.assert_not_called()
        assert code == 2


def test_cli_email_without_smtp_config_warns_and_does_not_fail(
        demo, tmp_path, monkeypatch, capsys):
    vuln_url, _, _ = demo
    monkeypatch.delenv("KAVACH_SMTP_HOST", raising=False)
    monkeypatch.delenv("KAVACH_NOTIFY_TO", raising=False)
    code = cli_main([vuln_url, "--email",
                     "--history-dir", str(tmp_path / "history")])
    assert code == 2
    assert "KAVACH_SMTP_HOST" in capsys.readouterr().err
