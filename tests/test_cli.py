"""CLI tests: exit codes 0 (A/B), 1 (C/D), 2 (F), 3 (bad URL)."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from kavach.cli import main
from kavach.demo_server import serve_both


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, stop = serve_both()
    yield vuln_url, secure_url
    stop()


def test_cli_vulnerable_exits_2(demo, capsys):
    vuln_url, _ = demo
    assert main([vuln_url]) == 2
    assert "Grade F" in capsys.readouterr().out


def test_cli_hardened_exits_0(demo, capsys):
    _, secure_url = demo
    assert main([secure_url, "--insecure"]) == 0
    assert "Grade A" in capsys.readouterr().out


def test_cli_bad_url_exits_3():
    assert main(["ftp://example.com/"]) == 3
    assert main([""]) == 3


def test_cli_unresolvable_host_exits_2():
    assert main(["not-a-url"]) == 2  # valid shape, unreachable host


def test_cli_json_is_valid(demo, capsys):
    vuln_url, _ = demo
    assert main([vuln_url, "--json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] == "F" and "findings" in data


def test_cli_module_entrypoint(demo):
    vuln_url, _ = demo
    proc = subprocess.run([sys.executable, "-m", "kavach", vuln_url],
                          capture_output=True, text=True)
    assert proc.returncode == 2
    assert "Grade F" in proc.stdout
