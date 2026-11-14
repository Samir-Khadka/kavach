"""API tests (skipped when FastAPI is not installed)."""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from kavach.api import app  # noqa: E402
from kavach.demo_server import serve_all  # noqa: E402

client = TestClient(app)


@pytest.fixture(scope="module")
def demo():
    vuln_url, secure_url, mixed_url, stop = serve_all()
    yield vuln_url, secure_url, mixed_url
    stop()


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_endpoint(demo):
    vuln_url, _, _ = demo
    r = client.post("/scan", json={"url": vuln_url})
    assert r.status_code == 200
    data = r.json()
    assert data["grade"] == "F"
    assert data["counts"]["critical"] == 5
    assert all("fix" in f and "owasp" in f for f in data["findings"])


def test_scan_endpoint_rejects_bad_lang():
    r = client.post("/scan", json={"url": "https://example.com",
                                   "lang": "xx"})
    assert r.status_code == 422
