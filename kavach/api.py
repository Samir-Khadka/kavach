"""FastAPI service: POST /scan with {"url": ..., "lang": "en"}.

Run it with:  uvicorn kavach.api:app --port 8000
Only scan sites you own or have explicit permission to test.
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .report import to_dict
from .scanner import scan

app = FastAPI(title="Kavach", version="0.3.0",
              description="Web security scanner — only scan sites you own "
                          "or have explicit permission to test.")


class ScanRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"])
    lang: str = Field("en", pattern="^(en|ne)$")
    max_pages: int = Field(1, ge=1, le=20)


class ScanResponse(BaseModel):
    url: str
    final_url: str
    score: int
    grade: str
    requests_made: int
    duration_s: float
    counts: dict
    pages: list
    findings: list
    disclaimer: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan_endpoint(req: ScanRequest) -> dict:
    return to_dict(scan(req.url, lang=req.lang,
                       max_pages=req.max_pages))
