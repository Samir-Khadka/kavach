"""FastAPI service: POST /scan with {"url": ..., "lang": "en"}.

Run it with:  uvicorn kavach.api:app --port 8000
Only scan sites you own or have explicit permission to test.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .auth import AuthError, login
from .report import to_dict
from .scanner import scan

app = FastAPI(title="Kavach", version="0.5.0",
              description="Web security scanner — only scan sites you own "
                          "or have explicit permission to test.")


class AuthRequest(BaseModel):
    auth_url: str = Field(..., examples=["https://example.com/login"])
    username: str
    password: str
    user_field: str | None = None
    password_field: str | None = None
    auth_check: str | None = None


class ScanRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"])
    lang: str = Field("en", pattern="^(en|ne)$")
    max_pages: int = Field(1, ge=1, le=20)
    auth: AuthRequest | None = None


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
    session = None
    if req.auth is not None:
        try:
            session, _ = login(req.auth.auth_url, req.auth.username,
                               req.auth.password,
                               user_field=req.auth.user_field,
                               password_field=req.auth.password_field,
                               auth_check=req.auth.auth_check)
        except AuthError as e:
            raise HTTPException(status_code=401, detail=f"login failed: {e}")
    return to_dict(scan(req.url, lang=req.lang,
                       max_pages=req.max_pages, session=session))
