"""Data model: one finding, one scan result."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def grade_of(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    message: str
    fix: str
    evidence: str = ""
    owasp: str = ""
    page: str = ""  # the page the finding was found on ("" = seed page)
    details: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    url: str
    final_url: str
    findings: list[Finding]
    score: int
    grade: str
    requests_made: int
    duration_s: float
    lang: str = "en"
    disclaimer: str = ""
    pages: list[str] = field(default_factory=list)  # every page scanned
    form_pages: list[str] = field(default_factory=list)  # pages reached
    # by submitting a GET form (no link pointed at them)
    diff: object = None  # a history.DiffResult, or None when there is
    # no previous scan to compare with
    priorities: list = field(default_factory=list)  # ranked fix
    # actions (priorities.Priority): what to fix first, and the gain

    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out
