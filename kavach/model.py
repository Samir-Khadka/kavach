"""Data model: one finding, one scan result."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    message: str
    fix: str
    evidence: str = ""
    owasp: str = ""
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

    @property
    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out
