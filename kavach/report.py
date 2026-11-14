"""Plain-text (and JSON-ready) scan report."""
from __future__ import annotations

import json

from .model import ScanResult


def to_dict(result: ScanResult) -> dict:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "score": result.score,
        "grade": result.grade,
        "requests_made": result.requests_made,
        "duration_s": result.duration_s,
        "counts": result.counts,
        "findings": [
            {"rule": f.rule, "severity": f.severity, "title": f.title,
             "message": f.message, "fix": f.fix, "evidence": f.evidence,
             "owasp": f.owasp}
            for f in result.findings],
        "disclaimer": result.disclaimer,
    }


def to_text(result: ScanResult) -> str:
    lines = [f"Kavach scan: {result.url}",
             f"Grade {result.grade} — score {result.score}/100 "
             f"({result.requests_made} requests, {result.duration_s}s)"]
    if result.final_url != result.url:
        lines.append(f"Final URL: {result.final_url}")
    counts = result.counts
    counts_text = ", ".join(
        f"{n} {s}" for s, n in counts.items() if n) or "none"
    lines.append("Findings: " + counts_text)
    for f in result.findings:
        lines.append("")
        lines.append(f"[{f.severity}] {f.title} ({f.rule})")
        lines.append(f"  {f.message}")
        if f.evidence:
            lines.append(f"  Evidence: {f.evidence}")
        lines.append(f"  Fix: {f.fix}")
        if f.owasp:
            lines.append(f"  OWASP: {f.owasp}")
    lines.append("")
    lines.append(result.disclaimer)
    return "\n".join(lines) + "\n"


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), ensure_ascii=False, indent=1)
