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


GRADE_COLORS = {"A": "#4c1", "B": "#97ca00", "C": "#dfb317",
                "D": "#fe7d37", "F": "#e05d44"}

SEVERITY_COLORS = {"critical": "#b91c1c", "high": "#ea580c",
                   "medium": "#ca8a04", "low": "#6d28d9", "info": "#475569"}


def badge_svg(grade: str) -> str:
    """A small shields.io-style badge: kavach | GRADE."""
    color = GRADE_COLORS[grade]
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="20" '
        'role="img" aria-label="kavach: grade ' + grade + '">'
        '<rect width="96" height="20" rx="3" fill="#555"/>'
        '<rect x="56" width="40" height="20" rx="3" fill="' + color + '"/>'
        '<rect x="56" width="40" height="20" fill="' + color + '"/>'
        '<rect width="96" height="20" rx="3" fill="none"/>'
        '<g fill="#fff" font-family="Verdana,sans-serif" font-size="11">'
        '<text x="8" y="14">kavach</text>'
        '<text x="72" y="14" text-anchor="middle" font-weight="bold">'
        + grade + '</text></g></svg>')


def to_html(result: ScanResult) -> str:
    """A self-contained HTML report (inline CSS, no external files)."""
    color = GRADE_COLORS[result.grade]
    rows = []
    order = ("critical", "high", "medium", "low", "info")
    for severity in order:
        for f in result.findings:
            if f.severity != severity:
                continue
            rows.append(
                f'<section class="finding {severity}">'
                f'<h3><span class="sev" style="background:'
                f'{SEVERITY_COLORS[severity]}">{severity}</span> '
                f'{f.title} <code>{f.rule}</code></h3>'
                f'<p>{f.message}</p>'
                + (f'<p class="ev">Evidence: <code>{f.evidence}</code></p>'
                   if f.evidence else '')
                + f'<p class="fix">Fix: {f.fix}</p>'
                + (f'<p class="ow">OWASP: {f.owasp}</p>' if f.owasp else '')
                + '</section>')
    counts = result.counts
    counts_text = ", ".join(f"{n} {s}" for s, n in counts.items() if n) \
        or "none"
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        f'<title>Kavach scan — {result.url}</title><style>'
        'body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem '
        'auto;padding:0 1rem;color:#1e293b;background:#f8fafc}'
        '.grade{display:flex;align-items:center;gap:1rem}'
        '.badge{font-size:3rem;font-weight:800;color:#fff;border-radius:'
        '.5rem;padding:.2rem 1rem}'
        '.finding{background:#fff;border:1px solid #e2e8f0;border-radius:'
        '.5rem;padding:1rem;margin:.75rem 0}'
        '.sev{color:#fff;border-radius:.25rem;padding:.1rem .4rem;'
        'font-size:.8rem;text-transform:uppercase}'
        'code{background:#f1f5f9;padding:.1rem .3rem;border-radius:.25rem}'
        '.fix{font-weight:600}.ev,.ow{color:#64748b;font-size:.9rem}'
        'footer{color:#64748b;font-size:.9rem;margin-top:2rem}'
        '</style></head><body>'
        f'<h1>Kavach scan</h1><p>{result.url}</p>'
        f'<div class="grade"><span class="badge" style="background:'
        f'{color}">{result.grade}</span><span>score {result.score}/100<br>'
        f'Findings: {counts_text}<br>{result.requests_made} requests, '
        f'{result.duration_s}s</span></div>'
        + "".join(rows) +
        f'<footer>{result.disclaimer}</footer></body></html>')
