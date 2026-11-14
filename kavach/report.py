"""Plain-text (and JSON-ready) scan report."""
from __future__ import annotations

import json

from .model import ScanResult


def to_dict(result: ScanResult) -> dict:
    diff = None
    if result.diff is not None:
        d = result.diff
        diff = {
            "previous_at": d.previous_at,
            "previous_grade": d.previous_grade,
            "previous_score": d.previous_score,
            "score_change": d.score_change,
            "grade_change": d.grade_change,
            "new_findings": [
                {"rule": f.rule, "severity": f.severity,
                 "title": f.title, "page": f.page}
                for f in d.new_findings],
            "fixed_findings": [
                {"rule": f.rule, "severity": f.severity,
                 "title": f.title, "page": f.page}
                for f in d.fixed_findings],
        }
    return {
        "url": result.url,
        "final_url": result.final_url,
        "score": result.score,
        "grade": result.grade,
        "requests_made": result.requests_made,
        "duration_s": result.duration_s,
        "pages": result.pages,
        "form_pages": result.form_pages,
        "diff": diff,
        "counts": result.counts,
        "findings": [
            {"rule": f.rule, "severity": f.severity, "title": f.title,
             "message": f.message, "fix": f.fix, "evidence": f.evidence,
             "owasp": f.owasp, "page": f.page}
            for f in result.findings],
        "disclaimer": result.disclaimer,
    }


def to_text(result: ScanResult) -> str:
    lines = [f"Kavach scan: {result.url}",
             f"Grade {result.grade} — score {result.score}/100 "
             f"({result.requests_made} requests, {result.duration_s}s)"]
    if result.final_url != result.url:
        lines.append(f"Final URL: {result.final_url}")
    if len(result.pages) > 1:
        lines.append(f"Pages scanned: {len(result.pages)}")
        for p in result.pages:
            via = " (via form)" if p in result.form_pages else ""
            lines.append(f"  {p}{via}")
    counts = result.counts
    counts_text = ", ".join(
        f"{n} {s}" for s, n in counts.items() if n) or "none"
    lines.append("Findings: " + counts_text)
    if result.diff is not None:
        d = result.diff
        lines.append("")
        lines.append(f"Changes since last scan ({d.previous_at or 'unknown time'}):")
        change = d.grade_change or f"grade {d.previous_grade}"
        sign = "+" if d.score_change >= 0 else ""
        lines.append(f"  Score {d.previous_score} → {result.score} "
                     f"({sign}{d.score_change}), {change}")
        if d.new_findings:
            lines.append(f"  New: {len(d.new_findings)} finding(s)")
            for f in d.new_findings:
                page_note = f" on {f.page}" if f.page else ""
                lines.append(f"    + [{f.severity}] {f.title} "
                             f"({f.rule}){page_note}")
        if d.fixed_findings:
            lines.append(f"  Fixed: {len(d.fixed_findings)} finding(s)")
            for f in d.fixed_findings:
                page_note = f" on {f.page}" if f.page else ""
                lines.append(f"    - [{f.severity}] {f.title} "
                             f"({f.rule}){page_note}")
        if not d.has_changes:
            lines.append("  No changes.")
    for f in result.findings:
        lines.append("")
        page_note = f" on {f.page}" if len(result.pages) > 1 and f.page \
            else ""
        lines.append(f"[{f.severity}] {f.title} ({f.rule}){page_note}")
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
    diff_html = ""
    if result.diff is not None:
        d = result.diff
        sign = "+" if d.score_change >= 0 else ""
        change = d.grade_change or f"grade {d.previous_grade}"
        items = []
        for f in d.new_findings:
            page_note = (f' on <code>{f.page}</code>' if f.page else '')
            items.append(f'<li class="new">+ [{f.severity}] {f.title} '
                         f'<code>{f.rule}</code>{page_note}</li>')
        for f in d.fixed_findings:
            page_note = (f' on <code>{f.page}</code>' if f.page else '')
            items.append(f'<li class="fixed">− [{f.severity}] {f.title} '
                         f'<code>{f.rule}</code>{page_note}</li>')
        if not d.has_changes:
            items.append('<li>No changes since the last scan.</li>')
        diff_html = (
            f'<section class="diff"><h2>Changes since last scan '
            f'({d.previous_at or "unknown time"})</h2>'
            f'<p>Score {d.previous_score} → {result.score} '
            f'({sign}{d.score_change}), {change}</p>'
            f'<ul>{"".join(items)}</ul></section>')
    rows = []
    order = ("critical", "high", "medium", "low", "info")
    for severity in order:
        for f in result.findings:
            if f.severity != severity:
                continue
            page_note = (f'<p class="ev">Page: <code>{f.page}</code></p>'
                         if len(result.pages) > 1 and f.page else '')
            rows.append(
                f'<section class="finding {severity}">'
                f'<h3><span class="sev" style="background:'
                f'{SEVERITY_COLORS[severity]}">{severity}</span> '
                f'{f.title} <code>{f.rule}</code></h3>'
                f'<p>{f.message}</p>'
                + page_note
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
        f'{result.duration_s}s'
        + (f'<br>Pages scanned: {len(result.pages)}'
           if len(result.pages) > 1 else '')
        + '</span></div>'
        + diff_html
        + "".join(rows) +
        f'<footer>{result.disclaimer}</footer></body></html>')
