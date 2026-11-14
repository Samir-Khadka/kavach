"""Scan history: remember the last scan of each URL, and report what
changed since then.

One file per URL in the history directory, named from the host plus a
short hash of the URL (so two URLs on the same host never collide).
Each scan overwrites its file with the new result, so the history is
one file per URL and never grows without bound. The diff compares
findings by (rule, evidence, page): a finding present now but absent
before is new, one absent now but present before is fixed, and the
grade and score change are reported alongside.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .model import Finding, ScanResult


@dataclass
class DiffResult:
    previous_at: str
    previous_grade: str
    previous_score: int
    current_grade: str
    current_score: int
    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)

    @property
    def score_change(self) -> int:
        return self.current_score - self.previous_score

    @property
    def grade_change(self) -> str:
        if self.current_grade == self.previous_grade:
            return ""
        return f"{self.previous_grade} → {self.current_grade}"

    @property
    def has_changes(self) -> bool:
        return bool(self.new_findings or self.fixed_findings
                    or self.grade_change)


def history_path(history_dir: str | Path, url: str) -> Path:
    host = urlsplit(url).hostname or "site"
    host = "".join(c if c.isalnum() or c in "-." else "-" for c in host)
    digest = hashlib.sha1(url.encode()).hexdigest()[:8]
    return Path(history_dir) / f"{host}-{digest}.json"


def save_scan(history_dir: str | Path, result: ScanResult) -> Path:
    """Write this scan as the latest for its URL. Returns the file."""
    from .report import to_dict
    path = history_path(history_dir, result.url)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = to_dict(result)
    data["scanned_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def load_previous(history_dir: str | Path, url: str) -> dict | None:
    """The previous scan's stored dict for this URL, or None."""
    path = history_path(history_dir, url)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _key(f: dict) -> tuple[str, str, str]:
    return (f.get("rule", ""), f.get("evidence", ""),
            f.get("page", ""))


def _from_dict(data: dict) -> Finding:
    return Finding(rule=data.get("rule", ""), severity=data.get("severity", ""),
                   title=data.get("title", ""), message=data.get("message", ""),
                   fix=data.get("fix", ""), evidence=data.get("evidence", ""),
                   owasp=data.get("owasp", ""), page=data.get("page", ""))


def diff_results(previous: dict, current: ScanResult) -> DiffResult:
    """What changed between a stored scan and the current one."""
    prev_findings = {_key(f): f for f in previous.get("findings", [])}
    curr_findings = {(f.rule, f.evidence, f.page): f
                     for f in current.findings}
    new = [curr_findings[k] for k in curr_findings
           if k not in prev_findings]
    fixed = [_from_dict(prev_findings[k]) for k in prev_findings
             if k not in curr_findings]
    return DiffResult(
        previous_at=previous.get("scanned_at", ""),
        previous_grade=previous.get("grade", "?"),
        previous_score=previous.get("score", 0),
        current_grade=current.grade,
        current_score=current.score,
        new_findings=new,
        fixed_findings=fixed,
    )
