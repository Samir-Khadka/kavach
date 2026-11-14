"""Fix prioritisation: which finding to fix first for the biggest
grade gain.

Each rule is one fix action, ranked by the score it gains when fixed
everywhere. The gain respects the same dedupe as the score: a missing
header on five pages is one fix worth 8 points, while a probe that
fires on three pages is three separate fixes worth 15 each. The
cumulative score and grade show where you land after fixing everything
up to that rank — computed from the unfloored score, so a site graded
F at 0 does not pretend one fix moves it to 50 when it does not.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import DEDUCTIONS, Finding
from .model import grade_of as _grade_of


def grade_of(score: int) -> str:
    return _grade_of(score)


@dataclass
class Priority:
    rank: int
    rule: str
    severity: str
    gain: int
    pages: list[str] = field(default_factory=list)
    fix: str = ""
    cumulative_score: int = 0
    cumulative_grade: str = "F"


def raw_score(findings: list[Finding]) -> int:
    """The score before the 0 floor: 100 minus the deductions for the
    unique issues (dedupe by rule + evidence, as in the score)."""
    seen: set[tuple[str, str]] = set()
    total = 0
    for f in findings:
        key = (f.rule, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        total += DEDUCTIONS[f.severity]
    return 100 - total


def prioritise(findings: list[Finding]) -> tuple[list[Priority], int, int]:
    """Ranked fix actions, the total gain from fixing everything, and
    the raw (unfloored) score. Empty when there is nothing to fix."""
    by_rule: dict[str, dict] = {}
    for f in findings:
        if f.severity == "info":
            continue  # info findings gain nothing — not a fix priority
        key = (f.rule, f.evidence)
        entry = by_rule.setdefault(f.rule, {
            "severity": f.severity, "fix": f.fix, "gain": 0,
            "pages": set(), "seen": set()})
        if f.page:
            entry["pages"].add(f.page)  # every page, even a duplicate
        if key in entry["seen"]:
            continue
        entry["seen"].add(key)
        entry["gain"] += DEDUCTIONS[f.severity]
    ranked = sorted(by_rule.items(),
                    key=lambda kv: (-kv[1]["gain"], kv[0]))
    raw = raw_score(findings)
    total_gain = sum(e["gain"] for _, e in ranked)
    priorities: list[Priority] = []
    gained = 0
    for i, (rule, e) in enumerate(ranked, start=1):
        gained += e["gain"]
        score = max(0, raw + gained)
        priorities.append(Priority(
            rank=i, rule=rule, severity=e["severity"], gain=e["gain"],
            pages=sorted(e["pages"]), fix=e["fix"],
            cumulative_score=score, cumulative_grade=grade_of(score)))
    return priorities, total_gain, raw
