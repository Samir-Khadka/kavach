"""Fix verification: re-scan and confirm a specific finding is gone.

The loop is prioritise → fix → verify. After fixing a finding (say,
adding HSTS), run `kavach verify <url> --rule missing_hsts` and get a
plain answer: FIXED, or STILL PRESENT with the pages it is still on.
A rule name that Kavach cannot produce is rejected up front, so a
typo does not scan for something that can never appear.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .checks import KNOWN_RULES
from .http import Session
from .model import Finding, ScanResult
from .scanner import scan

ALL_RULES = KNOWN_RULES | {"unreachable"}


@dataclass
class VerifyResult:
    rule: str
    fixed: bool
    occurrences: list[Finding] = field(default_factory=list)
    scan: ScanResult | None = None

    @property
    def pages(self) -> list[str]:
        seen: list[str] = []
        for f in self.occurrences:
            if f.page and f.page not in seen:
                seen.append(f.page)
        return seen


def verify(url: str, rule: str, page: str | None = None,
           lang: str = "en", verify_tls: bool = True,
           max_pages: int = 1, delay: float = 0.2,
           session: Session | None = None,
           history_dir: str | None = None) -> VerifyResult:
    """Re-scan and check whether `rule` is still present. Raises
    ValueError for an unknown rule name. `page` restricts the check
    to one page (the finding may be fixed there and present elsewhere)."""
    if rule not in ALL_RULES:
        raise ValueError(
            f"unknown rule {rule!r} — run `kavach verify` with one of: "
            + ", ".join(sorted(ALL_RULES)))
    result = scan(url, lang=lang, verify_tls=verify_tls,
                  max_pages=max_pages, delay=delay, session=session,
                  history_dir=history_dir)
    occurrences = [f for f in result.findings if f.rule == rule]
    if page is not None:
        occurrences = [f for f in occurrences if f.page == page]
    return VerifyResult(rule=rule, fixed=not occurrences,
                        occurrences=occurrences, scan=result)
