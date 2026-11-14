"""Kavach (कवच — "shield"): a web security scanner.

Point it at a URL you own or have permission to test. It checks the
OWASP Top 10 basics — security headers, TLS, cookies, CORS, exposed
sensitive files — plus two safe, non-destructive probes (an error-based
SQL-injection probe and a reflected-input probe), and grades the site
A–F with fix guidance in English or Nepali.

Safety rules, built in, not just documented:
- read-only GET requests only, no POST/PUT/DELETE, no destructive payloads;
- the probes use a single quote (SQL error detection) and one inert
  marker tag <kavach> (reflection detection) — nothing that executes;
- at most ~12 requests per scan, 5s timeout each, honest User-Agent;
- only scan sites you own or have explicit permission to test.
"""
from .scanner import ScanResult, grade_of, scan
from .model import Finding

__all__ = ["scan", "grade_of", "ScanResult", "Finding"]
