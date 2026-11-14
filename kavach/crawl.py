"""Link extraction for the crawler: same-origin HTML pages only.

A page is a crawl candidate when it is on the same origin (scheme +
host + port), is an http(s) URL, and does not point at a static asset
(images, styles, scripts, documents, archives). Fragments are stripped
and duplicates removed, so the same page is never queued twice.
"""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

SKIP_EXTENSIONS = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".pdf", ".zip", ".gz", ".xml", ".json", ".woff",
    ".woff2", ".ttf", ".mp4", ".mp3", ".webm", ".avi", ".mov", ".doc",
    ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rss", ".atom",
)

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "ftp:",
                "file:", "#")


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.links.append(value)


def extract_links(html: str, base_url: str) -> list[str]:
    """All crawlable same-origin links on a page, in first-seen order."""
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    base = urlsplit(base_url)
    origin = (base.scheme, base.netloc)
    seen: set[str] = set()
    out: list[str] = []
    for raw in parser.links:
        raw = raw.strip()
        if not raw or any(raw.lower().startswith(s) for s in SKIP_SCHEMES):
            continue
        absolute = urljoin(base_url, raw)
        parts = urlsplit(absolute)
        if (parts.scheme, parts.netloc) != origin:
            continue
        if parts.scheme not in ("http", "https"):
            continue
        if parts.path.lower().endswith(SKIP_EXTENSIONS):
            continue
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path,
                            parts.query, ""))
        if clean in seen or clean == base_url:
            continue
        seen.add(clean)
        out.append(clean)
    return out
