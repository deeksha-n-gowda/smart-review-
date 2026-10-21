#!/usr/bin/env python3
"""Crawl every page of the site and report broken links (checklist item 9).

    backend/venv/Scripts/python.exe scripts/check_links.py http://127.0.0.1:8000

Checks every href/src/og:url/twitter:image/link rel=icon found in the HTML,
resolves it against the page it was found on, and fails with exit code 1 if
anything returns a non-2xx/3xx status. External (http/https) links are
followed too, so the footer/API-doc links get verified as well.
"""

import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:")


class LinkCollector(HTMLParser):
    """Collects href/src everywhere, plus only the meta content values that
    actually hold URLs (og:image, og:url, twitter:image)."""

    URL_META = {"og:image", "og:url", "twitter:image"}

    def __init__(self):
        super().__init__()
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta":
            key = (attrs.get("property") or attrs.get("name") or "").lower()
            if key in self.URL_META and attrs.get("content"):
                self.links.add(attrs["content"].strip())
            return
        if tag == "link":
            # preconnect/dns-prefetch point at bare origins whose root 404s
            # by design (fonts.googleapis.com etc.) — not page links.
            rel = (attrs.get("rel") or "").lower().split()
            if rel and not ({"stylesheet", "icon", "apple-touch-icon",
                             "canonical", "alternate", "manifest"} & set(rel)):
                return
        if tag in ("a", "link", "img", "script", "iframe", "source"):
            for name in ("href", "src", "srcset"):
                value = attrs.get(name)
                if not value:
                    continue
                for part in value.split(","):  # srcset: "url 1x, url2 2x"
                    url = part.strip().split()[0]
                    if url:
                        self.links.add(url)


def check(base: str) -> int:
    base = base.rstrip("/")
    to_visit = [base + "/", base + "/faq.html", base + "/review.html"]
    seen_pages, results = set(), []

    while to_visit:
        url = to_visit.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)

        html = fetch(url)
        if html is None:
            # Non-HTML (API JSON etc.) — the status itself is the verdict.
            status = status_of(url)
            if status is None or status >= 400:
                results.append((url, f"PAGE FAILED ({status})", url))
            continue
        print(f"page {url}  200")

        collector = LinkCollector()
        try:
            collector.feed(html)
        except Exception as exc:  # malformed HTML shouldn't abort the crawl
            results.append((url, f"PARSE ERROR {exc}", url))
            continue

        for raw in sorted(collector.links):
            if raw.startswith(SKIP_SCHEMES) or raw.startswith("#"):
                continue
            target = urllib.parse.urljoin(url, raw)
            if not target.startswith(("http://", "https://")):
                continue

            internal = target.startswith(base)
            if not internal:
                # External links: one status check, never crawled.
                status = status_of(target)
                if status is None or status >= 400:
                    results.append((url, f"BROKEN ({status})", target))
                continue

            # Internal HTML pages get queued for crawling.
            if target.endswith((".html", "/")) and target not in seen_pages:
                to_visit.append(target)
                continue

            status = status_of(target)
            if status is None or status >= 400:
                results.append((url, f"BROKEN ({status})", target))

    print()
    if results:
        print(f"FAIL: {len(results)} problem(s):")
        for page, problem, target in results:
            print(f"  {problem:22} {target}\n      found in {page}")
        return 1
    print(f"OK: all links fine across {len(seen_pages)} pages")
    return 0


def status_of(url: str):
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "smart-review-linkcheck"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "smart-review-linkcheck"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read()
            if b"<html" not in body[:2000].lower():
                return None
            return body.decode("utf-8", "replace")
    except Exception:
        return None


if __name__ == "__main__":
    sys.exit(check(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"))
