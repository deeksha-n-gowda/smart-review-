#!/usr/bin/env python3
"""Measure transferred weight + timing per page (checklist item 7: fast load).

    backend/venv/Scripts/python.exe scripts/measure_speed.py http://127.0.0.1:8000

Fetches each HTML page with gzip accepted (as a browser sends), then fetches
every asset the page references, and reports raw vs transferred bytes so the
gzip saving is visible. Exits 1 if a page exceeds the 500 KB budget or its
HTML takes over 1s server-side.
"""

import gzip
import io
import re
import sys
import time
import urllib.parse
import urllib.request

BUDGET_BYTES = 500 * 1024
HTML_BUDGET_S = 1.0
PAGES = ["/", "/faq.html", "/review.html"]
ASSET_ATTR = re.compile(r'(?:href|src)="([^"]+)"')
EXTENSIONS = (".css", ".js", ".png", ".svg", ".ico", ".woff", ".woff2", ".jpg")


def fetch(url, gzip_ok=True):
    headers = {"User-Agent": "smart-review-speedcheck"}
    if gzip_ok:
        headers["Accept-Encoding"] = "gzip, br"
    req = urllib.request.Request(url, headers=headers)
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        elapsed = time.perf_counter() - start
        encoding = (resp.headers.get("Content-Encoding") or "").lower()
        ctype = resp.headers.get("Content-Type", "")
    # urllib does not auto-decompress; transferred = what hit the wire.
    transferred = len(body)
    raw = body
    if encoding == "gzip":
        raw = gzip.decompress(body)
    elif encoding == "br":
        try:
            import brotli
            raw = brotli.decompress(body)
        except Exception:
            raw = body  # unknown to this interpreter; report wire bytes only
    return {
        "transferred": transferred,
        "raw": len(raw),
        "time": elapsed,
        "encoding": encoding,
        "type": ctype,
        # `raw` is always decompressed — this is what the HTML parser needs.
        "text": raw.decode("utf-8", "replace") if "html" in ctype else "",
    }


def assets_of(html, base):
    urls = set()
    for match in ASSET_ATTR.findall(html):
        if match.startswith(("http://", "https://", "#", "mailto:", "data:")):
            if not match.startswith(base):
                continue
        target = urllib.parse.urljoin(base, match)
        if target.endswith(EXTENSIONS) or "/assets/" in target or "/css/" in target \
                or "/js/" in target:
            urls.add(target)
    return sorted(urls)


def measure(base):
    base = base.rstrip("/")
    problems = []
    print(f"{'page':<16} {'html':>9} {'gz':>8} {'assets':>9} {'total':>9} {'time':>7}")
    for page in PAGES:
        url = base + page
        try:
            html = fetch(url)
        except Exception as exc:
            problems.append(f"{url} failed: {exc}")
            print(f"{page:<16} ERROR {exc}")
            continue

        asset_raw = asset_wire = 0
        slowest = 0.0
        count = 0
        for asset in assets_of(html["text"], url):
            try:
                info = fetch(asset)
            except Exception as exc:
                problems.append(f"{asset} failed: {exc}")
                continue
            asset_raw += info["raw"]
            asset_wire += info["transferred"]
            slowest = max(slowest, info["time"])
            count += 1

        total_wire = html["transferred"] + asset_wire
        total_raw = html["raw"] + asset_raw
        flag = ""
        if total_wire > BUDGET_BYTES:
            problems.append(f"{page} weight {total_wire // 1024} KB > "
                            f"{BUDGET_BYTES // 1024} KB budget")
            flag = "  <-- OVER BUDGET"
        if html["time"] > HTML_BUDGET_S:
            problems.append(f"{page} HTML took {html['time']:.2f}s "
                            f"(budget {HTML_BUDGET_S}s)")
            flag += "  <-- SLOW"

        print(f"{page:<16} {html['raw']:>9,} {html['transferred']:>8,} "
              f"{asset_wire:>9,} {total_wire:>9,} {html['time'] * 1000:>6.0f}ms"
              f"   ({count} assets, uncompressed {total_raw:,}{flag})")

    print()
    if problems:
        print("FAIL:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: every page under {BUDGET_BYTES // 1024} KB transferred, "
          f"HTML under {HTML_BUDGET_S}s")
    return 0


if __name__ == "__main__":
    sys.exit(measure(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"))
