#!/usr/bin/env python3
"""
serve_frontend.py — Standalone Dev Server for the Frontend
============================================================
Serves the /frontend/ directory over HTTP so you can preview the UI
without running the full Django backend.

In this mode the frontend automatically falls back to mock data
(see api.js → useMockData()) when the Django health check fails.

Usage:
    python serve_frontend.py           # Serves on http://localhost:5500
    python serve_frontend.py 8080      # Custom port
    python serve_frontend.py --open    # Opens browser automatically

This script is for development convenience only.
In production, use Django (python manage.py runserver) or nginx.
"""

import sys
import os
import threading
import webbrowser
import http.server
import socketserver
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
DEFAULT_PORT = 5500

# ── Custom Handler ────────────────────────────────────────────────────────────

class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    """
    Serves files from /frontend/ with correct MIME types.
    Also adds CORS headers so the frontend can call Django on port 8000.
    Handles SPA-style routing: unknown paths fall back to index.html.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def end_headers(self):
        # CORS — allow calls to the Django backend on any localhost port
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        # No caching in dev
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def guess_type(self, path):
        """Extend MIME type guessing for modern file types, safely handling Windows Registry bugs."""
        # 1. Call super() safely without immediately unpacking
        res = super().guess_type(path)
        
        # 2. Extract the mime type depending on what Windows returned
        if isinstance(res, tuple) and len(res) >= 1:
            mime = res[0]
        elif isinstance(res, str):
            mime = res
        else:
            mime = None

        # 3. Apply your custom modern extension overrides and fallbacks
        ext = Path(str(path)).suffix.lower()
        extras = {
            ".js": "application/javascript",
            ".mjs": "application/javascript",
            ".css": "text/css",
            ".html": "text/html",
            ".svg": "image/svg+xml",
            ".woff2": "font/woff2",
        }

        # If Windows failed or if it's one of our specific modern formats, grab from extras
        if ext in extras:
            mime = extras[ext]
        elif not mime:
            mime = "application/octet-stream"

        # The parent SimpleHTTPRequestHandler expects just a string returned from guess_type
        return mime

    def do_GET(self):
        # Serve index.html for unknown paths (SPA fallback)
        requested = Path(FRONTEND_DIR, self.path.lstrip("/").split("?")[0])
        if not requested.exists() and not self.path.startswith("/api"):
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, fmt, *args):
        # Suppress noisy 304 / favicon requests in the console
        if args and (args[1] == "304" or "favicon" in str(args[0])):
            return
        print(f"  {self.address_string()} → {fmt % args}")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    port      = DEFAULT_PORT
    auto_open = False

    for arg in sys.argv[1:]:
        if arg == "--open":
            auto_open = True
        elif arg.isdigit():
            port = int(arg)

    if not FRONTEND_DIR.exists():
        print(f"Error: frontend directory not found at {FRONTEND_DIR}")
        sys.exit(1)

    with socketserver.TCPServer(("", port), FrontendHandler) as httpd:
        httpd.allow_reuse_address = True
        url = f"http://localhost:{port}"

        print()
        print("╔══════════════════════════════════════════════════════╗")
        print("║         Smart Review —  Dev Server               ║")
        print("╠══════════════════════════════════════════════════════╣")
        print(f"║  Serving:   {FRONTEND_DIR}")
        print(f"║  URL:       {url}")
        print(f"║  Review:    {url}/review.html")
        print("╠══════════════════════════════════════════════════════╣")
        print("║  ℹ  Django backend not required — mock data active.  ║")
        print("║     Start Django on :8000 for live API data.         ║")
        print("╠══════════════════════════════════════════════════════╣")
        print("║  Press Ctrl+C to stop                                ║")
        print("╚══════════════════════════════════════════════════════╝")
        print()

        if auto_open:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")


if __name__ == "__main__":
    main()
