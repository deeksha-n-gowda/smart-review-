"""
backend/config/frontend_views.py
==================================
In development, Django serves the /frontend/ HTML files directly
so you can work without a separate static file server.

In production, nginx (or similar) serves /frontend/ as static files,
and these views are never hit.

Registered in config/urls.py.
"""

import os
from pathlib import Path
from django.http import HttpResponse, Http404
from django.views import View


# Path to the /frontend/ directory (two levels up from /backend/config/)
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


class FrontendFileView(View):
    """
    Serves a file from the /frontend/ directory.
    Only active in development (DEBUG=True).

    Usage (in urls.py):
        path("", FrontendFileView.as_view(filename="index.html")),
    """
    filename = "index.html"

    def get(self, request, *args, **kwargs):
        from django.conf import settings
        if not settings.DEBUG:
            raise Http404("Frontend files are served by nginx in production.")

        filepath = FRONTEND_DIR / self.filename
        if not filepath.exists() or not filepath.is_file():
            raise Http404(f"Frontend file not found: {self.filename}")

        # Infer content type
        ext = filepath.suffix.lower()
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css":  "text/css; charset=utf-8",
            ".js":   "application/javascript; charset=utf-8",
            ".svg":  "image/svg+xml",
            ".png":  "image/png",
            ".ico":  "image/x-icon",
        }
        content_type = content_types.get(ext, "application/octet-stream")

        content = filepath.read_bytes()
        response = HttpResponse(content, content_type=content_type)

        # Cache-busting for development
        response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response["Pragma"]        = "no-cache"
        return response
