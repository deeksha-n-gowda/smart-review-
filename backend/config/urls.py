"""
config/urls.py — Root URL Configuration
==========================================
Routes:
    /                   → frontend/index.html  (dashboard)
    /review.html        → frontend/review.html (code review editor)
    /api/v1/            → REST API (api app)
    /admin/             → Django admin
    /css|js|assets/...  → Serves frontend sub-files (all environments)
    /media/...          → Serves uploaded files (all environments)

There is no reverse proxy in this deployment: Django (gunicorn, with
WhiteNoise for /static/) is the single public web server, so the frontend
and media routes are registered regardless of DEBUG.
"""

from pathlib import Path
from django.contrib import admin
from django.urls import path, re_path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.http import HttpResponse, Http404

def _find_frontend_dir() -> Path:
    """Locate the frontend/ directory across local and container layouts.

    Local checkout:  <repo>/backend/config/urls.py  → <repo>/frontend
    Docker image:    /app/config/urls.py            → /app/frontend
                     (Dockerfile: COPY frontend/ /app/frontend/)
    """
    candidates = [
        Path(settings.BASE_DIR).parent / "frontend",  # repo checkout
        Path(settings.BASE_DIR) / "frontend",         # container (/app/frontend)
        Path(__file__).resolve().parents[2] / "frontend",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


FRONTEND_DIR = _find_frontend_dir()


def _frontend_file(filename):
    """Factory: returns a view that reads and serves a frontend HTML file."""
    def _view(request):
        filepath = FRONTEND_DIR / filename
        if not filepath.exists():
            raise Http404(f"Frontend file not found: {filename}")
        ext_map = {
            ".html": "text/html; charset=utf-8",
            ".css":  "text/css; charset=utf-8",
            ".js":   "application/javascript; charset=utf-8",
            ".svg":  "image/svg+xml",
        }
        ext = filepath.suffix.lower()
        content_type = ext_map.get(ext, "text/plain")
        response = HttpResponse(filepath.read_bytes(), content_type=content_type)
        response["Cache-Control"] = "no-cache"
        return response
    return _view


urlpatterns = [
    # Django admin
    path("admin/", admin.site.urls),

    # REST API
    path("api/v1/", include("api.urls")),

    # Frontend HTML pages (served from /frontend/ directory)
    path("",            _frontend_file("index.html"),  name="home"),
    path("review.html", _frontend_file("review.html"), name="review"),

    # Frontend assets and uploads — served in every environment (no nginx in
    # front of gunicorn; WhiteNoise handles /static/ when DEBUG=False).
    re_path(
        r"^(?P<path>(?:css|js|assets)/.+)$",
        serve,
        {"document_root": str(FRONTEND_DIR)},
    ),
    re_path(
        r"^media/(?P<path>.+)$",
        serve,
        {"document_root": str(settings.MEDIA_ROOT)},
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
