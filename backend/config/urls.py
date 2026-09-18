"""
config/urls.py — Root URL Configuration (Phase 2 update)
==========================================================
Routes:
    /                   → frontend/index.html  (dashboard)
    /review.html        → frontend/review.html (code review editor)
    /api/v1/            → REST API (api app)
    /admin/             → Django admin
    /css|js|assets/...  → Serves frontend static sub-files in dev

In production, nginx serves /frontend/ as static files and only
proxies /api/v1/ and /admin/ to gunicorn.
"""

from pathlib import Path
from django.contrib import admin
from django.urls import path, re_path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.http import HttpResponse, Http404

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


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
]

# Development: serve /frontend/css/, /frontend/js/, /frontend/assets/
if settings.DEBUG:
    urlpatterns += [
        re_path(
            r"^(?P<path>(?:css|js|assets)/.+)$",
            serve,
            {"document_root": str(FRONTEND_DIR)},
        ),
    ]
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL,  document_root=settings.MEDIA_ROOT)
