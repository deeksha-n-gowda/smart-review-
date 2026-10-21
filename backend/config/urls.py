"""
config/urls.py — Root URL Configuration
=================================================================
Routes:
    /                   → frontend/index.html  (dashboard)
    /review.html        → frontend/review.html (code review editor)
    /faq.html           → frontend/faq.html    (AI code review guide + FAQ)
    /robots.txt         → generated (points crawlers at the sitemap)
    /sitemap.xml        → generated from the request host
    /api/v1/            → REST API (api app)
    /admin/             → Django admin
    /css|js|assets/...  → Serves frontend sub-files (all environments)
    /media/...          → Serves uploaded files (all environments)

There is no reverse proxy in this deployment: Django (gunicorn, with
WhiteNoise for /static/) is the single public web server, so the frontend
and media routes are registered regardless of DEBUG.
"""

from datetime import date
from pathlib import Path
from django.contrib import admin
from django.urls import path, re_path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.http import HttpResponse, HttpResponseBase, Http404
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView


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

# Placeholder replaced with the deployment's own origin when a frontend file
# is served. Keeps <link rel="canonical"> / Open Graph URLs correct on
# Render, on localhost and on any custom domain — no rebuild needed.
SITE_URL_PLACEHOLDER = b"__SITE_URL__"


def _site_url(request) -> str:
    """Absolute origin of this deployment, e.g. https://smart-review.onrender.com

    Derived from the incoming request (honouring X-Forwarded-Proto, which
    Render's proxy sets) so it is always correct.
    """
    return request.build_absolute_uri("/").rstrip("/")


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
        content = filepath.read_bytes()
        if SITE_URL_PLACEHOLDER in content:
            content = content.replace(
                SITE_URL_PLACEHOLDER, _site_url(request).encode("utf-8")
            )
        response = HttpResponse(content, content_type=content_type)
        response["Cache-Control"] = "no-cache"
        return response
    return _view


def robots_txt(request):
    """robots.txt — lets crawlers index the public pages, keeps them out of
    the admin/API/media areas, and points them at the sitemap."""
    site = _site_url(request)
    body = (
        "# robots.txt — Smart Review (AI code review assistant)\n"
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /admin/\n"
        "Disallow: /api/\n"
        "Disallow: /media/\n"
        "Disallow: /static/\n"
        "\n"
        "# Be gentle with a free-tier instance\n"
        "Crawl-delay: 1\n"
        "\n"
        f"Sitemap: {site}/sitemap.xml\n"
    )
    return HttpResponse(body, content_type="text/plain; charset=utf-8")


def sitemap_xml(request):
    """sitemap.xml — generated from the request host, so a custom domain
    attached later is reflected without a code change."""
    site = _site_url(request)
    lastmod = date.today().isoformat()
    pages = [
        ("/",           "1.0", "daily"),
        ("/faq.html",   "0.8", "weekly"),
        ("/review.html", "0.6", "weekly"),
    ]
    entries = "".join(
        "  <url>\n"
        f"    <loc>{site}{path}</loc>\n"
        f"    <lastmod>{lastmod}</lastmod>\n"
        f"    <changefreq>{freq}</changefreq>\n"
        f"    <priority>{priority}</priority>\n"
        "  </url>\n"
        for path, priority, freq in pages
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}"
        "</urlset>\n"
    )
    return HttpResponse(body, content_type="application/xml; charset=utf-8")


def frontend_asset(request, path):
    """Serve /css, /js, /assets with a revalidation-safe cache header.

    Django's serve() sets Last-Modified but no Cache-Control, so browsers
    spend a round trip revalidating every asset on every visit. These files
    are not fingerprinted, so a short max-age (not a year) keeps repeat
    visits fast without pinning users to stale CSS after a deploy.
    """
    response = serve(request, path, document_root=str(FRONTEND_DIR))
    if isinstance(response, HttpResponseBase) and response.status_code == 200:
        response["Cache-Control"] = "public, max-age=3600"
    return response


def favicon(request):
    """Serve the SVG favicon at /favicon.ico (browsers request that path
    by default even when the page declares an SVG icon)."""
    path = FRONTEND_DIR / "assets" / "favicon.svg"
    if not path.exists():
        raise Http404("favicon not found")
    response = HttpResponse(path.read_bytes(), content_type="image/svg+xml")
    response["Cache-Control"] = "public, max-age=604800"
    return response


urlpatterns = [
    # Django admin
    path("admin/", admin.site.urls),

    # REST API (versioned under /api/v1/)
    path("api/v1/", include("api.urls")),

    # OpenAPI schema & UI (drf-spectacular)
    path("api/schema/.json", SpectacularAPIView.as_view(), name="schema-json"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema-json"), name="schema-swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema-json"), name="schema-redoc"),

    # Frontend HTML pages (served from /frontend/ directory)
    path("",            _frontend_file("index.html"),  name="home"),
    path("review.html", _frontend_file("review.html"), name="review"),
    path("faq.html",    _frontend_file("faq.html"),    name="faq"),

    # SEO endpoints (generated, not static files, so they follow the domain)
    path("robots.txt",  robots_txt,  name="robots-txt"),
    path("sitemap.xml", sitemap_xml, name="sitemap-xml"),
    path("favicon.ico", favicon,     name="favicon"),

    # Frontend assets and uploads — served in every environment (no nginx in
    # front of gunicorn; WhiteNoise handles /static/ when DEBUG=False).
    re_path(
        r"^(?P<path>(?:css|js|assets)/.+)$",
        frontend_asset,
    ),
    re_path(
        r"^media/(?P<path>.+)$",
        serve,
        {"document_root": str(settings.MEDIA_ROOT)},
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)