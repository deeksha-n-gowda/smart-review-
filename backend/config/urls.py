"""
URL Configuration — AI Code Review Assistant
============================================
Routes incoming HTTP requests to the appropriate app.

URL Layout:
    /               → Frontend dashboard (served by Django templates)
    /api/v1/        → REST API endpoints (api app)
    /admin/         → Django admin interface
    /static/        → Static files (in dev)
    /media/         → Uploaded code files
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView


urlpatterns = [
    # Django admin — useful for inspecting DB records during development
    path("admin/", admin.site.urls),

    # REST API — all endpoints are versioned under /api/v1/
    path("api/v1/", include("api.urls")),

    # Frontend root — serves the dashboard template
    # In production, a proper web server (nginx) would serve the /frontend/ directory.
    # For dev convenience, Django serves it via a template view.
    path("", TemplateView.as_view(template_name="dashboard/index.html"), name="home"),
    path("review/", TemplateView.as_view(template_name="dashboard/review.html"), name="review"),
]

# Serve media files (uploaded code snippets) in development mode
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
