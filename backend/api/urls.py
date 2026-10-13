"""
api/urls.py — REST API URL Routes
=================================

All routes are prefixed with /api/v1/ from the root urls.py.

Endpoint Index
--------------
GET  /api/v1/health/                              Health check (with optional microservice probe)
GET  /api/v1/projects/                            List projects
POST /api/v1/projects/                            Create project
GET  /api/v1/projects/<uuid>/                     Project detail + file list
DEL  /api/v1/projects/<uuid>/                     Delete project
POST /api/v1/projects/<uuid>/upload/              Upload + encrypt + analyze a file
GET  /api/v1/files/<uuid>/                        File detail + vulnerability list
POST /api/v1/files/<uuid>/analyze/                (Re-)trigger analysis
GET  /api/v1/files/<uuid>/source/                 Decrypted source code
GET  /api/v1/vulnerabilities/<uuid>/              Vulnerability detail
GET  /api/v1/vulnerabilities/<uuid>/explanation/  XAI explanation

API Root & OpenAPI Schema
-------------------------
GET  /api/                              API root (human-readable landing page)
GET  /api/schema/.json                        Raw OpenAPI 3.0 schema
GET  /api/docs/                             Swagger UI
GET  /api/redoc/                            Redoc
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

app_name = "api"

# Router for any future ViewSet registrations
router = DefaultRouter(trailing_slash=False)

urlpatterns = [
    # API root & OpenAPI schema (drf-spectacular)
    path("", views.api_root, name="api-root"),
    path("schema/.json", views.schema_view, name="schema-json"),
    # The swagger/redoc views are handled by the spectacular package URLs
    # included below via include() to keep this file clean

    # Health check
    path("health/", views.health_check, name="health"),

    # Projects
    path("projects/", views.ProjectListCreateView.as_view(), name="project-list"),
    path("projects/<uuid:pk>/", views.ProjectDetailView.as_view(), name="project-detail"),

    # File upload + management
    path("projects/<uuid:project_pk>/upload/", views.CodeFileUploadView.as_view(), name="file-upload"),
    path("projects/<uuid:project_pk>/bulk-upload/", views.CodeFileBulkUploadView.as_view(), name="file-bulk-upload"),
    path("files/<uuid:pk>/", views.CodeFileDetailView.as_view(), name="file-detail"),
    path("files/<uuid:pk>/analyze/", views.TriggerAnalysisView.as_view(), name="file-analyze"),
    path("files/<uuid:pk>/source/", views.CodeFileSourceView.as_view(), name="file-source"),

    # Vulnerabilities
    path("vulnerabilities/<uuid:pk>/", views.VulnerabilityDetailView.as_view(), name="vuln-detail"),
    path("vulnerabilities/<uuid:pk>/explanation/", views.ExplanationDetailView.as_view(), name="explanation-detail"),

    # DRF router include (for future ViewSet registrations)
    path("v1/", include((router.urls, "api"), namespace="v1")),
]