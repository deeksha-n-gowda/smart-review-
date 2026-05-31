"""
api/urls.py — REST API URL Routes
===================================
All routes are prefixed with /api/v1/ from the root urls.py.

Endpoints (to be fully implemented in Phase 4):
    POST   /api/v1/projects/                         Create a new project
    GET    /api/v1/projects/                         List all projects
    GET    /api/v1/projects/<uuid>/                  Get project details + summary
    DELETE /api/v1/projects/<uuid>/                  Delete a project

    POST   /api/v1/projects/<uuid>/upload/           Upload a code file for analysis
    GET    /api/v1/files/<uuid>/                     Get file details + vulnerabilities
    POST   /api/v1/files/<uuid>/analyze/             Trigger analysis on a file
    GET    /api/v1/files/<uuid>/source/              Get decrypted source (dev only)

    GET    /api/v1/vulnerabilities/<uuid>/           Get a single vulnerability
    GET    /api/v1/vulnerabilities/<uuid>/explanation/ Get XAI explanation

    GET    /api/v1/health/                           Health check endpoint
"""

from django.urls import path
from . import views

app_name = "api"

urlpatterns = [
    # Health check
    path("health/", views.health_check, name="health"),

    # Projects
    path("projects/",              views.ProjectListCreateView.as_view(), name="project-list"),
    path("projects/<uuid:pk>/",    views.ProjectDetailView.as_view(),     name="project-detail"),

    # File upload + management
    path("projects/<uuid:project_pk>/upload/", views.CodeFileUploadView.as_view(), name="file-upload"),
    path("files/<uuid:pk>/",                   views.CodeFileDetailView.as_view(), name="file-detail"),
    path("files/<uuid:pk>/analyze/",           views.TriggerAnalysisView.as_view(), name="file-analyze"),
    path("files/<uuid:pk>/source/",            views.CodeFileSourceView.as_view(), name="file-source"),

    # Vulnerabilities
    path("vulnerabilities/<uuid:pk>/",             views.VulnerabilityDetailView.as_view(), name="vuln-detail"),
    path("vulnerabilities/<uuid:pk>/explanation/", views.ExplanationDetailView.as_view(),  name="explanation-detail"),
]
