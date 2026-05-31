"""
api/views.py — REST API Views (Phase 1 Stub)
=============================================
Placeholder view classes that return correct HTTP responses.
Full implementation comes in Phase 4.

Each view is stubbed to return a 200/501 so the URL routing works
and the frontend can be built against the API shape from Phase 2 onwards.
"""

import logging
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@api_view(["GET"])
def health_check(request):
    """
    GET /api/v1/health/
    Returns 200 with service status. Used by Docker health checks and
    the frontend to verify the backend is reachable.
    """
    from django.db import connection
    db_ok = True
    try:
        connection.ensure_connection()
    except Exception:
        db_ok = False

    return Response({
        "status":   "ok" if db_ok else "degraded",
        "service":  "AI Code Review Assistant",
        "version":  "1.0.0",
        "database": "connected" if db_ok else "unreachable",
    }, status=status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE)


# ---------------------------------------------------------------------------
# Project Views
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name="dispatch")
class ProjectListCreateView(View):
    """
    GET  /api/v1/projects/  — list all projects
    POST /api/v1/projects/  — create a new project
    Full implementation in Phase 4.
    """
    def get(self, request):
        return JsonResponse({"detail": "Project list — Phase 4 implementation pending.", "results": []})

    def post(self, request):
        return JsonResponse({"detail": "Project create — Phase 4 implementation pending."}, status=501)


@method_decorator(csrf_exempt, name="dispatch")
class ProjectDetailView(View):
    """GET/DELETE /api/v1/projects/<uuid>/"""
    def get(self, request, pk):
        return JsonResponse({"detail": f"Project {pk} — Phase 4 implementation pending."})

    def delete(self, request, pk):
        return JsonResponse({"detail": "Delete — Phase 4 implementation pending."}, status=501)


# ---------------------------------------------------------------------------
# Code File Views
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name="dispatch")
class CodeFileUploadView(View):
    """POST /api/v1/projects/<uuid>/upload/"""
    def post(self, request, project_pk):
        return JsonResponse({"detail": "File upload — Phase 4 implementation pending."}, status=501)


@method_decorator(csrf_exempt, name="dispatch")
class CodeFileDetailView(View):
    """GET /api/v1/files/<uuid>/"""
    def get(self, request, pk):
        return JsonResponse({"detail": f"File {pk} — Phase 4 implementation pending."})


@method_decorator(csrf_exempt, name="dispatch")
class TriggerAnalysisView(View):
    """POST /api/v1/files/<uuid>/analyze/"""
    def post(self, request, pk):
        return JsonResponse({"detail": "Analyze trigger — Phase 4 implementation pending."}, status=501)


@method_decorator(csrf_exempt, name="dispatch")
class CodeFileSourceView(View):
    """GET /api/v1/files/<uuid>/source/ — returns decrypted source (dev only)"""
    def get(self, request, pk):
        return JsonResponse({"detail": "Source view — Phase 4 implementation pending."})


# ---------------------------------------------------------------------------
# Vulnerability + Explanation Views
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name="dispatch")
class VulnerabilityDetailView(View):
    """GET /api/v1/vulnerabilities/<uuid>/"""
    def get(self, request, pk):
        return JsonResponse({"detail": f"Vulnerability {pk} — Phase 4 implementation pending."})


@method_decorator(csrf_exempt, name="dispatch")
class ExplanationDetailView(View):
    """GET /api/v1/vulnerabilities/<uuid>/explanation/"""
    def get(self, request, pk):
        return JsonResponse({"detail": f"Explanation for {pk} — Phase 4 implementation pending."})
