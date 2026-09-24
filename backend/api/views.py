"""
api/views.py — REST API Views
==============================
Endpoints:
    GET  /api/v1/health/                              Health check
    GET  /api/v1/projects/                            List projects
    POST /api/v1/projects/                            Create project
    GET  /api/v1/projects/<uuid>/                     Project detail + file list
    DEL  /api/v1/projects/<uuid>/                     Delete project
    POST /api/v1/projects/<uuid>/upload/              Upload + encrypt + analyze a file
    GET  /api/v1/files/<uuid>/                        File detail + vulnerabilities
    POST /api/v1/files/<uuid>/analyze/                (Re-)trigger analysis
    GET  /api/v1/files/<uuid>/source/                 Decrypted source (DEBUG only)
    GET  /api/v1/vulnerabilities/<uuid>/              Vulnerability detail
    GET  /api/v1/vulnerabilities/<uuid>/explanation/  XAI explanation
"""

import time
import logging

from django.conf import settings
from django.db import connection, transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import (
    Project, CodeFile, Vulnerability, Explanation,
    ReviewStatus, ExplanationType,
)
from .serializers import (
    ProjectListSerializer, ProjectDetailSerializer, ProjectCreateSerializer,
    CodeFileDetailSerializer, FileUploadSerializer,
    VulnerabilityDetailSerializer, ExplanationSerializer,
)

logger = logging.getLogger(__name__)


# ─── Health Check ─────────────────────────────────────────────────────────────

@api_view(["GET"])
def health_check(request):
    """
    GET /api/v1/health/
    Returns backend service status. Used by Docker health checks and frontend.

    Query params:
        services=1 — also probe the Java and C# microservices in parallel.
                     Opt-in because it can take a few seconds when a service
                     is down; the default response stays fast for the
                     Docker healthcheck (interval 30s, timeout 10s).
    """
    db_ok = True
    try:
        connection.ensure_connection()
    except Exception:
        db_ok = False

    payload = {
        "status":   "ok" if db_ok else "degraded",
        "service":  "AI Code Review Assistant",
        "version":  "1.0.0",
        "database": "connected" if db_ok else "unreachable",
        "debug":    settings.DEBUG,
    }

    if request.query_params.get("services") in ("1", "true", "yes"):
        try:
            from .microservice_client import check_all_services
            payload["microservices"] = check_all_services()
        except Exception as svc_err:
            logger.warning("Microservice health probe failed: %s", svc_err)
            payload["microservices"] = {"error": str(svc_err)}

    return Response(payload, status=status.HTTP_200_OK if db_ok else status.HTTP_503_SERVICE_UNAVAILABLE)


# ─── Project Views ─────────────────────────────────────────────────────────────

class ProjectListCreateView(APIView):
    """
    GET  /api/v1/projects/ — list all projects (newest first)
    POST /api/v1/projects/ — create a new project
    """

    def get(self, request):
        projects  = Project.objects.all()
        serializer = ProjectListSerializer(projects, many=True)
        return Response({
            "count":   projects.count(),
            "results": serializer.data,
        })

    def post(self, request):
        serializer = ProjectCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        project = serializer.save()
        logger.info("Created project '%s' (id=%s)", project.name, project.id)
        return Response(
            ProjectListSerializer(project).data,
            status=status.HTTP_201_CREATED,
        )


class ProjectDetailView(APIView):
    """
    GET    /api/v1/projects/<uuid>/ — full project with file list
    DELETE /api/v1/projects/<uuid>/ — delete project and all files
    """

    def _get_project(self, pk):
        try:
            return Project.objects.get(pk=pk)
        except Project.DoesNotExist:
            return None

    def get(self, request, pk):
        project = self._get_project(pk)
        if not project:
            return Response({"detail": "Project not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(ProjectDetailSerializer(project).data)

    def delete(self, request, pk):
        project = self._get_project(pk)
        if not project:
            return Response({"detail": "Project not found."}, status=status.HTTP_404_NOT_FOUND)
        name = project.name
        project.delete()
        logger.info("Deleted project '%s' (id=%s)", name, pk)
        return Response(status=status.HTTP_204_NO_CONTENT)


# ─── File Upload + Analysis ────────────────────────────────────────────────────

class CodeFileUploadView(APIView):
    """
    POST /api/v1/projects/<uuid>/upload/
    Accepts multipart/form-data with a 'file' field.
    Encrypts the source code, runs analysis, and creates Vulnerability records.
    """

    def post(self, request, project_pk):
        # Validate project exists
        try:
            project = Project.objects.get(pk=project_pk)
        except Project.DoesNotExist:
            return Response({"detail": "Project not found."}, status=status.HTTP_404_NOT_FOUND)

        # Validate uploaded file
        serializer = FileUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.validated_data["file"]
        language      = serializer.validated_data.get("language") or \
                        serializer.detect_language(uploaded_file.name)

        # Read source code
        try:
            raw_bytes   = uploaded_file.read()
            source_code = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return Response(
                {"detail": "File must be valid UTF-8 encoded text."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create CodeFile record with encrypted source
        with transaction.atomic():
            code_file = CodeFile(
                project  = project,
                filename = uploaded_file.name,
                language = language,
                status   = ReviewStatus.PENDING,
            )
            code_file.set_source(source_code)
            code_file.save()

        logger.info(
            "Uploaded '%s' (%d bytes, lang=%s) to project '%s'",
            uploaded_file.name, len(source_code), language, project.name,
        )

        # Run analysis synchronously (analysis is fast — rule engine + optional
        # microservice enrichment; async offload is not needed)
        self._run_analysis(code_file, source_code, language)

        return Response(
            CodeFileDetailSerializer(code_file).data,
            status=status.HTTP_201_CREATED,
        )

    def _run_analysis(self, code_file: CodeFile, source_code: str, language: str):
        """Runs the full ML analysis pipeline and persists results."""
        code_file.mark_analyzing()
        start_ms = int(time.time() * 1000)

        try:
            from ml.analyzer import CodeAnalyzer
            from ml.explainer import ExplanationGenerator

            analyzer  = CodeAnalyzer(language)
            result    = analyzer.analyze(source_code)
            source_lines = source_code.splitlines()

            # Merge microservice findings (javac / Roslyn) into the local
            # result. Never raises; no-ops when services are disabled.
            from .enrichment import enrich_analysis_result
            result = enrich_analysis_result(
                language, source_code, code_file.filename, result, analyzer,
            )

            gen = ExplanationGenerator()

            with transaction.atomic():
                for finding in result["vulnerabilities"]:
                    # Create Vulnerability record
                    vuln = Vulnerability.objects.create(
                        code_file        = code_file,
                        line_start       = finding["line_start"],
                        line_end         = finding.get("line_end"),
                        title            = finding["title"],
                        description      = finding["description"],
                        category         = finding["category"],
                        severity         = finding["severity"],
                        confidence_score = finding["confidence_score"],
                        rule_id          = finding["rule_id"],
                        recommendation   = finding["recommendation"],
                        code_snippet     = finding["code_snippet"],
                        fixed_snippet    = finding.get("fixed_snippet", ""),
                        cwe_id           = finding.get("cwe_id", ""),
                        owasp_category   = finding.get("owasp_category", ""),
                    )

                    # Generate SHAP + LIME explanations
                    try:
                        shap_data = gen.generate_shap(finding, source_lines)
                        summary   = gen.generate_summary(finding, shap_data)
                        top_name, top_importance = gen.generate_top_feature(shap_data)

                        # LIME-style data rides along under a separate key so
                        # the top-level SHAP schema stays unchanged.
                        explanation_payload = dict(shap_data)
                        explanation_payload["lime"] = gen.generate_lime(finding, source_lines)

                        exp = Explanation(
                            vulnerability         = vuln,
                            method                = ExplanationType.SHAP,
                            explanation_data      = explanation_payload,
                            summary               = summary,
                            top_feature_name      = top_name,
                            top_feature_importance= top_importance,
                        )
                        exp.save()
                    except Exception as exp_err:
                        logger.warning(
                            "Could not generate explanation for vuln %s: %s",
                            vuln.id, exp_err
                        )

                duration_ms = int(time.time() * 1000) - start_ms
                code_file.mark_complete(result["risk_score"], duration_ms)

            logger.info(
                "Analysis complete for '%s': %d findings, risk=%.2f, %dms",
                code_file.filename,
                len(result["vulnerabilities"]),
                result["risk_score"],
                duration_ms,
            )

        except Exception as err:
            logger.error("Analysis failed for '%s': %s", code_file.filename, err, exc_info=True)
            code_file.mark_failed(str(err))


# ─── File Detail + Re-analysis ────────────────────────────────────────────────

class CodeFileDetailView(APIView):
    """GET /api/v1/files/<uuid>/ — file detail with all vulnerabilities."""

    def get(self, request, pk):
        try:
            code_file = CodeFile.objects.prefetch_related("vulnerabilities").get(pk=pk)
        except CodeFile.DoesNotExist:
            return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(CodeFileDetailSerializer(code_file).data)


class TriggerAnalysisView(APIView):
    """
    POST /api/v1/files/<uuid>/analyze/
    Re-triggers analysis on an existing file (e.g. after rule updates).
    Deletes existing vulnerabilities and explanations, then re-runs.
    """

    def post(self, request, pk):
        try:
            code_file = CodeFile.objects.get(pk=pk)
        except CodeFile.DoesNotExist:
            return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)

        if code_file.status == ReviewStatus.ANALYZING:
            return Response(
                {"detail": "Analysis already in progress."},
                status=status.HTTP_409_CONFLICT,
            )

        # Decrypt source
        try:
            source_code = code_file.get_decrypted_source()
        except ValueError as e:
            return Response(
                {"detail": f"Could not decrypt source: {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Clear existing findings
        with transaction.atomic():
            code_file.vulnerabilities.all().delete()

        # Re-run analysis
        upload_view = CodeFileUploadView()
        upload_view._run_analysis(code_file, source_code, code_file.language)

        return Response({
            "status":  code_file.status,
            "message": f"Analysis complete for '{code_file.filename}'.",
            "risk_score": code_file.risk_score,
            "vulnerability_count": code_file.vulnerabilities.count(),
        })


class CodeFileSourceView(APIView):
    """
    GET /api/v1/files/<uuid>/source/
    Returns the decrypted source code. Only available when DEBUG=True.
    """

    def get(self, request, pk):
        if not settings.DEBUG:
            return Response(
                {"detail": "Source view is only available in DEBUG mode."},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            code_file = CodeFile.objects.get(pk=pk)
        except CodeFile.DoesNotExist:
            return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            source = code_file.get_decrypted_source()
        except ValueError as e:
            return Response(
                {"detail": f"Decryption failed: {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({
            "id":         str(code_file.id),
            "filename":   code_file.filename,
            "language":   code_file.language,
            "line_count": code_file.line_count,
            "source":     source,
        })


# ─── Vulnerability + Explanation ──────────────────────────────────────────────

class VulnerabilityDetailView(APIView):
    """GET /api/v1/vulnerabilities/<uuid>/ — full vulnerability detail."""

    def get(self, request, pk):
        try:
            vuln = Vulnerability.objects.get(pk=pk)
        except Vulnerability.DoesNotExist:
            return Response({"detail": "Vulnerability not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(VulnerabilityDetailSerializer(vuln).data)


class ExplanationDetailView(APIView):
    """
    GET /api/v1/vulnerabilities/<uuid>/explanation/
    Returns the XAI explanation for a vulnerability.
    If no explanation exists yet, generates one on-the-fly.
    """

    def get(self, request, pk):
        try:
            vuln = Vulnerability.objects.select_related("explanation").get(pk=pk)
        except Vulnerability.DoesNotExist:
            return Response({"detail": "Vulnerability not found."}, status=status.HTTP_404_NOT_FOUND)

        # Return existing explanation
        if hasattr(vuln, "explanation"):
            return Response(ExplanationSerializer(vuln.explanation).data)

        # Generate on-the-fly if missing (e.g. old records without explanations)
        try:
            source_code  = vuln.code_file.get_decrypted_source()
            source_lines = source_code.splitlines()

            from ml.explainer import ExplanationGenerator
            gen = ExplanationGenerator()

            finding = {
                "rule_id":          vuln.rule_id,
                "title":            vuln.title,
                "severity":         vuln.severity,
                "line_start":       vuln.line_start,
                "confidence_score": vuln.confidence_score,
                "shap_features":    [],  # No shap_features stored on model — use empty
            }

            shap_data               = gen.generate_shap(finding, source_lines)
            summary                 = gen.generate_summary(finding, shap_data)
            top_name, top_importance = gen.generate_top_feature(shap_data)

            # LIME-style data rides along under a separate key so the
            # top-level SHAP schema stays unchanged.
            explanation_payload = dict(shap_data)
            explanation_payload["lime"] = gen.generate_lime(finding, source_lines)

            exp = Explanation.objects.create(
                vulnerability          = vuln,
                method                 = ExplanationType.SHAP,
                explanation_data       = explanation_payload,
                summary                = summary,
                top_feature_name       = top_name,
                top_feature_importance = top_importance,
            )
            return Response(ExplanationSerializer(exp).data)

        except Exception as e:
            logger.error("On-the-fly explanation failed for vuln %s: %s", pk, e)
            return Response(
                {"detail": "Explanation could not be generated."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
