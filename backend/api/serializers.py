"""
api/serializers.py — Django REST Framework Serializers
=======================================================
Converts model instances to/from JSON for the REST API.

Serializers handle:
  - Validation of incoming request data
  - Nested representation (e.g. Project includes summary stats)
  - Selective field exposure (encrypted_source is NEVER serialized)
"""

from rest_framework import serializers
from core.models import (
    Project, CodeFile, Vulnerability, Explanation,
    Language, ReviewStatus, Severity,
)


# ---------------------------------------------------------------------------
# Explanation Serializer
# ---------------------------------------------------------------------------

class ExplanationSerializer(serializers.ModelSerializer):
    """Full XAI explanation — returned when client requests vuln detail."""

    class Meta:
        model   = Explanation
        fields  = [
            "id", "method", "explanation_data", "summary",
            "top_feature_name", "top_feature_importance", "generated_at",
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------------
# Vulnerability Serializers
# ---------------------------------------------------------------------------

class VulnerabilityListSerializer(serializers.ModelSerializer):
    """
    Compact representation for embedding inside CodeFile responses.
    Omits large text fields (description, recommendation) to keep payload small.
    """
    line_range = serializers.SerializerMethodField()

    class Meta:
        model  = Vulnerability
        fields = [
            "id", "title", "severity", "category",
            "line_start", "line_end", "line_range",
            "rule_id", "confidence_score",
            "cwe_id", "owasp_category",
            "code_snippet",
        ]

    def get_line_range(self, obj):
        if obj.line_end and obj.line_end != obj.line_start:
            return f"{obj.line_start}–{obj.line_end}"
        return str(obj.line_start)


class VulnerabilityDetailSerializer(serializers.ModelSerializer):
    """Full vulnerability detail including description, recommendation, and fix snippet."""
    line_range   = serializers.SerializerMethodField()
    has_explanation = serializers.SerializerMethodField()

    class Meta:
        model  = Vulnerability
        fields = [
            "id", "title", "severity", "category",
            "line_start", "line_end", "line_range",
            "description", "recommendation",
            "code_snippet", "fixed_snippet",
            "rule_id", "confidence_score",
            "cwe_id", "owasp_category",
            "has_explanation", "created_at",
        ]

    def get_line_range(self, obj):
        if obj.line_end and obj.line_end != obj.line_start:
            return f"{obj.line_start}–{obj.line_end}"
        return str(obj.line_start)

    def get_has_explanation(self, obj):
        return hasattr(obj, "explanation")


# ---------------------------------------------------------------------------
# CodeFile Serializers
# ---------------------------------------------------------------------------

class CodeFileListSerializer(serializers.ModelSerializer):
    """Compact file representation for project file lists."""
    vulnerability_count          = serializers.IntegerField(read_only=True)
    critical_vulnerability_count = serializers.IntegerField(read_only=True)

    class Meta:
        model  = CodeFile
        fields = [
            "id", "filename", "language", "status",
            "risk_score", "line_count", "size_bytes",
            "analysis_duration_ms",
            "vulnerability_count", "critical_vulnerability_count",
            "uploaded_at", "analyzed_at",
        ]


class CodeFileDetailSerializer(serializers.ModelSerializer):
    """
    Full file detail including embedded vulnerabilities.
    NOTE: encrypted_source is intentionally excluded — use /source/ endpoint.
    """
    vulnerabilities = VulnerabilityListSerializer(many=True, read_only=True)
    language_display = serializers.SerializerMethodField()

    def get_language_display(self, obj):
        return obj.language_display

    class Meta:
        model  = CodeFile
        fields = [
            "id", "project", "filename", "language", "language_display",
            "status", "risk_score",
            "line_count", "size_bytes", "analysis_duration_ms",
            "error_message",
            "vulnerabilities",
            "uploaded_at", "analyzed_at",
        ]


# ---------------------------------------------------------------------------
# Project Serializers
# ---------------------------------------------------------------------------

class ProjectListSerializer(serializers.ModelSerializer):
    """Compact project listing with computed summary stats."""
    summary = serializers.SerializerMethodField()

    class Meta:
        model  = Project
        fields = [
            "id", "name", "description",
            "overall_risk_score", "created_at", "updated_at",
            "summary",
        ]

    def get_summary(self, obj):
        return obj.get_summary()


class ProjectDetailSerializer(serializers.ModelSerializer):
    """
    Full project detail with embedded file list.
    Used on the review page to get the complete project state.
    """
    code_files = CodeFileListSerializer(many=True, read_only=True)
    summary    = serializers.SerializerMethodField()

    class Meta:
        model  = Project
        fields = [
            "id", "name", "description",
            "overall_risk_score", "created_at", "updated_at",
            "summary", "code_files",
        ]

    def get_summary(self, obj):
        return obj.get_summary()


class ProjectCreateSerializer(serializers.ModelSerializer):
    """Validates incoming project creation requests."""
    name = serializers.CharField(
        max_length=255,
        error_messages={"blank": "Project name cannot be blank."},
    )

    class Meta:
        model  = Project
        fields = ["name", "description"]

    def validate_name(self, value):
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Project name must be at least 2 characters.")
        return value.strip()


# ---------------------------------------------------------------------------
# File Upload Serializer
# ---------------------------------------------------------------------------

class FileUploadSerializer(serializers.Serializer):
    """Validates the multipart/form-data file upload request."""

    ALLOWED_EXTENSIONS = {
        ".py": "python", ".java": "java",
        ".cs": "csharp", ".js": "javascript", ".mjs": "javascript",
    }

    file     = serializers.FileField()
    language = serializers.ChoiceField(
        choices=Language.choices,
        required=False,
        allow_null=True,
    )

    def validate_file(self, value):
        from django.conf import settings
        max_size = settings.MAX_CODE_FILE_SIZE_BYTES

        if value.size > max_size:
            raise serializers.ValidationError(
                f"File too large ({value.size:,} bytes). Maximum allowed: {max_size:,} bytes (1 MB)."
            )

        import os
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            raise serializers.ValidationError(
                f"Unsupported file type '{ext}'. "
                f"Allowed: {', '.join(self.ALLOWED_EXTENSIONS.keys())}"
            )

        return value

    def detect_language(self, filename: str) -> str:
        """Auto-detects language from file extension."""
        import os
        ext = os.path.splitext(filename)[1].lower()
        return self.ALLOWED_EXTENSIONS.get(ext, "python")
