"""
core/admin.py — Django Admin Registration
==========================================
Registers all models with the Django admin interface for easy inspection
and manual data management during development.
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import Project, CodeFile, Vulnerability, Explanation, Severity


# ---------------------------------------------------------------------------
# Inlines
# ---------------------------------------------------------------------------

class CodeFileInline(admin.TabularInline):
    """Show code files inline within the Project admin page."""
    model = CodeFile
    extra = 0
    readonly_fields = ("id", "filename", "language", "status", "risk_score", "uploaded_at")
    fields = ("filename", "language", "status", "risk_score", "uploaded_at")
    show_change_link = True


class VulnerabilityInline(admin.TabularInline):
    """Show vulnerabilities inline within the CodeFile admin page."""
    model = Vulnerability
    extra = 0
    readonly_fields = ("id", "severity", "title", "line_start", "line_end", "category", "confidence_score")
    fields = ("severity", "title", "line_start", "line_end", "category", "confidence_score")
    show_change_link = True


# ---------------------------------------------------------------------------
# Project Admin
# ---------------------------------------------------------------------------

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display  = ("name", "file_count", "risk_badge", "created_at", "updated_at")
    list_filter   = ("created_at",)
    search_fields = ("name", "description")
    readonly_fields = ("id", "created_at", "updated_at", "overall_risk_score")
    inlines       = [CodeFileInline]

    @admin.display(description="Files")
    def file_count(self, obj):
        return obj.code_files.count()

    @admin.display(description="Risk Score")
    def risk_badge(self, obj):
        if obj.overall_risk_score is None:
            return "—"
        score = obj.overall_risk_score
        color = "#e74c3c" if score >= 0.7 else "#f39c12" if score >= 0.4 else "#27ae60"
        return format_html(
            '<span style="color:{}; font-weight:bold;">{:.0%}</span>',
            color, score
        )


# ---------------------------------------------------------------------------
# CodeFile Admin
# ---------------------------------------------------------------------------

@admin.register(CodeFile)
class CodeFileAdmin(admin.ModelAdmin):
    list_display  = ("filename", "language", "status_badge", "risk_score", "vulnerability_count", "uploaded_at")
    list_filter   = ("language", "status")
    search_fields = ("filename", "project__name")
    readonly_fields = ("id", "uploaded_at", "analyzed_at", "line_count", "size_bytes",
                       "risk_score", "analysis_duration_ms", "status")
    inlines       = [VulnerabilityInline]

    @admin.display(description="Status")
    def status_badge(self, obj):
        colors = {
            "pending":   "#95a5a6",
            "analyzing": "#3498db",
            "complete":  "#27ae60",
            "failed":    "#e74c3c",
        }
        color = colors.get(obj.status, "#333")
        return format_html('<span style="color:{}; font-weight:bold;">{}</span>', color, obj.get_status_display())

    @admin.display(description="Vulns")
    def vulnerability_count(self, obj):
        return obj.vulnerabilities.count()


# ---------------------------------------------------------------------------
# Vulnerability Admin
# ---------------------------------------------------------------------------

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display  = ("title", "severity_badge", "category", "line_start", "code_file", "confidence_score")
    list_filter   = ("severity", "category", "code_file__language")
    search_fields = ("title", "description", "rule_id", "cwe_id")
    readonly_fields = ("id", "created_at")

    @admin.display(description="Severity")
    def severity_badge(self, obj):
        colors = {
            Severity.CRITICAL: "#c0392b",
            Severity.HIGH:     "#e74c3c",
            Severity.MEDIUM:   "#f39c12",
            Severity.LOW:      "#27ae60",
            Severity.INFO:     "#3498db",
        }
        color = colors.get(obj.severity, "#333")
        return format_html(
            '<span style="color:{}; font-weight:bold;">{}</span>',
            color, obj.get_severity_display()
        )


# ---------------------------------------------------------------------------
# Explanation Admin
# ---------------------------------------------------------------------------

@admin.register(Explanation)
class ExplanationAdmin(admin.ModelAdmin):
    list_display  = ("vulnerability", "method", "top_feature_name", "top_feature_importance", "generated_at")
    list_filter   = ("method",)
    search_fields = ("vulnerability__title", "top_feature_name", "summary")
    readonly_fields = ("id", "generated_at", "top_feature_name", "top_feature_importance")
