"""
core/models.py — Database Models
=================================
Defines the four main entities in the AI Code Review system:

    1. Project       — A named collection of code files to be reviewed together.
    2. CodeFile      — A single source code file uploaded for analysis.
    3. Vulnerability — A specific issue found in a CodeFile at a specific line.
    4. Explanation   — An XAI (SHAP/LIME) explanation attached to a Vulnerability.

Design notes:
    - CodeFile stores the encrypted ciphertext of the source code, not plaintext.
      The encryption/decryption is handled by the security.encryption module.
    - UUIDs are used as primary keys to avoid exposing sequential IDs in the API.
    - All timestamps use Django's auto_now / auto_now_add to stay timezone-aware.
    - Model methods (e.g., get_decrypted_source) keep business logic close to data.
"""

import uuid
import logging

from django.db import models
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers / Choices
# ---------------------------------------------------------------------------

class Language(models.TextChoices):
    """Supported programming languages for code review."""
    PYTHON     = "python",     "Python"
    JAVA       = "java",       "Java"
    CSHARP     = "csharp",     "C#"
    JAVASCRIPT = "javascript", "JavaScript"


class ReviewStatus(models.TextChoices):
    """Life-cycle states for a code file review."""
    PENDING   = "pending",   "Pending"       # Uploaded, waiting for analysis
    ANALYZING = "analyzing", "Analyzing"     # ML pipeline is running
    COMPLETE  = "complete",  "Complete"      # Analysis finished successfully
    FAILED    = "failed",    "Failed"        # Analysis encountered an error


class Severity(models.TextChoices):
    """Severity levels for vulnerabilities, ordered high → low."""
    CRITICAL = "critical", "Critical"
    HIGH     = "high",     "High"
    MEDIUM   = "medium",   "Medium"
    LOW      = "low",      "Low"
    INFO     = "info",     "Info"


class VulnCategory(models.TextChoices):
    """Broad categories for vulnerability classification."""
    SECURITY        = "security",        "Security"
    PERFORMANCE     = "performance",     "Performance"
    MAINTAINABILITY = "maintainability", "Maintainability"
    STYLE           = "style",           "Style / Convention"
    CORRECTNESS     = "correctness",     "Correctness / Logic"
    COMPLEXITY      = "complexity",      "Complexity"


# ---------------------------------------------------------------------------
# 1. Project
# ---------------------------------------------------------------------------

class Project(models.Model):
    """
    A Project groups one or more CodeFiles that belong to the same review session.

    Example: A student uploads their entire assignment repo — each .py/.java file
    becomes a CodeFile under one Project.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the project (UUID4).",
    )
    name = models.CharField(
        max_length=255,
        help_text="Human-readable project name, e.g. 'Assignment 3 - Sorting Algorithms'.",
    )
    description = models.TextField(
        blank=True,
        default="",
        help_text="Optional description of the project or review scope.",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the project was created.",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp of the last update to this project.",
    )

    # Overall risk score (0.0–1.0) computed as weighted average of all file scores
    overall_risk_score = models.FloatField(
        null=True,
        blank=True,
        help_text="Aggregate risk score across all files (0.0 = clean, 1.0 = high risk).",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Project"
        verbose_name_plural = "Projects"

    def __str__(self):
        return f"Project({self.name!r}, files={self.code_files.count()})"

    def get_summary(self):
        """
        Returns a dict with a quick summary of the project's review status.
        Useful for the dashboard view without loading all related objects.
        """
        files = self.code_files.all()
        vulns = Vulnerability.objects.filter(code_file__project=self)
        return {
            "total_files": files.count(),
            "completed_files": files.filter(status=ReviewStatus.COMPLETE).count(),
            "total_vulnerabilities": vulns.count(),
            "critical_count": vulns.filter(severity=Severity.CRITICAL).count(),
            "high_count": vulns.filter(severity=Severity.HIGH).count(),
            "overall_risk_score": self.overall_risk_score,
        }

    def recalculate_risk_score(self):
        """
        Recomputes the overall_risk_score as the average of all CodeFile scores.
        Called automatically after each file's analysis completes.
        """
        files = self.code_files.filter(risk_score__isnull=False)
        if not files.exists():
            self.overall_risk_score = None
        else:
            self.overall_risk_score = sum(f.risk_score for f in files) / files.count()
        self.save(update_fields=["overall_risk_score", "updated_at"])
        logger.debug("Project %s risk score updated → %.3f", self.id, self.overall_risk_score or 0)


# ---------------------------------------------------------------------------
# 2. CodeFile
# ---------------------------------------------------------------------------

class CodeFile(models.Model):
    """
    Represents a single source code file submitted for review.

    The actual source code is stored AES-256-GCM encrypted in `encrypted_source`.
    The `get_decrypted_source()` method handles decryption transparently.

    Analysis results (vulnerabilities, risk score) are attached to this model
    via the Vulnerability FK and the `risk_score` field.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="code_files",
        help_text="The project this file belongs to.",
    )
    filename = models.CharField(
        max_length=512,
        help_text="Original filename as uploaded, e.g. 'BubbleSort.java'.",
    )
    language = models.CharField(
        max_length=20,
        choices=Language.choices,
        help_text="Detected or user-specified programming language.",
    )
    status = models.CharField(
        max_length=20,
        choices=ReviewStatus.choices,
        default=ReviewStatus.PENDING,
        help_text="Current stage of the review pipeline.",
    )

    # --- Encrypted storage ---
    # We store the ciphertext as bytes. The nonce and tag are prepended
    # by the encryption helper (see security/encryption.py).
    encrypted_source = models.BinaryField(
        help_text=(
            "AES-256-GCM encrypted source code. "
            "Format: [16-byte nonce][16-byte auth tag][ciphertext]"
        ),
    )

    # --- Metadata ---
    line_count = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Total number of lines in the source file.",
    )
    size_bytes = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Size of the original (unencrypted) source in bytes.",
    )

    # --- Analysis results ---
    risk_score = models.FloatField(
        null=True,
        blank=True,
        help_text="ML-assigned risk score (0.0–1.0). Null until analysis completes.",
    )
    analysis_duration_ms = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="How long the ML analysis took, in milliseconds.",
    )
    error_message = models.TextField(
        blank=True,
        default="",
        help_text="If status=FAILED, stores the error message for debugging.",
    )

    # --- Timestamps ---
    uploaded_at = models.DateTimeField(
        auto_now_add=True,
    )
    analyzed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when analysis finished (regardless of success/fail).",
    )

    class Meta:
        ordering = ["uploaded_at"]
        verbose_name = "Code File"
        verbose_name_plural = "Code Files"

    def __str__(self):
        return f"CodeFile({self.filename!r}, lang={self.language}, status={self.status})"

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def set_source(self, plaintext: str):
        """
        Encrypts and stores the given plaintext source code.
        Also updates line_count and size_bytes.

        Args:
            plaintext: The raw source code string (UTF-8).
        """
        from security.encryption import AESCipher  # local import avoids circular deps

        cipher = AESCipher(settings.AES_SECRET_KEY_BYTES)
        self.encrypted_source = cipher.encrypt(plaintext.encode("utf-8"))
        self.line_count = plaintext.count("\n") + 1
        self.size_bytes = len(plaintext.encode("utf-8"))
        logger.debug("CodeFile %s: stored %d bytes encrypted.", self.filename, self.size_bytes)

    def get_decrypted_source(self) -> str:
        """
        Decrypts and returns the source code as a UTF-8 string.

        Returns:
            The original plaintext source code.

        Raises:
            ValueError: If decryption fails (wrong key or tampered data).
        """
        from security.encryption import AESCipher

        cipher = AESCipher(settings.AES_SECRET_KEY_BYTES)
        plaintext_bytes = cipher.decrypt(bytes(self.encrypted_source))
        return plaintext_bytes.decode("utf-8")

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def mark_analyzing(self):
        """Transition the file to 'analyzing' state."""
        self.status = ReviewStatus.ANALYZING
        self.save(update_fields=["status"])

    def mark_complete(self, risk_score: float, duration_ms: int):
        """Transition to 'complete' and record results."""
        self.status = ReviewStatus.COMPLETE
        self.risk_score = max(0.0, min(1.0, risk_score))  # clamp to [0, 1]
        self.analysis_duration_ms = duration_ms
        self.analyzed_at = timezone.now()
        self.save(update_fields=["status", "risk_score", "analysis_duration_ms", "analyzed_at"])
        # Trigger project-level score recalculation
        self.project.recalculate_risk_score()

    def mark_failed(self, error: str):
        """Transition to 'failed' and record the error."""
        self.status = ReviewStatus.FAILED
        self.error_message = error[:2000]  # Truncate to avoid huge DB entries
        self.analyzed_at = timezone.now()
        self.save(update_fields=["status", "error_message", "analyzed_at"])

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def vulnerability_count(self) -> int:
        return self.vulnerabilities.count()

    @property
    def critical_vulnerability_count(self) -> int:
        return self.vulnerabilities.filter(severity=Severity.CRITICAL).count()

    @property
    def language_display(self) -> str:
        return Language(self.language).label if self.language else "Unknown"


# ---------------------------------------------------------------------------
# 3. Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(models.Model):
    """
    A specific issue found in a CodeFile at a particular line (or range of lines).

    Each Vulnerability is produced by the ML analysis pipeline and describes:
        - WHERE the issue is (line numbers)
        - WHAT the issue is (title, description, category)
        - HOW severe it is (severity)
        - WHAT to do about it (recommendation)
        - HOW confident the model is (confidence_score)

    Vulnerabilities link to Explanations for the XAI side of the system.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    code_file = models.ForeignKey(
        CodeFile,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
        help_text="The file in which this vulnerability was found.",
    )

    # --- Location ---
    line_start = models.PositiveIntegerField(
        help_text="First line of the problematic code section (1-indexed).",
    )
    line_end = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Last line of the problematic section. Equal to line_start for single-line issues.",
    )

    # --- Classification ---
    title = models.CharField(
        max_length=255,
        help_text="Short, human-readable name for the issue, e.g. 'SQL Injection Risk'.",
    )
    description = models.TextField(
        help_text="Detailed explanation of the vulnerability and why it's a problem.",
    )
    category = models.CharField(
        max_length=30,
        choices=VulnCategory.choices,
        default=VulnCategory.SECURITY,
        help_text="Broad category the vulnerability falls into.",
    )
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.MEDIUM,
        help_text="How critical this issue is.",
    )

    # --- ML output ---
    confidence_score = models.FloatField(
        default=1.0,
        help_text="Model confidence in this finding (0.0–1.0).",
    )
    rule_id = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Internal rule or detector ID that flagged this issue, e.g. 'PY-SEC-001'.",
    )

    # --- Remediation ---
    recommendation = models.TextField(
        blank=True,
        default="",
        help_text="Suggested fix or mitigation for this vulnerability.",
    )
    code_snippet = models.TextField(
        blank=True,
        default="",
        help_text="The specific lines of code involved (stored plaintext for display).",
    )
    fixed_snippet = models.TextField(
        blank=True,
        default="",
        help_text="Optional: a corrected version of the code snippet.",
    )

    # --- CWE / OWASP reference ---
    cwe_id = models.CharField(
        max_length=20,
        blank=True,
        default="",
        help_text="CWE identifier if applicable, e.g. 'CWE-89'.",
    )
    owasp_category = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="OWASP Top 10 category if applicable, e.g. 'A03:2021 – Injection'.",
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-severity", "line_start"]
        verbose_name = "Vulnerability"
        verbose_name_plural = "Vulnerabilities"

    def __str__(self):
        return (
            f"Vuln({self.severity.upper()}: {self.title!r} "
            f"@ line {self.line_start}, file={self.code_file.filename!r})"
        )

    @property
    def line_range(self) -> str:
        """Human-readable line range, e.g. '42' or '42–47'."""
        if self.line_end and self.line_end != self.line_start:
            return f"{self.line_start}–{self.line_end}"
        return str(self.line_start)

    @property
    def severity_weight(self) -> float:
        """
        Numeric weight for risk score calculations.
        Maps severity strings to float values.
        """
        weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH:     0.75,
            Severity.MEDIUM:   0.5,
            Severity.LOW:      0.25,
            Severity.INFO:     0.05,
        }
        return weights.get(self.severity, 0.5)


# ---------------------------------------------------------------------------
# 4. Explanation
# ---------------------------------------------------------------------------

class ExplanationType(models.TextChoices):
    """The XAI method used to generate this explanation."""
    SHAP = "shap", "SHAP (SHapley Additive exPlanations)"
    LIME = "lime", "LIME (Local Interpretable Model-Agnostic Explanations)"
    RULE = "rule", "Rule-Based (Deterministic)"


class Explanation(models.Model):
    """
    An Explainable AI (XAI) explanation attached to a specific Vulnerability.

    This stores the output of SHAP or LIME analysis explaining WHY the model
    flagged this particular vulnerability. The explanation data is stored as
    structured JSON containing feature importance scores, which the frontend
    renders as a bar chart.

    SHAP explanation_data format:
    {
        "method": "shap",
        "base_value": 0.42,
        "prediction": 0.87,
        "features": [
            {"name": "sql_string_concat", "value": 1, "shap_value": 0.31, "display": "SQL string concat detected"},
            {"name": "user_input_present", "value": 1, "shap_value": 0.22, "display": "User input not sanitized"},
            {"name": "parameterized_query", "value": 0, "shap_value": -0.08, "display": "No parameterized query"},
            ...
        ]
    }

    LIME explanation_data format:
    {
        "method": "lime",
        "prediction_proba": [0.13, 0.87],
        "intercept": 0.35,
        "features": [
            {"name": "exec_call", "weight": 0.29, "display": "exec() call present"},
            ...
        ]
    }
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    vulnerability = models.OneToOneField(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="explanation",
        help_text="The vulnerability this explanation is for.",
    )
    method = models.CharField(
        max_length=10,
        choices=ExplanationType.choices,
        default=ExplanationType.SHAP,
        help_text="Which XAI method produced this explanation.",
    )

    # --- Core explanation data ---
    # Stored as JSON; validated and structured by the ML pipeline.
    explanation_data = models.JSONField(
        help_text=(
            "Structured XAI output. See Explanation model docstring for schema. "
            "Contains feature names, values, and importance scores."
        ),
    )

    # --- Human-readable summary ---
    summary = models.TextField(
        blank=True,
        default="",
        help_text=(
            "Auto-generated plain-English summary of why this was flagged, "
            "e.g. 'The model flagged this because it detected user input being "
            "concatenated directly into a SQL string.'"
        ),
    )

    # --- The feature that contributed most ---
    top_feature_name = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="Name of the feature with the highest absolute importance score.",
    )
    top_feature_importance = models.FloatField(
        null=True,
        blank=True,
        help_text="Importance score of the top feature.",
    )

    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Explanation"
        verbose_name_plural = "Explanations"

    def __str__(self):
        return (
            f"Explanation({self.method.upper()} for "
            f"{self.vulnerability.title!r} @ {self.vulnerability.code_file.filename!r})"
        )

    def get_sorted_features(self) -> list:
        """
        Returns the feature list from explanation_data sorted by absolute
        importance/SHAP value descending. Safe to call on both SHAP and LIME data.
        """
        features = self.explanation_data.get("features", [])
        # For SHAP use 'shap_value', for LIME use 'weight'
        key = "shap_value" if self.method == ExplanationType.SHAP else "weight"
        return sorted(features, key=lambda f: abs(f.get(key, 0)), reverse=True)

    def compute_top_feature(self):
        """
        Scans the feature list and updates top_feature_name / top_feature_importance.
        Call this after setting explanation_data and before saving.
        """
        features = self.get_sorted_features()
        if features:
            key = "shap_value" if self.method == ExplanationType.SHAP else "weight"
            top = features[0]
            self.top_feature_name = top.get("display", top.get("name", ""))
            self.top_feature_importance = abs(top.get(key, 0))
