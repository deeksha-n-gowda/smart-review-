"""
api/enrichment.py — Microservice Result Enrichment
===================================================
Merges findings from the polyglot microservices (the Java javac compiler
service and the C# Roslyn analysis daemon) into the local rule-based
analysis result produced by ml.analyzer.CodeAnalyzer.

Design principles:
  - Local rules always win ties. External findings are assigned a lower
    confidence so analyzer._deduplicate() keeps the local copy when both
    report the same (rule_id, line_start).
  - Enrichment is strictly optional. Every call path is wrapped so an
    unreachable or slow service can never fail an analysis — worst case the
    result is returned unchanged.
  - Gated on settings.MICROSERVICES_ENABLED (set to False in tests so no
    network calls are ever attempted).

Usage:
    from api.enrichment import enrich_analysis_result
    result = enrich_analysis_result(language, source, filename, result, analyzer)
"""

import logging
import time

from django.conf import settings

from ml.analyzer import compute_risk_score
from .microservice_client import JavaServiceClient, CSharpServiceClient

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

# Sort order (mirrors ml.analyzer.analyze)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Model choice validation — service payloads are normalized against these.
VALID_SEVERITIES = set(SEVERITY_ORDER)
VALID_CATEGORIES = {
    "security", "performance", "maintainability",
    "style", "correctness", "complexity",
}

# Upper bound on findings imported from a single service. Both javac on a
# broken file and Roslyn on a large file can emit long diagnostic lists;
# capping keeps the vulnerability table (and the UI) manageable.
MAX_EXTERNAL_FINDINGS = 50

# ── Java compiler service mapping ────────────────────────────────────────────
# javax.tools.Diagnostic.Kind names (as serialized by the service):
#   ERROR, MANDATORY_WARNING, WARNING, NOTE, OTHER.
# NOTE/OTHER are informational chatter (e.g. "Recompiling the source file")
# and are deliberately skipped.

_JAVA_KIND_MAP = {
    "ERROR": {
        "severity":    "high",
        "category":    "correctness",
        "confidence":  0.98,
        "rule_id":     "JAVA-COMPILE-ERROR",
        "title":       "Java Compilation Error",
        "shap":        ["compile_error"],
        "recommendation": (
            "Fix the compilation error reported by javac — the file does not "
            "build until this is resolved."
        ),
    },
    "WARNING": {
        "severity":    "low",
        "category":    "maintainability",
        "confidence":  0.85,
        "rule_id":     "JAVA-COMPILE-WARNING",
        "title":       "Java Compilation Warning",
        "shap":        ["compiler_warning"],
        "recommendation": (
            "Address the compiler warning — it usually points at dead code, "
            "unchecked casts, or deprecated APIs."
        ),
    },
}


# ── C# Roslyn daemon mapping ─────────────────────────────────────────────────
# Roslyn DiagnosticSeverity.ToString() values: Error, Warning, Info, Hidden.
# Info/Hidden are IDE suggestions and are deliberately skipped.

_CSHARP_ROS_ERROR = {
    "severity":    "high",
    "category":    "correctness",
    "confidence":  0.98,
    "title":       "C# Compilation Error",
    "shap":        ["compile_error"],
    "recommendation": (
        "Fix the compilation error reported by Roslyn — the file does not "
        "build until this is resolved."
    ),
}
_CSHARP_ROS_WARNING = {
    "severity":    "low",
    "category":    "maintainability",
    "confidence":  0.85,
    "title":       "C# Compilation Warning",
    "shap":        ["compiler_warning"],
    "recommendation": (
        "Address the compiler warning — it usually points at dead code, "
        "unused fields, or possible null references."
    ),
}

# Confidence for rule findings produced by the C# service's own analysis
# engine. Deliberately below every local csharp_rules confidence (0.78–0.99)
# so _deduplicate() keeps the local finding when both detect the same rule.
_CSHARP_SERVICE_FINDING_CONFIDENCE = 0.75


# ── Helpers ──────────────────────────────────────────────────────────────────

def _clamp_line(raw_line, line_count: int) -> int:
    """
    Coerces a service-reported line number into [1, line_count].

    Services report 0 (or a negative NOPOS-style value) when a diagnostic
    has no position, and can occasionally report a line past EOF.
    """
    try:
        line = int(raw_line)
    except (TypeError, ValueError):
        return 1
    upper = max(line_count, 1)
    return max(1, min(line, upper))


def _source_snippet(fragment, lines, line: int) -> str:
    """
    Returns the best available code snippet: the service-provided fragment
    first, falling back to the actual source line, truncated to 500 chars
    (matching ml.analyzer's snippet cap).
    """
    snippet = (fragment or "").strip()
    if not snippet and 1 <= line <= len(lines):
        snippet = lines[line - 1].strip()
    return snippet[:500]


def _normalize_severity(raw, default="medium") -> str:
    sev = str(raw or "").strip().lower()
    return sev if sev in VALID_SEVERITIES else default


def _normalize_category(raw, default="correctness") -> str:
    cat = str(raw or "").strip().lower()
    return cat if cat in VALID_CATEGORIES else default


def _finding(*, rule_id, title, description, severity, category, line,
             snippet, recommendation, confidence, shap_features,
             cwe_id=""):
    """Builds a finding dict with the exact keys _run_analysis persists."""
    return {
        "rule_id":          str(rule_id)[:100],
        "title":            str(title)[:255],
        "description":      str(description or ""),
        "severity":         severity,
        "category":         category,
        "line_start":       line,
        "line_end":         None,
        "code_snippet":     snippet,
        "fixed_snippet":    "",
        "recommendation":   str(recommendation or ""),
        "cwe_id":           str(cwe_id or "")[:20],
        "owasp_category":   "",
        "confidence_score": confidence,
        "shap_features":    shap_features,
    }


# ── Java diagnostics → findings ──────────────────────────────────────────────

def java_diagnostics_to_findings(diagnostics, source_code: str) -> list:
    """
    Maps javac diagnostics ({"kind", "line", "column", "message",
    "source_fragment"}) into analyzer-shaped finding dicts.

    ERROR      → high / correctness   (conf 0.98, JAVA-COMPILE-ERROR)
    WARNING    → low / maintainability (conf 0.85, JAVA-COMPILE-WARNING)
    NOTE/OTHER → skipped (informational)
    """
    findings = []
    if not diagnostics:
        return findings

    lines = source_code.splitlines()

    for diag in diagnostics:
        if not isinstance(diag, dict):
            continue

        kind = str(diag.get("kind") or "").strip().upper()
        if kind == "MANDATORY_WARNING":          # javac emits both spellings
            kind = "WARNING"
        spec = _JAVA_KIND_MAP.get(kind)
        if spec is None:                         # NOTE / OTHER / unknown
            continue

        line = _clamp_line(diag.get("line"), len(lines))
        message = str(diag.get("message") or "").strip() or "Compiler diagnostic"

        findings.append(_finding(
            rule_id       = spec["rule_id"],
            title         = spec["title"],
            description   = message,
            severity      = spec["severity"],
            category      = spec["category"],
            line          = line,
            snippet       = _source_snippet(diag.get("source_fragment"), lines, line),
            recommendation= spec["recommendation"],
            confidence    = spec["confidence"],
            shap_features = spec["shap"],
        ))

        if len(findings) >= MAX_EXTERNAL_FINDINGS:
            logger.info("Java diagnostics capped at %d findings.", MAX_EXTERNAL_FINDINGS)
            break

    return findings


# ── C# service response → findings ───────────────────────────────────────────

def csharp_result_to_findings(response, source_code: str) -> list:
    """
    Maps a full C# daemon response into analyzer-shaped finding dicts:

      - "diagnostics": Roslyn compiler diagnostics
          Error   → high / correctness    (conf 0.98, rule_id CS-ROS-CSxxxx)
          Warning → low / maintainability (conf 0.85, rule_id CS-ROS-CSxxxx)
          Info/Hidden → skipped
      - "findings": the service's own rule engine (CS-SEC-*, ...)
          passed through with conf 0.75 so local duplicates win dedupe.
    """
    findings = []
    if not isinstance(response, dict):
        return findings

    lines = source_code.splitlines()

    # 1. Roslyn diagnostics
    for diag in response.get("diagnostics") or []:
        if not isinstance(diag, dict):
            continue

        sev = str(diag.get("severity") or "").strip().lower()
        if sev == "error":
            spec = _CSHARP_ROS_ERROR
        elif sev == "warning":
            spec = _CSHARP_ROS_WARNING
        else:                                    # info / hidden / unknown
            continue

        roslyn_id = str(diag.get("id") or "").strip() or "UNKNOWN"
        line      = _clamp_line(diag.get("line"), len(lines))
        message   = str(diag.get("message") or "").strip() or "Compiler diagnostic"

        findings.append(_finding(
            rule_id       = f"CS-ROS-{roslyn_id}",
            title         = f"{spec['title']} ({roslyn_id})",
            description   = message,
            severity      = spec["severity"],
            category      = spec["category"],
            line          = line,
            snippet       = _source_snippet(diag.get("source_fragment"), lines, line),
            recommendation= spec["recommendation"],
            confidence    = spec["confidence"],
            shap_features = spec["shap"],
        ))

        if len(findings) >= MAX_EXTERNAL_FINDINGS:
            logger.info("C# diagnostics capped at %d findings.", MAX_EXTERNAL_FINDINGS)
            return findings

    # 2. The service's own rule findings
    for item in response.get("findings") or []:
        if not isinstance(item, dict):
            continue
        if not item.get("title") or not item.get("rule_id"):
            continue

        line = _clamp_line(item.get("line"), len(lines))
        findings.append(_finding(
            rule_id       = item.get("rule_id"),
            title         = item.get("title"),
            description   = item.get("description") or item.get("title") or "",
            severity      = _normalize_severity(item.get("severity")),
            category      = _normalize_category(item.get("category"), default="security"),
            line          = line,
            snippet       = _source_snippet(item.get("snippet"), lines, line),
            recommendation= item.get("recommendation") or "",
            confidence    = _CSHARP_SERVICE_FINDING_CONFIDENCE,
            shap_features = ["roslyn_rule_match"],
            cwe_id        = item.get("cwe_id") or "",
        ))

        if len(findings) >= MAX_EXTERNAL_FINDINGS:
            logger.info("C# findings capped at %d findings.", MAX_EXTERNAL_FINDINGS)
            break

    return findings


# ── Public entry point ───────────────────────────────────────────────────────

def enrich_analysis_result(language, source_code, filename, result, analyzer):
    """
    Merges microservice findings into an analyzer result dict (in place).

    Args:
        language:    One of "python" | "java" | "csharp" | "javascript".
        source_code: Original plaintext source (for snippet/line fallbacks).
        filename:    Original filename (hint for the C# daemon).
        result:      dict returned by CodeAnalyzer.analyze() — mutated.
        analyzer:    the CodeAnalyzer instance (reuses its dedupe logic).

    Returns:
        The same result dict. Unchanged if enrichment is disabled, the
        language has no backing service, the service is unreachable, or
        the service reports no findings.

    Never raises.
    """
    if not getattr(settings, "MICROSERVICES_ENABLED", True):
        return result

    language = (language or "").lower()
    if language not in ("java", "csharp"):
        return result

    start_ms = int(time.time() * 1000)

    try:
        if language == "java":
            response = JavaServiceClient().compile_safe(source_code)
            external = java_diagnostics_to_findings(
                response.get("diagnostics") if isinstance(response, dict) else None,
                source_code,
            )
        else:  # csharp
            response = CSharpServiceClient().analyze_safe(
                source_code, filename=filename or "Snippet.cs",
            )
            external = csharp_result_to_findings(response, source_code)
    except Exception:
        # Enrichment must never fail an analysis — log and move on.
        logger.exception("Microservice enrichment failed (lang=%s) — continuing local-only.", language)
        return result

    if not external:
        return result

    local = result.get("vulnerabilities") or []

    # Local findings come first, so on an exact (rule_id, line) tie the local
    # copy survives — external confidences are capped below local ones.
    merged = analyzer._deduplicate(local + external)

    # Re-sort: severity (critical → info), then line number.
    merged.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 5), f["line_start"]))

    result["vulnerabilities"] = merged
    result["risk_score"] = compute_risk_score(merged)

    logger.info(
        "Enriched %s analysis with %d microservice finding(s) → %d total, risk=%.2f (%dms)",
        language, len(external), len(merged), result["risk_score"],
        int(time.time() * 1000) - start_ms,
    )
    return result
