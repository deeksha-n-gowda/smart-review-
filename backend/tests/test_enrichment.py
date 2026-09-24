"""
tests/test_enrichment.py — Microservice Enrichment Tests
=========================================================
Covers api/enrichment.py:
  - Java javac diagnostic mapping (severity/category/confidence/clamping)
  - C# Roslyn diagnostic + service-finding mapping
  - Merge behaviour: local-first dedupe, re-sort, risk recomputation
  - Safety: enrichment disabled, unreachable services, unexpected errors
  - API-level: upload with enrichment mocked in

All network access is mocked — MICROSERVICES_ENABLED is False globally
(see conftest.py) and flipped per-test only with a mocked client.

Run with:
    cd backend
    pytest tests/test_enrichment.py -v
"""

import json
from unittest import mock

import pytest
from django.test import TestCase, Client, override_settings

from api.enrichment import (
    enrich_analysis_result,
    java_diagnostics_to_findings,
    csharp_result_to_findings,
    MAX_EXTERNAL_FINDINGS,
)
from ml.analyzer import CodeAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

JAVA_SRC = "\n".join(f"line {i};" for i in range(1, 11))  # 10 lines

CSHARP_SRC = "\n".join(f"// line {i}" for i in range(1, 11))


def local_analyzer(language="java"):
    return CodeAnalyzer(language)


# ---------------------------------------------------------------------------
# Java diagnostic mapping
# ---------------------------------------------------------------------------

class TestJavaDiagnosticsMapping:

    def test_error_maps_to_high_correctness(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "ERROR", "line": 3, "message": "';' expected", "source_fragment": "line 3;"}],
            JAVA_SRC,
        )
        assert len(findings) == 1
        f = findings[0]
        assert f["rule_id"] == "JAVA-COMPILE-ERROR"
        assert f["severity"] == "high"
        assert f["category"] == "correctness"
        assert f["confidence_score"] == 0.98
        assert f["line_start"] == 3
        assert f["description"] == "';' expected"
        assert f["shap_features"] == ["compile_error"]

    def test_warning_maps_to_low_maintainability(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "WARNING", "line": 5, "message": "deprecation"}],
            JAVA_SRC,
        )
        f = findings[0]
        assert f["rule_id"] == "JAVA-COMPILE-WARNING"
        assert f["severity"] == "low"
        assert f["category"] == "maintainability"
        assert f["confidence_score"] == 0.85
        assert f["shap_features"] == ["compiler_warning"]

    def test_mandatory_warning_treated_as_warning(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "MANDATORY_WARNING", "line": 2, "message": "unchecked cast"}],
            JAVA_SRC,
        )
        assert findings[0]["rule_id"] == "JAVA-COMPILE-WARNING"

    def test_note_and_other_skipped(self):
        findings = java_diagnostics_to_findings(
            [
                {"kind": "NOTE", "line": 1, "message": "Recompiling"},
                {"kind": "OTHER", "line": 2, "message": "something"},
            ],
            JAVA_SRC,
        )
        assert findings == []

    def test_line_zero_clamped_to_one(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "ERROR", "line": 0, "message": "file-level error"}],
            JAVA_SRC,
        )
        assert findings[0]["line_start"] == 1

    def test_line_past_eof_clamped_to_line_count(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "ERROR", "line": 999, "message": "boom"}],
            JAVA_SRC,
        )
        assert findings[0]["line_start"] == 10  # len(JAVA_SRC.splitlines())

    def test_snippet_falls_back_to_source_line(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "ERROR", "line": 4, "message": "err", "source_fragment": ""}],
            JAVA_SRC,
        )
        assert findings[0]["code_snippet"] == "line 4;"

    def test_source_fragment_preferred(self):
        findings = java_diagnostics_to_findings(
            [{"kind": "ERROR", "line": 4, "message": "err", "source_fragment": "  int x;;"}],
            JAVA_SRC,
        )
        assert findings[0]["code_snippet"] == "int x;;"

    def test_empty_diagnostics_returns_empty(self):
        assert java_diagnostics_to_findings([], JAVA_SRC) == []
        assert java_diagnostics_to_findings(None, JAVA_SRC) == []

    def test_findings_capped(self):
        diags = [{"kind": "ERROR", "line": i, "message": f"err {i}"} for i in range(1, 200)]
        findings = java_diagnostics_to_findings(diags, JAVA_SRC)
        assert len(findings) == MAX_EXTERNAL_FINDINGS


# ---------------------------------------------------------------------------
# C# service response mapping
# ---------------------------------------------------------------------------

class TestCSharpResultMapping:

    def test_roslyn_error_maps_to_high_correctness(self):
        findings = csharp_result_to_findings(
            {"diagnostics": [
                {"severity": "Error", "id": "CS0103", "message": "name does not exist",
                 "line": 2, "source_fragment": "// line 2"}
            ]},
            CSHARP_SRC,
        )
        f = findings[0]
        assert f["rule_id"] == "CS-ROS-CS0103"
        assert f["severity"] == "high"
        assert f["category"] == "correctness"
        assert f["confidence_score"] == 0.98
        assert f["line_start"] == 2

    def test_roslyn_warning_maps_to_low_maintainability(self):
        findings = csharp_result_to_findings(
            {"diagnostics": [
                {"severity": "Warning", "id": "CS0219", "message": "unused", "line": 3}
            ]},
            CSHARP_SRC,
        )
        f = findings[0]
        assert f["rule_id"] == "CS-ROS-CS0219"
        assert f["severity"] == "low"
        assert f["confidence_score"] == 0.85

    def test_roslyn_info_and_hidden_skipped(self):
        findings = csharp_result_to_findings(
            {"diagnostics": [
                {"severity": "Info", "id": "IDE0005", "message": "unnecessary using", "line": 1},
                {"severity": "Hidden", "id": "IDE0011", "message": "add braces", "line": 1},
            ]},
            CSHARP_SRC,
        )
        assert findings == []

    def test_service_finding_pass_through_with_local_winning_confidence(self):
        findings = csharp_result_to_findings(
            {"findings": [{
                "rule_id": "CS-SEC-001",
                "title": "SQL Injection",
                "description": "concat query",
                "severity": "critical",
                "category": "security",
                "line": 7,
                "snippet": "var q = \"...\" + id;",
                "recommendation": "parameterize",
                "cwe_id": "CWE-89",
            }]},
            CSHARP_SRC,
        )
        f = findings[0]
        assert f["rule_id"] == "CS-SEC-001"
        assert f["severity"] == "critical"
        assert f["category"] == "security"
        assert f["confidence_score"] == 0.75          # below every local confidence
        assert f["shap_features"] == ["roslyn_rule_match"]
        assert f["cwe_id"] == "CWE-89"
        assert f["line_start"] == 7

    def test_service_finding_severity_and_category_normalized(self):
        findings = csharp_result_to_findings(
            {"findings": [{
                "rule_id": "X-1", "title": "T",
                "severity": "Severe!", "category": "weird",
                "line": 1,
            }]},
            CSHARP_SRC,
        )
        assert findings[0]["severity"] == "medium"     # invalid → default
        assert findings[0]["category"] == "security"   # invalid → default

    def test_findings_without_title_or_rule_id_skipped(self):
        findings = csharp_result_to_findings(
            {"findings": [{"title": "", "rule_id": "X"}, {"title": "T"}]},
            CSHARP_SRC,
        )
        assert findings == []

    def test_total_capped(self):
        response = {
            "diagnostics": [
                {"severity": "Error", "id": f"CS000{i}", "message": "e", "line": 1}
                for i in range(60)
            ],
            "findings": [],
        }
        findings = csharp_result_to_findings(response, CSHARP_SRC)
        assert len(findings) == MAX_EXTERNAL_FINDINGS

    def test_empty_response_returns_empty(self):
        assert csharp_result_to_findings({}, CSHARP_SRC) == []
        assert csharp_result_to_findings(None, CSHARP_SRC) == []


# ---------------------------------------------------------------------------
# enrich_analysis_result — merge + safety behaviour
# ---------------------------------------------------------------------------

def _make_result(findings):
    """Minimal CodeAnalyzer.analyze()-shaped result dict."""
    return {
        "vulnerabilities": findings,
        "risk_score": 0.11,
        "duration_ms": 5,
        "line_count": 10,
        "metrics": {},
    }


class TestEnrichAnalysisResult:

    @pytest.fixture(autouse=True)
    def _enable_services(self, settings):
        settings.MICROSERVICES_ENABLED = True

    def test_disabled_returns_result_untouched(self, settings):
        settings.MICROSERVICES_ENABLED = False
        result = _make_result([])
        with mock.patch("api.enrichment.JavaServiceClient") as client:
            out = enrich_analysis_result("java", JAVA_SRC, "A.java", result, local_analyzer())
        client.assert_not_called()
        assert out is result
        assert out["vulnerabilities"] == []

    @pytest.mark.parametrize("language", ["python", "javascript"])
    def test_languages_without_services_untouched(self, language):
        result = _make_result([])
        with mock.patch("api.enrichment.JavaServiceClient") as j, \
             mock.patch("api.enrichment.CSharpServiceClient") as c:
            out = enrich_analysis_result(language, "x", "x.py", result, local_analyzer("python"))
        j.assert_not_called()
        c.assert_not_called()
        assert out is result

    def test_java_error_added_and_risk_recomputed(self):
        result = _make_result([])
        resp = {"success": True, "compile_ok": False,
                "diagnostics": [{"kind": "ERROR", "line": 3, "message": "';' expected"}]}
        with mock.patch("api.enrichment.JavaServiceClient") as client:
            client.return_value.compile_safe.return_value = resp
            out = enrich_analysis_result("java", JAVA_SRC, "A.java", result, local_analyzer())

        assert len(out["vulnerabilities"]) == 1
        assert out["vulnerabilities"][0]["rule_id"] == "JAVA-COMPILE-ERROR"
        # Risk must be recomputed — a single high finding is far above 0.11
        assert out["risk_score"] > 0.11

    def test_local_findings_win_dedupe_on_tie(self):
        """Same (rule_id, line) from both sources → the local copy survives."""
        local_finding = {
            "rule_id": "CS-SEC-001", "title": "SQL Injection (local)",
            "description": "local", "severity": "critical", "category": "security",
            "line_start": 7, "line_end": None, "code_snippet": "local;",
            "fixed_snippet": "", "recommendation": "local", "cwe_id": "CWE-89",
            "owasp_category": "", "confidence_score": 0.88,
            "shap_features": ["sql_string_concat"],
        }
        result = _make_result([local_finding])
        resp = {
            "diagnostics": [],
            "findings": [{
                "rule_id": "CS-SEC-001", "title": "SQL Injection (service)",
                "description": "svc", "severity": "critical", "category": "security",
                "line": 7, "snippet": "svc;", "recommendation": "svc", "cwe_id": "CWE-89",
            }],
        }
        with mock.patch("api.enrichment.CSharpServiceClient") as client:
            client.return_value.analyze_safe.return_value = resp
            out = enrich_analysis_result("csharp", CSHARP_SRC, "A.cs", result, local_analyzer("csharp"))

        # Deduped to one, and it is the LOCAL version
        same_rule = [f for f in out["vulnerabilities"] if f["rule_id"] == "CS-SEC-001"]
        assert len(same_rule) == 1
        assert same_rule[0]["title"] == "SQL Injection (local)"
        assert same_rule[0]["confidence_score"] == 0.88

    def test_merged_sorted_by_severity_then_line(self):
        result = _make_result([
            {
                "rule_id": "JAVA-LOW", "title": "t", "description": "d",
                "severity": "low", "category": "style", "line_start": 1,
                "line_end": None, "code_snippet": "", "fixed_snippet": "",
                "recommendation": "", "cwe_id": "", "owasp_category": "",
                "confidence_score": 0.8, "shap_features": [],
            },
        ])
        resp = {"success": True, "compile_ok": False, "diagnostics": [
            {"kind": "ERROR", "line": 5, "message": "boom"},
            {"kind": "ERROR", "line": 2, "message": "bang"},
        ]}
        with mock.patch("api.enrichment.JavaServiceClient") as client:
            client.return_value.compile_safe.return_value = resp
            out = enrich_analysis_result("java", JAVA_SRC, "A.java", result, local_analyzer())

        keys = [(f["severity"], f["line_start"]) for f in out["vulnerabilities"]]
        assert keys == [("high", 2), ("high", 5), ("low", 1)]

    def test_unreachable_service_returns_unchanged(self):
        """compile_safe never raises, but belt-and-braces: even an exception
        from the client must not fail the analysis."""
        result = _make_result([])
        with mock.patch("api.enrichment.JavaServiceClient") as client:
            client.return_value.compile_safe.side_effect = RuntimeError("kaboom")
            out = enrich_analysis_result("java", JAVA_SRC, "A.java", result, local_analyzer())
        assert out is result
        assert out["vulnerabilities"] == []

    def test_service_error_dict_returns_unchanged(self):
        """compile_safe's error payload (service down) yields no findings."""
        result = _make_result([])
        error_payload = {"success": False, "compile_ok": None,
                         "diagnostics": [], "error": "unreachable"}
        with mock.patch("api.enrichment.JavaServiceClient") as client:
            client.return_value.compile_safe.return_value = error_payload
            out = enrich_analysis_result("java", JAVA_SRC, "A.java", result, local_analyzer())
        assert out["vulnerabilities"] == []
        assert out["risk_score"] == 0.11   # untouched


# ---------------------------------------------------------------------------
# API-level integration (enrichment mocked in)
# ---------------------------------------------------------------------------

JAVA_UPLOAD_SRC = """
public class Broken {
    public static void main(String[] args) {
        int x = 1
        System.out.println(x);
    }
}
"""

JAVA_SERVICE_RESPONSE = {
    "success": True,
    "compile_ok": False,
    "diagnostics": [
        {"kind": "ERROR", "line": 4, "column": 22, "message": "';' expected",
         "source_fragment": "int x = 1"},
    ],
}


class TestUploadWithEnrichment(TestCase):

    def setUp(self):
        self.client = Client()
        resp = self.client.post(
            "/api/v1/projects/",
            data=json.dumps({"name": "Enrichment Project"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        self.project_id = json.loads(resp.content)["id"]

    def _upload(self, filename, content):
        import io
        file_obj = io.BytesIO(content.encode("utf-8"))
        file_obj.name = filename
        return self.client.post(
            f"/api/v1/projects/{self.project_id}/upload/",
            {"file": file_obj},
            format="multipart",
        )

    @override_settings(MICROSERVICES_ENABLED=True)
    @mock.patch("api.enrichment.JavaServiceClient")
    def test_upload_merges_java_service_findings(self, mock_client):
        mock_client.return_value.compile_safe.return_value = JAVA_SERVICE_RESPONSE

        resp = self._upload("Broken.java", JAVA_UPLOAD_SRC)
        self.assertEqual(resp.status_code, 201)

        data = json.loads(resp.content)
        rule_ids = [v["rule_id"] for v in data["vulnerabilities"]]
        self.assertIn("JAVA-COMPILE-ERROR", rule_ids)

        # Persisted with the mapped severity/category
        from core.models import Project, CodeFile, Vulnerability, Explanation
        compile_vuln = Vulnerability.objects.get(rule_id="JAVA-COMPILE-ERROR")
        self.assertEqual(compile_vuln.severity, "high")
        self.assertEqual(compile_vuln.category, "correctness")
        self.assertEqual(compile_vuln.line_start, 4)

        # An Explanation row was generated for it too
        self.assertTrue(Explanation.objects.filter(vulnerability=compile_vuln).exists())

    def test_upload_without_services_flag_is_local_only(self):
        """Global default from conftest: MICROSERVICES_ENABLED=False."""
        resp = self._upload("Broken.java", JAVA_UPLOAD_SRC)
        self.assertEqual(resp.status_code, 201)
        data = json.loads(resp.content)
        rule_ids = [v["rule_id"] for v in data["vulnerabilities"]]
        self.assertNotIn("JAVA-COMPILE-ERROR", rule_ids)


# ---------------------------------------------------------------------------
# Health endpoint — opt-in service probe
# ---------------------------------------------------------------------------

class TestHealthServiceProbe(TestCase):

    def setUp(self):
        self.client = Client()

    @mock.patch("api.microservice_client.check_all_services")
    def test_services_probed_only_when_requested(self, mock_check):
        mock_check.return_value = {"java": {"status": "ok"}, "csharp": {"status": "ok"}}

        # Default: no probe (keeps the Docker healthcheck fast)
        data = json.loads(self.client.get("/api/v1/health/").content)
        self.assertNotIn("microservices", data)
        mock_check.assert_not_called()

        # Opt-in: probe runs and is included
        data = json.loads(self.client.get("/api/v1/health/?services=1").content)
        self.assertIn("microservices", data)
        self.assertEqual(data["microservices"]["java"]["status"], "ok")
        mock_check.assert_called_once()
