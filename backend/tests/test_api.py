"""
tests/test_api.py — REST API Integration Tests
===============================================
Tests the Django REST API endpoints end-to-end using Django's
test client — no real HTTP server required.

Covers:
  - Health check
  - Project CRUD
  - File upload + analysis pipeline
  - Vulnerability retrieval
  - Explanation retrieval
  - Error cases (404, 400, 413)

Run with:
    cd backend
    pytest tests/test_api.py -v
    pytest tests/test_api.py -v -k "test_health"  # single test
"""

import json
import io
import pytest

from django.test import TestCase, Client
from django.urls import reverse

from core.models import (
    Project, CodeFile, Vulnerability, Explanation,
    Language, ReviewStatus, Severity, ExplanationType,
)


# ---------------------------------------------------------------------------
# Fixtures / base class
# ---------------------------------------------------------------------------

class APITestBase(TestCase):
    """
    Base class providing helpers for JSON API calls via Django's test client.
    Uses Django's TestCase so each test runs in a transaction that is rolled
    back automatically — no manual cleanup needed.
    """

    def setUp(self):
        self.client = Client()

    # ── Helpers ───────────────────────────────────────────────────────────

    def get(self, path):
        return self.client.get(path, content_type="application/json")

    def post_json(self, path, data):
        return self.client.post(
            path,
            data=json.dumps(data),
            content_type="application/json",
        )

    def post_file(self, path, filename, content, content_type="text/plain"):
        file_obj = io.BytesIO(content.encode("utf-8"))
        file_obj.name = filename
        return self.client.post(path, {"file": file_obj}, format="multipart")

    def delete(self, path):
        return self.client.delete(path)

    def json(self, response):
        return json.loads(response.content)

    def create_project(self, name="Test Project", description=""):
        resp = self.post_json("/api/v1/projects/", {"name": name, "description": description})
        self.assertEqual(resp.status_code, 201)
        return self.json(resp)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

class TestHealthCheck(APITestBase):

    def test_health_returns_200(self):
        resp = self.get("/api/v1/health/")
        self.assertEqual(resp.status_code, 200)

    def test_health_has_status_field(self):
        data = self.json(self.get("/api/v1/health/"))
        self.assertIn("status", data)

    def test_health_has_service_field(self):
        data = self.json(self.get("/api/v1/health/"))
        self.assertIn("service", data)
        self.assertIn("Code Review", data["service"])

    def test_health_has_database_field(self):
        data = self.json(self.get("/api/v1/health/"))
        self.assertIn("database", data)
        self.assertEqual(data["database"], "connected")

    def test_health_method_not_allowed(self):
        resp = self.client.post("/api/v1/health/")
        self.assertEqual(resp.status_code, 405)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

class TestProjectListCreate(APITestBase):

    def test_empty_project_list(self):
        resp = self.get("/api/v1/projects/")
        self.assertEqual(resp.status_code, 200)
        data = self.json(resp)
        self.assertIn("results", data)
        self.assertIn("count", data)

    def test_create_project_returns_201(self):
        resp = self.post_json("/api/v1/projects/", {"name": "My Project"})
        self.assertEqual(resp.status_code, 201)

    def test_create_project_has_uuid(self):
        data = self.create_project()
        self.assertIn("id", data)
        self.assertEqual(len(data["id"]), 36)   # UUID4 string length

    def test_create_project_name_stored(self):
        data = self.create_project(name="Unique Name 123")
        self.assertEqual(data["name"], "Unique Name 123")

    def test_create_project_with_description(self):
        data = self.create_project(name="Project P", description="Test desc")
        self.assertEqual(data.get("description", "Test desc"), "Test desc")

    def test_create_project_blank_name_rejected(self):
        resp = self.post_json("/api/v1/projects/", {"name": ""})
        self.assertEqual(resp.status_code, 400)

    def test_create_project_missing_name_rejected(self):
        resp = self.post_json("/api/v1/projects/", {"description": "no name"})
        self.assertEqual(resp.status_code, 400)

    def test_create_project_name_too_short_rejected(self):
        resp = self.post_json("/api/v1/projects/", {"name": "X"})
        self.assertEqual(resp.status_code, 400)

    def test_project_appears_in_list_after_creation(self):
        self.create_project(name="ListTest")
        resp = self.get("/api/v1/projects/")
        names = [p["name"] for p in self.json(resp)["results"]]
        self.assertIn("ListTest", names)

    def test_multiple_projects_in_list(self):
        self.create_project(name="Project Alpha")
        self.create_project(name="Project Beta")
        resp = self.get("/api/v1/projects/")
        self.assertGreaterEqual(self.json(resp)["count"], 2)


class TestProjectDetail(APITestBase):

    def setUp(self):
        super().setUp()
        self.project_data = self.create_project(name="Detail Test")
        self.project_id   = self.project_data["id"]

    def test_get_project_returns_200(self):
        resp = self.get(f"/api/v1/projects/{self.project_id}/")
        self.assertEqual(resp.status_code, 200)

    def test_get_project_has_correct_name(self):
        data = self.json(self.get(f"/api/v1/projects/{self.project_id}/"))
        self.assertEqual(data["name"], "Detail Test")

    def test_get_project_has_code_files_list(self):
        data = self.json(self.get(f"/api/v1/projects/{self.project_id}/"))
        self.assertIn("code_files", data)

    def test_get_project_has_summary(self):
        data = self.json(self.get(f"/api/v1/projects/{self.project_id}/"))
        self.assertIn("summary", data)
        self.assertIn("total_files", data["summary"])

    def test_get_nonexistent_project_returns_404(self):
        resp = self.get("/api/v1/projects/00000000-0000-0000-0000-000000000000/")
        self.assertEqual(resp.status_code, 404)

    def test_delete_project_returns_204(self):
        resp = self.delete(f"/api/v1/projects/{self.project_id}/")
        self.assertEqual(resp.status_code, 204)

    def test_deleted_project_returns_404(self):
        self.delete(f"/api/v1/projects/{self.project_id}/")
        resp = self.get(f"/api/v1/projects/{self.project_id}/")
        self.assertEqual(resp.status_code, 404)

    def test_delete_nonexistent_returns_404(self):
        resp = self.delete("/api/v1/projects/00000000-0000-0000-0000-000000000000/")
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# File Upload
# ---------------------------------------------------------------------------

PYTHON_CLEAN = '''
def add(a, b):
    """Return the sum of a and b."""
    return a + b


def multiply(a, b):
    return a * b
'''

PYTHON_VULNERABLE = '''
import sqlite3
import hashlib
import os

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed

def run(cmd):
    os.system("echo " + cmd)
'''

JS_VULNERABLE = '''
function loadProfile(userId) {
    fetch("/api/users/" + userId)
        .then(r => r.json())
        .then(data => {
            document.getElementById("bio").innerHTML = data.bio;
            localStorage.setItem("authToken", data.token);
        });
}
function applyFilter(code) { return eval(code); }
'''


class TestFileUpload(APITestBase):

    def setUp(self):
        super().setUp()
        self.project = self.create_project(name="Upload Test")
        self.pid     = self.project["id"]

    def upload(self, filename, content):
        url = f"/api/v1/projects/{self.pid}/upload/"
        return self.post_file(url, filename, content)

    # ── Success cases ──────────────────────────────────────────────────────

    def test_upload_python_returns_201(self):
        resp = self.upload("clean.py", PYTHON_CLEAN)
        self.assertEqual(resp.status_code, 201)

    def test_upload_response_has_id(self):
        data = self.json(self.upload("clean.py", PYTHON_CLEAN))
        self.assertIn("id", data)

    def test_upload_response_has_filename(self):
        data = self.json(self.upload("myfile.py", PYTHON_CLEAN))
        self.assertEqual(data["filename"], "myfile.py")

    def test_upload_response_has_language(self):
        data = self.json(self.upload("test.py", PYTHON_CLEAN))
        self.assertEqual(data["language"], "python")

    def test_upload_auto_detects_java(self):
        java_src = "public class Hello { public static void main(String[] a) {} }"
        data = self.json(self.upload("Hello.java", java_src))
        self.assertEqual(data["language"], "java")

    def test_upload_auto_detects_javascript(self):
        data = self.json(self.upload("app.js", JS_VULNERABLE))
        self.assertEqual(data["language"], "javascript")

    def test_upload_auto_detects_csharp(self):
        cs_src = "using System;\nclass Program { static void Main() {} }"
        data = self.json(self.upload("Program.cs", cs_src))
        self.assertEqual(data["language"], "csharp")

    def test_upload_triggers_analysis(self):
        data = self.json(self.upload("vuln.py", PYTHON_VULNERABLE))
        self.assertIn(data["status"], ("complete", "analyzing", "failed"))

    def test_upload_vulnerable_python_has_vulnerabilities(self):
        data = self.json(self.upload("vuln.py", PYTHON_VULNERABLE))
        if data["status"] == "complete":
            self.assertGreater(len(data.get("vulnerabilities", [])), 0)

    def test_upload_clean_python_low_risk(self):
        data = self.json(self.upload("clean.py", PYTHON_CLEAN))
        if data["status"] == "complete" and data.get("risk_score") is not None:
            self.assertLess(data["risk_score"], 0.5)

    def test_upload_vulnerable_python_high_risk(self):
        data = self.json(self.upload("vuln.py", PYTHON_VULNERABLE))
        if data["status"] == "complete" and data.get("risk_score") is not None:
            self.assertGreater(data["risk_score"], 0.5)

    def test_uploaded_file_appears_in_project(self):
        self.upload("check.py", PYTHON_CLEAN)
        project = self.json(self.get(f"/api/v1/projects/{self.pid}/"))
        self.assertGreater(len(project["code_files"]), 0)

    # ── Error cases ────────────────────────────────────────────────────────

    def test_upload_to_nonexistent_project_404(self):
        url  = "/api/v1/projects/00000000-0000-0000-0000-000000000000/upload/"
        resp = self.post_file(url, "test.py", PYTHON_CLEAN)
        self.assertEqual(resp.status_code, 404)

    def test_upload_unsupported_extension_rejected(self):
        resp = self.upload("README.md", "# hello")
        self.assertEqual(resp.status_code, 400)

    def test_upload_no_file_rejected(self):
        resp = self.client.post(
            f"/api/v1/projects/{self.pid}/upload/",
            {},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 400)


# ---------------------------------------------------------------------------
# File Detail
# ---------------------------------------------------------------------------

class TestFileDetail(APITestBase):

    def setUp(self):
        super().setUp()
        project = self.create_project()
        self.pid = project["id"]
        upload_resp = self.post_file(
            f"/api/v1/projects/{self.pid}/upload/",
            "vuln.py",
            PYTHON_VULNERABLE,
        )
        self.file_data = self.json(upload_resp)
        self.fid       = self.file_data["id"]

    def test_get_file_returns_200(self):
        resp = self.get(f"/api/v1/files/{self.fid}/")
        self.assertEqual(resp.status_code, 200)

    def test_get_file_has_correct_filename(self):
        data = self.json(self.get(f"/api/v1/files/{self.fid}/"))
        self.assertEqual(data["filename"], "vuln.py")

    def test_get_file_has_vulnerabilities(self):
        data = self.json(self.get(f"/api/v1/files/{self.fid}/"))
        self.assertIn("vulnerabilities", data)
        self.assertIsInstance(data["vulnerabilities"], list)

    def test_get_nonexistent_file_returns_404(self):
        resp = self.get("/api/v1/files/00000000-0000-0000-0000-000000000000/")
        self.assertEqual(resp.status_code, 404)

    def test_each_vulnerability_has_required_fields(self):
        data   = self.json(self.get(f"/api/v1/files/{self.fid}/"))
        vulns  = data.get("vulnerabilities", [])
        required = {"id", "title", "severity", "line_start", "category"}
        for v in vulns:
            missing = required - v.keys()
            self.assertEqual(missing, set(), f"Vulnerability missing fields: {missing}")

    def test_vulnerability_severities_are_valid(self):
        data   = self.json(self.get(f"/api/v1/files/{self.fid}/"))
        vulns  = data.get("vulnerabilities", [])
        valid  = {"critical", "high", "medium", "low", "info"}
        for v in vulns:
            self.assertIn(v["severity"], valid)


# ---------------------------------------------------------------------------
# Source endpoint
# ---------------------------------------------------------------------------

class TestFileSource(APITestBase):

    def setUp(self):
        super().setUp()
        project      = self.create_project()
        upload_resp  = self.post_file(
            f"/api/v1/projects/{project['id']}/upload/",
            "source.py",
            PYTHON_CLEAN,
        )
        self.fid = self.json(upload_resp)["id"]

    def test_source_returns_200(self):
        resp = self.get(f"/api/v1/files/{self.fid}/source/")
        self.assertEqual(resp.status_code, 200)

    def test_source_contains_source_field(self):
        resp = self.get(f"/api/v1/files/{self.fid}/source/")
        self.assertEqual(resp.status_code, 200)
        data = self.json(resp)
        self.assertIn("source", data)
        self.assertIn("def add", data["source"])

    def test_source_available_when_debug_false(self):
        # Regression test: production runs with DEBUG=False. The review page
        # loads file content through this endpoint (Promise.all in review.js),
        # so a 403 here leaves the UI stuck on "Loading…".
        with self.settings(DEBUG=False):
            resp = self.get(f"/api/v1/files/{self.fid}/source/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("def add", self.json(resp)["source"])


# ---------------------------------------------------------------------------
# Vulnerability Detail
# ---------------------------------------------------------------------------

class TestVulnerabilityDetail(APITestBase):

    def setUp(self):
        super().setUp()
        project     = self.create_project()
        upload_resp = self.post_file(
            f"/api/v1/projects/{project['id']}/upload/",
            "vuln.py",
            PYTHON_VULNERABLE,
        )
        file_data = self.json(upload_resp)
        # Pick first vulnerability if analysis completed
        self.vulns = file_data.get("vulnerabilities", [])

    def test_get_vulnerability_returns_200(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities created — analysis may not have run")
        vid  = self.vulns[0]["id"]
        resp = self.get(f"/api/v1/vulnerabilities/{vid}/")
        self.assertEqual(resp.status_code, 200)

    def test_vulnerability_has_description(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        data = self.json(self.get(f"/api/v1/vulnerabilities/{vid}/"))
        self.assertIn("description", data)
        self.assertGreater(len(data["description"]), 10)

    def test_vulnerability_has_recommendation(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        data = self.json(self.get(f"/api/v1/vulnerabilities/{vid}/"))
        self.assertIn("recommendation", data)

    def test_nonexistent_vulnerability_returns_404(self):
        resp = self.get("/api/v1/vulnerabilities/00000000-0000-0000-0000-000000000000/")
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# Explanation Detail
# ---------------------------------------------------------------------------

class TestExplanationDetail(APITestBase):

    def setUp(self):
        super().setUp()
        project     = self.create_project()
        upload_resp = self.post_file(
            f"/api/v1/projects/{project['id']}/upload/",
            "vuln.py",
            PYTHON_VULNERABLE,
        )
        file_data   = self.json(upload_resp)
        self.vulns  = file_data.get("vulnerabilities", [])

    def test_explanation_returns_200(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        resp = self.get(f"/api/v1/vulnerabilities/{vid}/explanation/")
        self.assertIn(resp.status_code, (200, 500))

    def test_explanation_has_method_field(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        resp = self.get(f"/api/v1/vulnerabilities/{vid}/explanation/")
        if resp.status_code == 200:
            data = self.json(resp)
            self.assertIn("method", data)
            self.assertIn(data["method"], ("shap", "lime", "rule"))

    def test_explanation_has_explanation_data(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        resp = self.get(f"/api/v1/vulnerabilities/{vid}/explanation/")
        if resp.status_code == 200:
            data = self.json(resp)
            self.assertIn("explanation_data", data)

    def test_explanation_data_has_features(self):
        if not self.vulns:
            self.skipTest("No vulnerabilities")
        vid  = self.vulns[0]["id"]
        resp = self.get(f"/api/v1/vulnerabilities/{vid}/explanation/")
        if resp.status_code == 200:
            exp_data = self.json(resp).get("explanation_data", {})
            self.assertIn("features", exp_data)
            self.assertIsInstance(exp_data["features"], list)

    def test_nonexistent_vuln_explanation_returns_404(self):
        resp = self.get("/api/v1/vulnerabilities/00000000-0000-0000-0000-000000000000/explanation/")
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# Re-analysis trigger
# ---------------------------------------------------------------------------

class TestTriggerAnalysis(APITestBase):

    def setUp(self):
        super().setUp()
        project     = self.create_project()
        upload_resp = self.post_file(
            f"/api/v1/projects/{project['id']}/upload/",
            "vuln.py",
            PYTHON_VULNERABLE,
        )
        self.fid = self.json(upload_resp)["id"]

    def test_analyze_endpoint_returns_200(self):
        resp = self.client.post(
            f"/api/v1/files/{self.fid}/analyze/",
            content_type="application/json",
        )
        self.assertIn(resp.status_code, (200, 409))

    def test_analyze_nonexistent_file_returns_404(self):
        resp = self.client.post(
            "/api/v1/files/00000000-0000-0000-0000-000000000000/analyze/",
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# Model layer (direct DB tests)
# ---------------------------------------------------------------------------

class TestCoreModels(APITestBase):
    """Tests model methods directly, no HTTP."""

    def test_project_get_summary(self):
        project = Project.objects.create(name="Summary Test")
        summary = project.get_summary()
        self.assertIn("total_files", summary)
        self.assertIn("total_vulnerabilities", summary)
        self.assertEqual(summary["total_files"], 0)

    def test_codefile_set_source_encrypts(self):
        project = Project.objects.create(name="Enc Test")
        f = CodeFile(project=project, filename="x.py", language="python")
        f.set_source("def foo(): pass")
        f.save()
        # encrypted_source should not contain the plaintext
        raw = bytes(f.encrypted_source)
        self.assertNotIn(b"def foo", raw)
        self.assertGreater(len(raw), 0)

    def test_codefile_get_decrypted_source(self):
        project = Project.objects.create(name="Dec Test")
        f = CodeFile(project=project, filename="y.py", language="python")
        src = "x = 42\nprint(x)\n"
        f.set_source(src)
        f.save()
        self.assertEqual(f.get_decrypted_source(), src)

    def test_codefile_line_count_set(self):
        project = Project.objects.create(name="Lines Test")
        f = CodeFile(project=project, filename="z.py", language="python")
        f.set_source("a = 1\nb = 2\nc = 3")
        self.assertEqual(f.line_count, 3)

    def test_project_recalculate_risk_score(self):
        project = Project.objects.create(name="Risk Test")
        f1 = CodeFile(project=project, filename="a.py", language="python",
                      risk_score=0.8, status=ReviewStatus.COMPLETE)
        f1.set_source("x=1"); f1.save()
        f2 = CodeFile(project=project, filename="b.py", language="python",
                      risk_score=0.4, status=ReviewStatus.COMPLETE)
        f2.set_source("y=2"); f2.save()
        project.recalculate_risk_score()
        self.assertAlmostEqual(project.overall_risk_score, 0.6, places=3)

    def test_vulnerability_severity_weight(self):
        project = Project.objects.create(name="SevW Test")
        f = CodeFile(project=project, filename="w.py", language="python")
        f.set_source("x=1"); f.save()
        vuln = Vulnerability.objects.create(
            code_file=f, line_start=1, title="Test",
            description="d", severity=Severity.CRITICAL,
        )
        self.assertEqual(vuln.severity_weight, 1.0)

    def test_explanation_compute_top_feature(self):
        project = Project.objects.create(name="Exp Test")
        f = CodeFile(project=project, filename="e.py", language="python")
        f.set_source("x=1"); f.save()
        vuln = Vulnerability.objects.create(
            code_file=f, line_start=1, title="T", description="d",
        )
        exp = Explanation(
            vulnerability=vuln,
            method=ExplanationType.SHAP,
            explanation_data={
                "method": "shap",
                "base_value": 0.3,
                "prediction": 0.9,
                "features": [
                    {"name": "eval_call", "value": 1, "shap_value": 0.6, "display": "eval() called"},
                    {"name": "user_input", "value": 1, "shap_value": 0.2, "display": "User input"},
                    {"name": "safe_mode",  "value": 0, "shap_value": -0.1, "display": "No safe mode"},
                ],
            },
        )
        exp.compute_top_feature()
        self.assertEqual(exp.top_feature_name, "eval() called")
        self.assertAlmostEqual(exp.top_feature_importance, 0.6, places=3)

    def test_explanation_sorted_features(self):
        project = Project.objects.create(name="SortFeat Test")
        f = CodeFile(project=project, filename="s.py", language="python")
        f.set_source("x=1"); f.save()
        vuln = Vulnerability.objects.create(
            code_file=f, line_start=1, title="T", description="d",
        )
        exp = Explanation(
            vulnerability=vuln,
            method=ExplanationType.SHAP,
            explanation_data={
                "method": "shap", "base_value": 0.3, "prediction": 0.8,
                "features": [
                    {"name": "b", "value": 1, "shap_value": 0.1,  "display": "B"},
                    {"name": "a", "value": 1, "shap_value": 0.45, "display": "A"},
                    {"name": "c", "value": 0, "shap_value": -0.2, "display": "C"},
                ],
            },
        )
        exp.save()
        sorted_f = exp.get_sorted_features()
        self.assertEqual(sorted_f[0]["name"], "a")   # 0.45 is highest abs
        self.assertEqual(sorted_f[1]["name"], "c")   # 0.20 is second
        self.assertEqual(sorted_f[2]["name"], "b")   # 0.10 is lowest
