# CodeLens REST API Reference

Base URL: `http://localhost:8000/api/v1`

All responses are JSON. All UUIDs are version 4.

---

## Health

### GET /health/
```json
{
  "status": "ok",
  "service": "AI Code Review Assistant",
  "version": "1.0.0",
  "database": "connected"
}
```
With `?services=1`, the response additionally includes a `"microservices"`
object probing the Java and C# services (opt-in — the default response stays
fast for the Docker healthcheck).

---

## Projects

### GET /projects/
List all projects.
```json
{
  "count": 2,
  "results": [
    {
      "id": "uuid",
      "name": "My Project",
      "description": "...",
      "overall_risk_score": 0.87,
      "created_at": "2025-01-01T00:00:00Z",
      "summary": {
        "total_files": 2,
        "completed_files": 2,
        "total_vulnerabilities": 5,
        "critical_count": 2,
        "high_count": 1
      }
    }
  ]
}
```

### POST /projects/
Create a project.
```json
// Request
{ "name": "My Project", "description": "optional" }
// Response 201
{ "id": "uuid", "name": "My Project", ... }
```

### GET /projects/{uuid}/
Project detail with all files.

### DELETE /projects/{uuid}/
Delete project and all files. Returns 204.

---

## Files

### POST /projects/{uuid}/upload/
Upload a file for analysis. Multipart form-data.

Fields:
- `file` — The source code file (required)
- `language` — Override auto-detection: `python|java|csharp|javascript` (optional)

```json
// Response 201 — full CodeFile with vulnerabilities
{
  "id": "uuid",
  "filename": "auth.py",
  "language": "python",
  "status": "complete",
  "risk_score": 0.91,
  "vulnerabilities": [
    {
      "id": "uuid",
      "title": "SQL Injection",
      "severity": "critical",
      "line_start": 9,
      "code_snippet": "...",
      "cwe_id": "CWE-89"
    }
  ]
}
```

### GET /files/{uuid}/
File detail with all vulnerabilities.

### POST /files/{uuid}/analyze/
Re-trigger analysis. Clears existing findings and re-runs.
```json
{ "status": "complete", "risk_score": 0.91, "vulnerability_count": 4 }
```

### GET /files/{uuid}/source/
Returns decrypted source code. **DEBUG mode only.**
```json
{ "filename": "auth.py", "language": "python", "source": "import sqlite3..." }
```

---

## Vulnerabilities

### GET /vulnerabilities/{uuid}/
Full vulnerability detail.
```json
{
  "id": "uuid",
  "title": "SQL Injection",
  "severity": "critical",
  "category": "security",
  "line_start": 9,
  "description": "...",
  "recommendation": "...",
  "code_snippet": "...",
  "fixed_snippet": "...",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021 – Injection",
  "confidence_score": 0.97
}
```

### GET /vulnerabilities/{uuid}/explanation/
SHAP-style explanation for a vulnerability (illustrative attribution —
generated from a built-in rule-weight model, not a trained estimator).
```json
{
  "id": "uuid",
  "method": "shap",
  "summary": "The model flagged this because...",
  "top_feature_name": "SQL string concatenation detected",
  "top_feature_importance": 0.38,
  "explanation_data": {
    "method": "shap",
    "base_value": 0.35,
    "prediction": 0.97,
    "features": [
      { "name": "sql_string_concat", "value": 1, "shap_value": 0.38, "display": "SQL string concatenation detected" },
      { "name": "user_input_present", "value": 1, "shap_value": 0.22, "display": "Unvalidated user input in scope" }
    ]
  }
}
```

---

## Java Service (Port 9090)

### POST http://localhost:9090/compile
```json
// Request
{ "source_code": "public class Hello {...}", "check_only": true }
// Response
{ "compile_ok": true, "diagnostics": [], "duration_ms": 120 }
```

---

## C# Daemon (Port 9091)

### POST http://localhost:9091/analyze
```json
// Request
{ "source_code": "using System; class Program {...}", "semantic_analysis": false }
// Response
{ "syntax_ok": true, "findings": [...], "metrics": {...}, "duration_ms": 45 }
```
