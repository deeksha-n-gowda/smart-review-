"""
ml/rules/csharp_rules.py — C# Vulnerability Rules
"""
import re

def _re(pattern, flags=0):
    return re.compile(pattern, re.IGNORECASE | flags)

SECURITY_RULES = [
    {
        "id": "CS-SEC-001",
        "title": "SQL Injection",
        "description": (
            "String concatenation used to build SQL commands. "
            "An attacker can manipulate the query to bypass authentication or extract data."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'(?:SqlCommand|ExecuteNonQuery|ExecuteReader|ExecuteScalar)\s*\([^)]*\+'),
        "recommendation": (
            "Use parameterized queries or Dapper/EF Core:\n"
            "  var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id=@id\", conn);\n"
            "  cmd.Parameters.AddWithValue(\"@id\", userId);"
        ),
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.88,
        "shap_features": [
            "sql_concat_command", "sqlcommand_usage", "parameterized_query_absent",
            "user_input_present", "ef_core_usage",
        ],
    },
    {
        "id": "CS-SEC-002",
        "title": "Hardcoded Connection String / Credential",
        "description": (
            "A database connection string, password, or API key appears hardcoded. "
            "These end up in compiled assemblies and version control history."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(
            r'(?:connectionString|password|Password|ApiKey|Secret)\s*=\s*"[^"]{8,}"'
        ),
        "recommendation": (
            "Use configuration files (appsettings.json) with environment variable overrides, "
            "or Azure Key Vault / AWS Secrets Manager for production secrets."
        ),
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "confidence": 0.80,
        "shap_features": [
            "hardcoded_connection_string", "credential_keyword", "env_var_usage",
            "key_vault_usage", "config_file_pattern",
        ],
    },
    {
        "id": "CS-SEC-003",
        "title": "Insecure Deserialization (BinaryFormatter)",
        "description": (
            "BinaryFormatter is insecure and has been marked obsolete in .NET 5+. "
            "It can execute arbitrary code when deserializing untrusted data."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\bBinaryFormatter\b'),
        "recommendation": (
            "Use System.Text.Json or Newtonsoft.Json for cross-platform data. "
            "For binary formats, use MessagePack or Protocol Buffers."
        ),
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "confidence": 0.92,
        "shap_features": [
            "binary_formatter_usage", "untrusted_source", "json_alternative",
            "obsolete_api", "deserialization_risk",
        ],
    },
    {
        "id": "CS-SEC-004",
        "title": "Weak Cryptography (MD5/SHA1)",
        "description": "MD5 and SHA1 are cryptographically broken and must not be used for security purposes.",
        "severity": "high",
        "category": "security",
        "pattern": _re(r'MD5\.Create\(\)|SHA1\.Create\(\)|new\s+MD5CryptoServiceProvider|new\s+SHA1CryptoServiceProvider'),
        "recommendation": "Use SHA-256 or SHA-3: SHA256.Create() or SHA256.HashData(data).",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.95,
        "shap_features": [
            "md5_sha1_usage", "sha256_alternative", "password_context",
            "security_context", "bcrypt_usage",
        ],
    },
    {
        "id": "CS-SEC-005",
        "title": "Path Traversal",
        "description": (
            "User-controlled input used to construct a file path without validation. "
            "An attacker can use '../' sequences to read or write arbitrary files."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'(?:File\.Read|File\.Write|File\.Open|Path\.Combine)\s*\([^)]*Request\.\w+'),
        "recommendation": (
            "Validate paths with Path.GetFullPath() and confirm they stay within the allowed root:\n"
            "  var fullPath = Path.GetFullPath(Path.Combine(rootDir, userInput));\n"
            "  if (!fullPath.StartsWith(rootDir)) throw new UnauthorizedAccessException();"
        ),
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021 – Broken Access Control",
        "confidence": 0.78,
        "shap_features": [
            "file_operation_with_user_input", "path_validation_missing",
            "getfullpath_check", "root_dir_check",
        ],
    },
    {
        "id": "CS-SEC-006",
        "title": "XSS via Response.Write()",
        "description": (
            "Response.Write() with user-supplied data without HTML encoding enables XSS. "
            "The user's input is rendered directly as HTML in the browser."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'Response\.Write\s*\([^)]*Request\.'),
        "recommendation": (
            "HTML-encode output:\n"
            "  Response.Write(HttpUtility.HtmlEncode(userInput));\n"
            "Or use Razor views which auto-encode by default."
        ),
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.85,
        "shap_features": [
            "response_write_user_input", "html_encoding_absent", "razor_view_absent",
            "xss_context",
        ],
    },
]

MAINTAINABILITY_RULES = [
    {
        "id": "CS-MAINT-001",
        "title": "Empty catch Block",
        "description": "Empty catch block silently swallows exceptions, hiding bugs.",
        "severity": "medium",
        "category": "maintainability",
        "pattern": _re(r'catch\s*(?:\([^)]+\))?\s*\{\s*\}'),
        "recommendation": "At minimum log: _logger.LogError(ex, \"Unexpected error\");",
        "cwe_id": "CWE-390",
        "owasp_category": "",
        "confidence": 0.90,
        "shap_features": ["empty_catch_block", "exception_swallowed", "logging_absent"],
    },
    {
        "id": "CS-MAINT-002",
        "title": "TODO / FIXME Comment",
        "description": "Known unfinished or potentially broken code marker left in source.",
        "severity": "info",
        "category": "maintainability",
        "pattern": _re(r'//\s*(?:TODO|FIXME|HACK|XXX)\b'),
        "recommendation": "Create a tracked issue and remove or resolve the comment.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.99,
        "shap_features": ["todo_comment", "fixme_comment", "comment_quality"],
    },
]

ALL_RULES = SECURITY_RULES + MAINTAINABILITY_RULES
RULES_BY_ID = {r["id"]: r for r in ALL_RULES}
