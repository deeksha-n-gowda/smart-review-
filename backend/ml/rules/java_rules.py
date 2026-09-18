"""
ml/rules/java_rules.py — Java Vulnerability Rules
"""
import re

def _re(pattern, flags=0):
    return re.compile(pattern, re.IGNORECASE | flags)

SECURITY_RULES = [
    {
        "id": "JAVA-SEC-001",
        "title": "SQL Injection",
        "description": (
            "String concatenation used to build SQL query — classic SQL injection. "
            "An attacker can manipulate the query to bypass authentication or exfiltrate data."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'(?:createQuery|createNativeQuery|prepareStatement|executeQuery)\s*\([^)]*\+'),
        "recommendation": (
            "Use PreparedStatement with parameterized queries:\n"
            "  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
            "  ps.setInt(1, userId);"
        ),
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.87,
        "shap_features": [
            "sql_concat_in_query", "prepared_statement_absent", "user_input_present",
            "parameterized_query", "orm_usage",
        ],
    },
    {
        "id": "JAVA-SEC-002",
        "title": "Hardcoded Password / Credential",
        "description": (
            "A password, secret, or API key appears hardcoded in Java source. "
            "These are included in compiled bytecode, which is trivially decompilable."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(
            r'(?:password|passwd|secret|apiKey|token)\s*=\s*"[^"]{6,}"'
        ),
        "recommendation": (
            "Load credentials from environment variables or a secrets manager:\n"
            "  String password = System.getenv(\"DB_PASSWORD\");"
        ),
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "confidence": 0.82,
        "shap_features": [
            "hardcoded_string_credential", "env_var_usage", "secrets_manager_usage",
            "credential_keyword", "decompilation_risk",
        ],
    },
    {
        "id": "JAVA-SEC-003",
        "title": "Insecure Deserialization",
        "description": (
            "ObjectInputStream.readObject() can execute arbitrary code during deserialization "
            "if the input stream is from an untrusted source (network, user upload)."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\bObjectInputStream\b.*\breadObject\s*\(|\.readObject\s*\(\)'),
        "recommendation": (
            "Implement a deserialization filter (Java 9+):\n"
            "  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"maxdepth=5;...\");\n"
            "Or use JSON/Protocol Buffers instead of native serialization for external data."
        ),
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "confidence": 0.80,
        "shap_features": [
            "object_input_stream", "read_object_call", "untrusted_source",
            "deserialization_filter", "json_alternative",
        ],
    },
    {
        "id": "JAVA-SEC-004",
        "title": "Weak Random Number Generation",
        "description": (
            "java.util.Random is not cryptographically secure. Its output can be predicted "
            "after observing a small number of values."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(r'\bnew\s+Random\s*\(\)'),
        "recommendation": "Use java.security.SecureRandom for security-sensitive operations.",
        "cwe_id": "CWE-338",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.75,
        "shap_features": [
            "util_random_usage", "secure_random_absent", "security_context",
            "token_generation_context",
        ],
    },
    {
        "id": "JAVA-SEC-005",
        "title": "Null Pointer Dereference Risk",
        "description": (
            "Method chaining on an object that could be null without a null check. "
            "This may cause NullPointerException at runtime."
        ),
        "severity": "medium",
        "category": "correctness",
        "pattern": _re(r'\w+\.get\w*\(\)\.\w+\('),
        "recommendation": (
            "Add null checks or use Optional:\n"
            "  Optional.ofNullable(obj.getValue()).ifPresent(v -> v.process());"
        ),
        "cwe_id": "CWE-476",
        "owasp_category": "",
        "confidence": 0.55,
        "shap_features": ["null_check_missing", "method_chaining", "optional_usage", "npe_risk"],
    },
    {
        "id": "JAVA-SEC-006",
        "title": "printStackTrace() in Production",
        "description": (
            "Exception.printStackTrace() outputs to stderr and may expose stack traces "
            "containing internal paths, class names, and logic to end users or logs."
        ),
        "severity": "low",
        "category": "maintainability",
        "pattern": _re(r'\.printStackTrace\s*\(\)'),
        "recommendation": "Use a structured logger (SLF4J/Logback): logger.error(\"Error occurred\", e);",
        "cwe_id": "CWE-532",
        "owasp_category": "",
        "confidence": 0.88,
        "shap_features": ["print_stack_trace", "logger_absent", "sensitive_info_exposure", "error_handling"],
    },
]

MAINTAINABILITY_RULES = [
    {
        "id": "JAVA-MAINT-001",
        "title": "Empty catch Block",
        "description": "Empty catch block silently swallows exceptions, making bugs invisible.",
        "severity": "medium",
        "category": "maintainability",
        "pattern": _re(r'catch\s*\([^)]+\)\s*\{\s*\}'),
        "recommendation": "At minimum log the exception: logger.error(\"Unexpected error\", e);",
        "cwe_id": "CWE-390",
        "owasp_category": "",
        "confidence": 0.90,
        "shap_features": ["empty_catch_block", "exception_swallowed", "logging_absent"],
    },
    {
        "id": "JAVA-MAINT-002",
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
