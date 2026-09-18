"""
ml/rules/python_rules.py — Python Vulnerability Rules
=======================================================
Defines the complete rule set for static analysis of Python source code.
Each rule dict is applied line-by-line (or file-level for complexity rules)
by PythonAnalyzer in analyzer.py.

Rule keys:
    id            Unique rule identifier e.g. "PY-SEC-001"
    title         Short human-readable name
    description   Full vulnerability explanation
    severity      "critical"|"high"|"medium"|"low"|"info"
    category      VulnCategory string
    pattern       compiled re — matched against individual lines (None = file-level only)
    recommendation How to fix
    cwe_id        CWE reference
    owasp_category OWASP Top 10 mapping
    confidence    Base confidence score 0.0–1.0
    shap_features List of feature names for SHAP explanation
"""

import re

def _re(pattern, flags=0):
    return re.compile(pattern, re.IGNORECASE | flags)


SECURITY_RULES = [
    {
        "id": "PY-SEC-001",
        "title": "SQL Injection",
        "description": (
            "User-supplied input is concatenated directly into a SQL query string "
            "without sanitization or parameterization. An attacker can manipulate "
            "the query to bypass authentication, extract arbitrary data, or destroy records."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(
            r'(?:execute|cursor\.execute|db\.execute|conn\.execute)\s*\('
            r'[^)]*(?:\+\s*\w+|\bformat\b|\bf["\']|\%\s*\w)'
        ),
        "recommendation": (
            "Use parameterized queries:\n"
            "  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
            "Or use an ORM such as Django ORM or SQLAlchemy."
        ),
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.88,
        "shap_features": [
            "sql_string_concat", "user_input_present", "parameterized_query",
            "input_sanitization", "orm_usage", "raw_execute_call",
        ],
    },
    {
        "id": "PY-SEC-001b",
        "title": "SQL Injection (String Formatting)",
        "description": (
            "SQL query built using str.format() or f-strings with variables — "
            "equivalent to string concatenation and equally vulnerable to injection."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(
            r'(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*(?:\.format\(|f[\'"].*\{)'
        ),
        "recommendation": "Never use .format() or f-strings to build SQL queries. Use parameterized queries.",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.82,
        "shap_features": [
            "sql_format_string", "fstring_in_sql", "parameterized_query",
            "input_sanitization", "orm_usage",
        ],
    },
    {
        "id": "PY-SEC-002",
        "title": "OS Command Injection",
        "description": (
            "User-controlled input passed directly to os.system(). An attacker can "
            "inject shell metacharacters (;, &&, |, $()) to execute arbitrary commands."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\bos\.system\s*\([^)]*(?:\+|\bformat\b|f[\'"])'),
        "recommendation": (
            "Use subprocess.run() with a list and shell=False:\n"
            "  subprocess.run(['command', arg1, arg2], shell=False, check=True)"
        ),
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.93,
        "shap_features": [
            "os_system_call", "shell_true_flag", "user_input_concat",
            "subprocess_list_args", "input_validation",
        ],
    },
    {
        "id": "PY-SEC-002b",
        "title": "Subprocess Shell Injection",
        "description": (
            "subprocess called with shell=True and a string argument that may include "
            "user-controlled data — equivalent to os.system() injection risk."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True'),
        "recommendation": "Use shell=False and pass arguments as a list.",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.78,
        "shap_features": [
            "shell_true_flag", "subprocess_string_arg", "user_input_present",
            "subprocess_list_args", "input_validation",
        ],
    },
    {
        "id": "PY-SEC-003",
        "title": "Code Injection via eval()",
        "description": (
            "eval() executes arbitrary Python code from a string. If the argument "
            "is user-controlled, this allows full system compromise."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\beval\s*\('),
        "recommendation": (
            "Remove eval() entirely. Use ast.literal_eval() for safe literals, "
            "or a function dispatch dict for dynamic behavior."
        ),
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.92,
        "shap_features": [
            "eval_call", "external_arg_passed", "function_param_origin",
            "sandboxing_present", "allowlist_check",
        ],
    },
    {
        "id": "PY-SEC-003b",
        "title": "Code Injection via exec()",
        "description": "exec() compiles and executes arbitrary Python code — same injection risk as eval().",
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\bexec\s*\('),
        "recommendation": "Remove exec(). Refactor to use explicit function calls or a dispatch table.",
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.90,
        "shap_features": [
            "exec_call", "external_arg_passed", "function_param_origin",
            "sandboxing_present", "allowlist_check",
        ],
    },
    {
        "id": "PY-SEC-004",
        "title": "Weak Cryptographic Hash (MD5)",
        "description": (
            "MD5 is cryptographically broken. Collision attacks are trivial and "
            "rainbow tables for common passwords are widely available."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\bhashlib\.md5\b|MD5\s*\('),
        "recommendation": (
            "For passwords: use bcrypt, scrypt, or Argon2.\n"
            "For integrity: use SHA-256 — hashlib.sha256(data).hexdigest()"
        ),
        "cwe_id": "CWE-916",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.97,
        "shap_features": [
            "md5_hash_usage", "password_context", "bcrypt_present",
            "salt_usage", "sha256_alternative",
        ],
    },
    {
        "id": "PY-SEC-004b",
        "title": "Weak Cryptographic Hash (SHA-1)",
        "description": (
            "SHA-1 is cryptographically weak — practical collision attacks demonstrated in 2017. "
            "Do not use for security-sensitive purposes."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(r'\bhashlib\.sha1\b'),
        "recommendation": "Use SHA-256 or SHA-3 for new code. For passwords, use bcrypt/Argon2.",
        "cwe_id": "CWE-327",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.90,
        "shap_features": [
            "sha1_hash_usage", "password_context", "sha256_alternative",
            "security_context", "salt_usage",
        ],
    },
    {
        "id": "PY-SEC-005",
        "title": "Hardcoded Secret / Credential",
        "description": (
            "A credential, API key, password, or secret token appears hardcoded in source. "
            "These are easily discovered through version control history and cannot be "
            "rotated without a code change."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(
            r'(?:password|passwd|secret|api_key|apikey|token|auth|credential)\s*='
            r'\s*["\'][^"\']{6,}["\']'
        ),
        "recommendation": (
            "Store secrets in environment variables or a secrets manager.\n"
            "  import os; password = os.environ['DB_PASSWORD']"
        ),
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "confidence": 0.80,
        "shap_features": [
            "hardcoded_string_assignment", "credential_keyword", "env_var_usage",
            "secrets_manager_usage", "string_length",
        ],
    },
    {
        "id": "PY-SEC-006",
        "title": "Insecure Deserialization (pickle)",
        "description": (
            "pickle.loads() can execute arbitrary code during deserialization. "
            "Deserializing pickle data from an untrusted source enables remote code execution."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\bpickle\.loads?\s*\('),
        "recommendation": (
            "Never deserialize pickle from untrusted sources. "
            "Use JSON, MessagePack, or Protocol Buffers for external data exchange."
        ),
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "confidence": 0.85,
        "shap_features": [
            "pickle_loads_call", "untrusted_source", "signature_verification",
            "json_alternative", "data_origin",
        ],
    },
    {
        "id": "PY-SEC-007",
        "title": "Unsafe YAML Deserialization",
        "description": (
            "yaml.load() without SafeLoader can execute arbitrary Python code "
            "embedded in the YAML payload, enabling remote code execution."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\byaml\.load\s*\((?![^)]*SafeLoader)'),
        "recommendation": "Always use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "confidence": 0.83,
        "shap_features": [
            "yaml_load_call", "safe_loader_missing", "untrusted_input",
            "yaml_safe_load_alternative", "data_origin",
        ],
    },
    {
        "id": "PY-SEC-008",
        "title": "Path Traversal",
        "description": (
            "User-controlled input used to construct a file path without validation. "
            "An attacker can include '../' sequences to escape the intended directory."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\bopen\s*\([^)]*(?:\+\s*\w+|\.format\s*\(|f["\'])'),
        "recommendation": (
            "Validate paths with os.path.realpath() and confirm they stay within the allowed root:\n"
            "  safe = os.path.realpath(os.path.join(base_dir, user_input))\n"
            "  assert safe.startswith(base_dir)"
        ),
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021 – Broken Access Control",
        "confidence": 0.72,
        "shap_features": [
            "open_with_user_input", "path_validation_missing", "realpath_check",
            "base_dir_check", "user_controlled_path",
        ],
    },
    {
        "id": "PY-SEC-009",
        "title": "Insecure Random Number Generation",
        "description": (
            "The random module uses Mersenne Twister which is not cryptographically secure. "
            "Its output can be predicted if enough values are observed."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(
            r'\brandom\.(?:random|randint|choice|randrange|shuffle|sample)\s*\('
        ),
        "recommendation": (
            "Use the secrets module:\n"
            "  import secrets\n"
            "  token = secrets.token_hex(32)\n"
            "  choice = secrets.choice(options)"
        ),
        "cwe_id": "CWE-338",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.70,
        "shap_features": [
            "random_module_usage", "security_context", "secrets_module_absent",
            "token_generation_context", "session_context",
        ],
    },
    {
        "id": "PY-SEC-010",
        "title": "Flask Debug Mode Enabled",
        "description": (
            "Flask running with debug=True enables an interactive browser debugger "
            "that allows arbitrary Python code execution and must never reach production."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\bapp\.run\s*\([^)]*debug\s*=\s*True'),
        "recommendation": (
            "Control debug mode via environment variable:\n"
            "  app.run(debug=os.environ.get('FLASK_DEBUG','false').lower()=='true')"
        ),
        "cwe_id": "CWE-94",
        "owasp_category": "A05:2021 – Security Misconfiguration",
        "confidence": 0.95,
        "shap_features": [
            "debug_true_flag", "production_context", "env_var_control",
            "flask_app_run", "debug_false_alternative",
        ],
    },
]

MAINTAINABILITY_RULES = [
    {
        "id": "PY-MAINT-001",
        "title": "Bare except Clause",
        "description": (
            "A bare 'except:' catches everything including SystemExit and KeyboardInterrupt, "
            "suppressing signals and masking genuine errors."
        ),
        "severity": "medium",
        "category": "maintainability",
        "pattern": _re(r'^\s*except\s*:'),
        "recommendation": "Catch specific exceptions: except (ValueError, TypeError) as e:",
        "cwe_id": "CWE-390",
        "owasp_category": "",
        "confidence": 0.92,
        "shap_features": [
            "bare_except", "specific_exception_missing", "exception_logging",
            "error_handling_quality", "broad_catch",
        ],
    },
    {
        "id": "PY-MAINT-002",
        "title": "Mutable Default Argument",
        "description": (
            "Mutable default argument (list/dict/set) is shared across all calls, "
            "leading to subtle state accumulation bugs."
        ),
        "severity": "medium",
        "category": "correctness",
        "pattern": _re(r'def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|list\(\)|dict\(\)|set\(\))'),
        "recommendation": "Use None as default and initialise inside the function body.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.88,
        "shap_features": [
            "mutable_default_arg", "list_default", "dict_default",
            "none_default_pattern", "function_def",
        ],
    },
    {
        "id": "PY-MAINT-003",
        "title": "TODO / FIXME Comment",
        "description": "Known unfinished or potentially broken code marker left in source.",
        "severity": "info",
        "category": "maintainability",
        "pattern": _re(r'#\s*(?:TODO|FIXME|HACK|XXX|BUG)\b'),
        "recommendation": "Create a tracked issue and remove or resolve the comment.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.99,
        "shap_features": ["todo_comment", "fixme_comment", "issue_tracker_reference", "comment_quality"],
    },
    {
        "id": "PY-MAINT-004",
        "title": "print() Statement (Debug Leftover)",
        "description": (
            "print() in production can leak sensitive data to stdout, "
            "which may be aggregated into centralised logging systems."
        ),
        "severity": "low",
        "category": "maintainability",
        "pattern": _re(r'^\s*print\s*\('),
        "recommendation": "Replace print() with the logging module at the appropriate level.",
        "cwe_id": "CWE-532",
        "owasp_category": "",
        "confidence": 0.75,
        "shap_features": ["print_statement", "logging_module_absent", "sensitive_data_in_print", "debug_context"],
    },
]

PERFORMANCE_RULES = [
    {
        "id": "PY-PERF-001",
        "title": "String Concatenation in Loop",
        "description": (
            "String '+=' inside a loop creates a new object each iteration (O(n²)). "
            "For large data this causes significant performance degradation."
        ),
        "severity": "medium",
        "category": "performance",
        "pattern": _re(r'\w+\s*\+=\s*["\'\w]'),
        "recommendation": "Accumulate into a list and join: result = ''.join(parts)",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.60,
        "shap_features": ["string_concat_in_loop", "loop_context", "list_join_pattern", "data_size_indicator"],
    },
]

COMPLEXITY_RULES = [
    {
        "id": "PY-CMPLX-001",
        "title": "High Cyclomatic Complexity",
        "description": (
            "Function has cyclomatic complexity above the recommended threshold of 10. "
            "High complexity strongly correlates with defect density."
        ),
        "severity": "medium",
        "category": "complexity",
        "pattern": None,  # Applied at file level, not per-line
        "recommendation": "Refactor by extracting sub-functions and reducing conditional nesting.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.85,
        "shap_features": [
            "cyclomatic_complexity", "branch_count", "nesting_depth",
            "function_length", "return_count",
        ],
    },
]

ALL_RULES = SECURITY_RULES + MAINTAINABILITY_RULES + PERFORMANCE_RULES + COMPLEXITY_RULES
RULES_BY_ID = {r["id"]: r for r in ALL_RULES}
