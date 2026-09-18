"""
ml/rules/javascript_rules.py — JavaScript Vulnerability Rules
"""
import re

def _re(pattern, flags=0):
    return re.compile(pattern, re.IGNORECASE | flags)

SECURITY_RULES = [
    {
        "id": "JS-SEC-001",
        "title": "Cross-Site Scripting (XSS) via innerHTML",
        "description": (
            "User-controlled data assigned to element.innerHTML without sanitization. "
            "If the data contains HTML or JavaScript it will execute in the user's browser, "
            "potentially stealing cookies or performing actions on their behalf."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\.innerHTML\s*=(?!=)'),
        "recommendation": (
            "Use element.textContent for plain text, or DOMPurify.sanitize() for HTML:\n"
            "  element.textContent = userInput;\n"
            "  element.innerHTML = DOMPurify.sanitize(htmlInput);"
        ),
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.85,
        "shap_features": [
            "inner_html_assignment", "api_response_data", "dom_purify_present",
            "text_content_used", "user_input_source",
        ],
    },
    {
        "id": "JS-SEC-001b",
        "title": "XSS via document.write()",
        "description": (
            "document.write() with user-controlled input enables XSS. "
            "Additionally, document.write() blocks the HTML parser and should be avoided."
        ),
        "severity": "high",
        "category": "security",
        "pattern": _re(r'\bdocument\.write\s*\('),
        "recommendation": "Replace document.write() with DOM manipulation (createElement, textContent).",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.82,
        "shap_features": [
            "document_write_call", "user_input_source", "dom_manipulation_alternative",
            "parser_blocking", "xss_context",
        ],
    },
    {
        "id": "JS-SEC-002",
        "title": "Dangerous eval() Usage",
        "description": (
            "eval() executes arbitrary JavaScript code from a string. "
            "If the argument is user-controlled or from an untrusted source, "
            "this enables code injection."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(r'\beval\s*\('),
        "recommendation": (
            "Remove eval() entirely. Use a whitelist of allowed operations, "
            "or restructure the logic to avoid dynamic code execution."
        ),
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021 – Injection",
        "confidence": 0.96,
        "shap_features": [
            "eval_call", "external_arg_passed", "function_param_origin",
            "sandboxing_present", "allowlist_check",
        ],
    },
    {
        "id": "JS-SEC-003",
        "title": "Sensitive Data in localStorage",
        "description": (
            "Authentication tokens or sensitive preferences stored in localStorage "
            "are accessible to any JavaScript on the page. An XSS vulnerability "
            "anywhere on the site would allow token theft."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(r'localStorage\.setItem\s*\([^,]*(?:token|auth|password|secret|key)'),
        "recommendation": (
            "Store authentication tokens in HttpOnly cookies set by the server. "
            "These are inaccessible to JavaScript even in the presence of XSS."
        ),
        "cwe_id": "CWE-312",
        "owasp_category": "A02:2021 – Cryptographic Failures",
        "confidence": 0.85,
        "shap_features": [
            "localstorage_sensitive_data", "token_storage", "httponly_cookie_absent",
            "xss_reachability", "data_sensitivity",
        ],
    },
    {
        "id": "JS-SEC-004",
        "title": "Prototype Pollution Risk",
        "description": (
            "Object.assign() or direct property assignment with unsanitized user-controlled "
            "keys can pollute Object.prototype, affecting all objects and potentially "
            "enabling privilege escalation or denial of service."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(r'Object\.assign\s*\([^)]*JSON\.parse'),
        "recommendation": (
            "Validate that keys do not include '__proto__', 'constructor', or 'prototype':\n"
            "  const safe = Object.create(null);\n"
            "  Object.entries(parsed).filter(([k]) => !['__proto__','constructor'].includes(k))\n"
            "    .forEach(([k, v]) => safe[k] = v);"
        ),
        "cwe_id": "CWE-1321",
        "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        "confidence": 0.72,
        "shap_features": [
            "object_assign_call", "json_parse_input", "proto_key_check",
            "hasown_property_check", "prototype_chain_access",
        ],
    },
    {
        "id": "JS-SEC-005",
        "title": "Hardcoded API Key or Secret",
        "description": (
            "An API key, token, or secret appears hardcoded in JavaScript source. "
            "Client-side code is visible to all users — any secret here is effectively public."
        ),
        "severity": "critical",
        "category": "security",
        "pattern": _re(
            r'(?:api_?key|apikey|secret|token|password|auth)\s*[:=]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']'
        ),
        "recommendation": (
            "Never put secrets in client-side JavaScript. "
            "Call a backend endpoint that holds the secret server-side."
        ),
        "cwe_id": "CWE-798",
        "owasp_category": "A07:2021 – Identification and Authentication Failures",
        "confidence": 0.78,
        "shap_features": [
            "hardcoded_secret_string", "credential_keyword", "client_side_code",
            "backend_proxy_missing", "string_entropy",
        ],
    },
    {
        "id": "JS-SEC-006",
        "title": "Insecure postMessage Target Origin",
        "description": (
            "postMessage() called with '*' as targetOrigin sends the message to any origin. "
            "If the message contains sensitive data, any malicious page can intercept it."
        ),
        "severity": "medium",
        "category": "security",
        "pattern": _re(r'\.postMessage\s*\([^,]+,\s*["\'][*]["\']'),
        "recommendation": (
            "Always specify the exact target origin:\n"
            "  window.postMessage(data, 'https://trusted.example.com')"
        ),
        "cwe_id": "CWE-346",
        "owasp_category": "A01:2021 – Broken Access Control",
        "confidence": 0.90,
        "shap_features": [
            "wildcard_target_origin", "postmessage_call", "sensitive_data_in_message",
            "specific_origin_missing",
        ],
    },
]

MAINTAINABILITY_RULES = [
    {
        "id": "JS-MAINT-001",
        "title": "console.log() in Production Code",
        "description": (
            "console.log() statements left in production code may expose sensitive "
            "data in browser developer tools, which are accessible to end users."
        ),
        "severity": "low",
        "category": "maintainability",
        "pattern": _re(r'\bconsole\.(?:log|debug|dir)\s*\('),
        "recommendation": "Remove console.log() calls. Use a structured logging library with log levels.",
        "cwe_id": "CWE-532",
        "owasp_category": "",
        "confidence": 0.80,
        "shap_features": ["console_log_present", "debug_output", "sensitive_data_risk", "logging_library_absent"],
    },
    {
        "id": "JS-MAINT-002",
        "title": "=== vs == Comparison",
        "description": (
            "Using == (loose equality) instead of === (strict equality) invokes type coercion "
            "which can produce unexpected results e.g. 0 == false → true."
        ),
        "severity": "low",
        "category": "correctness",
        "pattern": _re(r'[^=!<>]==[^=]'),
        "recommendation": "Always use === (strict equality) and !== (strict inequality) in JavaScript.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.65,
        "shap_features": ["loose_equality", "type_coercion", "strict_equality_absent"],
    },
    {
        "id": "JS-MAINT-003",
        "title": "TODO / FIXME Comment",
        "description": "Known unfinished or potentially broken code marker left in source.",
        "severity": "info",
        "category": "maintainability",
        "pattern": _re(r'//\s*(?:TODO|FIXME|HACK|XXX|BUG)\b'),
        "recommendation": "Create a tracked issue and remove or resolve the comment.",
        "cwe_id": "",
        "owasp_category": "",
        "confidence": 0.99,
        "shap_features": ["todo_comment", "fixme_comment", "comment_quality"],
    },
]

ALL_RULES = SECURITY_RULES + MAINTAINABILITY_RULES
RULES_BY_ID = {r["id"]: r for r in ALL_RULES}
