"""
core/management/commands/seed_dev_data.py
=========================================
Populates the database with realistic sample data for development and UI testing.
Creates one sample Project, two CodeFiles (Python + JavaScript), with Vulnerabilities
and SHAP Explanations so the frontend has real data to render.

Usage:
    python manage.py seed_dev_data
    python manage.py seed_dev_data --clear    # Wipe existing data first
"""

import logging
import sys
from django.core.management.base import BaseCommand
from django.conf import settings

from core.models import (
    Project, CodeFile, Vulnerability, Explanation,
    Language, ReviewStatus, Severity, VulnCategory, ExplanationType
)

logger = logging.getLogger(__name__)


SAMPLE_PYTHON_CODE = '''
import sqlite3
import hashlib

def get_user(username, password):
    """Retrieve a user from the database by credentials."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # BUG: SQL injection — user input directly concatenated
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        # BUG: MD5 is cryptographically broken — do not use for passwords
        hashed = hashlib.md5(password.encode()).hexdigest()
        if user[2] == hashed:
            return user
    return None

def execute_command(user_input):
    """Run a system command based on user input."""
    # BUG: Command injection — user input passed directly to exec
    import os
    os.system("echo " + user_input)

class UserSession:
    def __init__(self):
        self.token = None
    
    def login(self, username, password):
        user = get_user(username, password)
        if user:
            # BUG: Weak token — predictable from username
            self.token = hashlib.md5(username.encode()).hexdigest()
            return True
        return False
'''.strip()


SAMPLE_JS_CODE = '''
// user-profile.js
// Fetches and renders a user profile from the API

async function loadProfile(userId) {
    const response = await fetch(`/api/users/${userId}`);
    const data = await response.json();
    
    // BUG: XSS — innerHTML with unsanitized server data
    document.getElementById("bio").innerHTML = data.bio;
    document.getElementById("name").innerHTML = data.displayName;
    
    return data;
}

function savePreferences(prefs) {
    // BUG: Sensitive data stored in localStorage (accessible by any script)
    localStorage.setItem("userPrefs", JSON.stringify(prefs));
    localStorage.setItem("authToken", prefs.token);
}

function buildQuery(searchTerm) {
    // BUG: Prototype pollution risk — no hasOwnProperty check
    const params = {};
    Object.assign(params, JSON.parse(searchTerm));
    return params;
}

// BUG: eval() with potentially user-controlled input
function applyFilter(filterCode) {
    return eval(filterCode);
}
'''.strip()


class Command(BaseCommand):
    help = "Seed the database with sample projects, files, and vulnerabilities for development."

    def add_arguments(self, parser):
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Delete all existing projects before seeding.",
        )

    def handle(self, *args, **options):
        # Never crash on Windows cp1252 consoles — replace unencodable chars
        # (e.g. ✓) instead of raising UnicodeEncodeError when output is piped.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(errors="replace")
            except (AttributeError, OSError, ValueError):
                pass

        if options["clear"]:
            count, _ = Project.objects.all().delete()
            self.stdout.write(self.style.WARNING(f"Cleared {count} existing project(s)."))

        self.stdout.write("Seeding development data...")

        # ------------------------------------------------------------------
        # 1. Create Project
        # ------------------------------------------------------------------
        project = Project.objects.create(
            name="Sample Assignment — Security Audit",
            description=(
                "A sample student project uploaded for security review. "
                "Contains intentional vulnerabilities for demonstration."
            ),
        )
        self.stdout.write(f"  ✓ Created project: {project.name} ({project.id})")

        # ------------------------------------------------------------------
        # 2. Python CodeFile
        # ------------------------------------------------------------------
        py_file = CodeFile(
            project=project,
            filename="auth.py",
            language=Language.PYTHON,
            status=ReviewStatus.COMPLETE,
            risk_score=0.91,
            analysis_duration_ms=312,
        )
        py_file.set_source(SAMPLE_PYTHON_CODE)
        py_file.save()
        self.stdout.write(f"  ✓ Created file: {py_file.filename}")

        # Python Vulnerabilities
        vuln_sqli = Vulnerability.objects.create(
            code_file=py_file,
            line_start=9,
            line_end=9,
            title="SQL Injection",
            description=(
                "User-supplied input is concatenated directly into a SQL query string "
                "without sanitization or parameterization. An attacker can manipulate "
                "the query to bypass authentication, extract arbitrary data, or modify records."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.CRITICAL,
            confidence_score=0.97,
            rule_id="PY-SEC-001",
            recommendation=(
                "Use parameterized queries (prepared statements) instead of string concatenation. "
                "Replace with: cursor.execute('SELECT * FROM users WHERE username=?', (username,))"
            ),
            code_snippet="query = \"SELECT * FROM users WHERE username='\" + username + \"'\"",
            fixed_snippet="cursor.execute('SELECT * FROM users WHERE username=?', (username,))",
            cwe_id="CWE-89",
            owasp_category="A03:2021 – Injection",
        )

        vuln_md5 = Vulnerability.objects.create(
            code_file=py_file,
            line_start=16,
            line_end=16,
            title="Weak Cryptographic Hash (MD5)",
            description=(
                "MD5 is a cryptographically broken hash function. It is vulnerable to "
                "collision attacks and preimage attacks, and rainbow tables for MD5 hashes "
                "of common passwords are widely available. Using MD5 for password storage "
                "provides almost no security."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.HIGH,
            confidence_score=0.99,
            rule_id="PY-SEC-002",
            recommendation=(
                "Use a memory-hard password hashing algorithm such as bcrypt, scrypt, or Argon2. "
                "In Python: use the 'bcrypt' library or Django's built-in password hashing."
            ),
            code_snippet="hashed = hashlib.md5(password.encode()).hexdigest()",
            fixed_snippet="import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            cwe_id="CWE-916",
            owasp_category="A02:2021 – Cryptographic Failures",
        )

        vuln_cmdi = Vulnerability.objects.create(
            code_file=py_file,
            line_start=22,
            line_end=22,
            title="OS Command Injection",
            description=(
                "User-controlled input is passed directly to os.system(). An attacker can "
                "inject shell metacharacters (;, &&, |, $()) to execute arbitrary system commands "
                "with the privileges of the running process."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
            rule_id="PY-SEC-003",
            recommendation=(
                "Never pass user input to os.system(). Use subprocess.run() with a list "
                "of arguments (not a string) and shell=False to prevent injection."
            ),
            code_snippet='os.system("echo " + user_input)',
            fixed_snippet='subprocess.run(["echo", user_input], shell=False, check=True)',
            cwe_id="CWE-78",
            owasp_category="A03:2021 – Injection",
        )

        vuln_weak_token = Vulnerability.objects.create(
            code_file=py_file,
            line_start=31,
            line_end=31,
            title="Predictable Session Token",
            description=(
                "Session tokens generated from the MD5 hash of the username are entirely predictable. "
                "An attacker who knows a valid username can forge a valid session token without "
                "ever knowing the password."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.HIGH,
            confidence_score=0.88,
            rule_id="PY-SEC-004",
            recommendation=(
                "Use a cryptographically secure random token generator: "
                "import secrets; token = secrets.token_hex(32)"
            ),
            code_snippet="self.token = hashlib.md5(username.encode()).hexdigest()",
            fixed_snippet="import secrets\nself.token = secrets.token_hex(32)",
            cwe_id="CWE-330",
            owasp_category="A07:2021 – Identification and Authentication Failures",
        )

        self.stdout.write(f"    ✓ Created {py_file.vulnerabilities.count()} vulnerabilities for {py_file.filename}")

        # SHAP Explanations for Python vulns
        self._create_shap_explanation(
            vuln_sqli,
            prediction=0.97,
            base_value=0.35,
            features=[
                {"name": "sql_string_concat",     "value": 1, "shap_value": 0.38, "display": "SQL string concatenation detected"},
                {"name": "user_input_present",     "value": 1, "shap_value": 0.22, "display": "Unvalidated user input in scope"},
                {"name": "parameterized_query",    "value": 0, "shap_value": -0.10, "display": "No parameterized query used"},
                {"name": "input_sanitization",     "value": 0, "shap_value": -0.08, "display": "No input sanitization found"},
                {"name": "orm_usage",              "value": 0, "shap_value": -0.05, "display": "ORM not used"},
                {"name": "raw_execute_call",       "value": 1, "shap_value": 0.14, "display": "Raw cursor.execute() call"},
            ],
            summary=(
                "The model flagged this as a Critical SQL Injection because it detected "
                "direct string concatenation of user input into a SQL query string (top factor, +0.38). "
                "The absence of parameterized queries (-0.10) and input sanitization (-0.08) "
                "further increase the risk score. Using a parameterized query would remove this vulnerability."
            ),
        )

        self._create_shap_explanation(
            vuln_md5,
            prediction=0.99,
            base_value=0.2,
            features=[
                {"name": "md5_hash_usage",         "value": 1, "shap_value": 0.55, "display": "hashlib.md5() used for password"},
                {"name": "password_context",        "value": 1, "shap_value": 0.18, "display": "Hash used in authentication context"},
                {"name": "bcrypt_present",          "value": 0, "shap_value": -0.07, "display": "bcrypt not imported"},
                {"name": "salt_usage",              "value": 0, "shap_value": -0.05, "display": "No salt applied"},
            ],
            summary=(
                "MD5 usage for password hashing is the overwhelming driver (+0.55) of this finding. "
                "The model is 99% confident because hashlib.md5() was found in a clear "
                "authentication context where a returned user record is being compared to the hash."
            ),
        )

        # ------------------------------------------------------------------
        # 3. JavaScript CodeFile
        # ------------------------------------------------------------------
        js_file = CodeFile(
            project=project,
            filename="user-profile.js",
            language=Language.JAVASCRIPT,
            status=ReviewStatus.COMPLETE,
            risk_score=0.76,
            analysis_duration_ms=198,
        )
        js_file.set_source(SAMPLE_JS_CODE)
        js_file.save()
        self.stdout.write(f"  ✓ Created file: {js_file.filename}")

        vuln_xss = Vulnerability.objects.create(
            code_file=js_file,
            line_start=8,
            line_end=9,
            title="Cross-Site Scripting (XSS) via innerHTML",
            description=(
                "User-controlled data from an API response is assigned to element.innerHTML "
                "without sanitization. If the API response contains HTML or JavaScript, "
                "it will be executed in the user's browser, potentially stealing cookies "
                "or performing actions on behalf of the user."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.HIGH,
            confidence_score=0.93,
            rule_id="JS-SEC-001",
            recommendation=(
                "Use element.textContent instead of innerHTML for displaying user-supplied text. "
                "If HTML rendering is required, use a trusted sanitization library like DOMPurify."
            ),
            code_snippet='document.getElementById("bio").innerHTML = data.bio;',
            fixed_snippet='document.getElementById("bio").textContent = data.bio;\n// Or with HTML: DOMPurify.sanitize(data.bio)',
            cwe_id="CWE-79",
            owasp_category="A03:2021 – Injection",
        )

        vuln_localstorage = Vulnerability.objects.create(
            code_file=js_file,
            line_start=14,
            line_end=15,
            title="Sensitive Data in localStorage",
            description=(
                "Authentication tokens and preferences are stored in localStorage, which is "
                "accessible to any JavaScript on the page. An XSS vulnerability anywhere on "
                "the site would allow an attacker to steal these tokens."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.MEDIUM,
            confidence_score=0.85,
            rule_id="JS-SEC-002",
            recommendation=(
                "Store authentication tokens in HttpOnly cookies, which are inaccessible to JavaScript. "
                "Non-sensitive preferences may remain in localStorage."
            ),
            code_snippet='localStorage.setItem("authToken", prefs.token);',
            fixed_snippet="// Use HttpOnly cookie set by server instead\n// document.cookie is NOT accessible to JS when HttpOnly is set",
            cwe_id="CWE-312",
            owasp_category="A02:2021 – Cryptographic Failures",
        )

        vuln_eval = Vulnerability.objects.create(
            code_file=js_file,
            line_start=26,
            line_end=26,
            title="Dangerous eval() Usage",
            description=(
                "eval() executes arbitrary JavaScript code. If the filterCode argument "
                "is user-controlled or comes from an untrusted source, this is equivalent "
                "to a code injection vulnerability."
            ),
            category=VulnCategory.SECURITY,
            severity=Severity.CRITICAL,
            confidence_score=0.96,
            rule_id="JS-SEC-003",
            recommendation=(
                "Remove eval() entirely. If dynamic behavior is needed, use a whitelist of "
                "allowed operations, or restructure the logic to avoid dynamic code execution."
            ),
            code_snippet="return eval(filterCode);",
            fixed_snippet="// Replace with a safe filter map:\nconst filters = { reverse: arr => [...arr].reverse() };\nreturn filters[filterCode]?.(data);",
            cwe_id="CWE-95",
            owasp_category="A03:2021 – Injection",
        )

        self._create_shap_explanation(
            vuln_xss,
            prediction=0.93,
            base_value=0.25,
            features=[
                {"name": "inner_html_assignment",  "value": 1, "shap_value": 0.42, "display": "innerHTML assignment to DOM element"},
                {"name": "api_response_data",      "value": 1, "shap_value": 0.21, "display": "Data sourced from API response"},
                {"name": "dom_purify_present",     "value": 0, "shap_value": -0.09, "display": "DOMPurify not imported"},
                {"name": "text_content_used",      "value": 0, "shap_value": -0.06, "display": "textContent not used as alternative"},
            ],
            summary=(
                "innerHTML assignment (top factor, +0.42) combined with data sourced directly "
                "from an API response (+0.21) drives this XSS finding. The model is 93% confident "
                "because no sanitization library was detected in the file."
            ),
        )

        self._create_shap_explanation(
            vuln_eval,
            prediction=0.96,
            base_value=0.18,
            features=[
                {"name": "eval_call",              "value": 1, "shap_value": 0.60, "display": "eval() function called"},
                {"name": "external_arg_passed",    "value": 1, "shap_value": 0.17, "display": "External argument passed to eval"},
                {"name": "function_param_origin",  "value": 1, "shap_value": 0.12, "display": "Argument originates from function parameter"},
                {"name": "sandboxing_present",     "value": 0, "shap_value": -0.09, "display": "No sandbox or allowlist present"},
            ],
            summary=(
                "The direct use of eval() is the dominant signal (+0.60) for this Critical finding. "
                "The model further increased confidence because the argument passed to eval() "
                "comes directly from a function parameter, meaning its origin is external and "
                "potentially attacker-controlled."
            ),
        )

        self.stdout.write(f"    ✓ Created {js_file.vulnerabilities.count()} vulnerabilities for {js_file.filename}")

        # ------------------------------------------------------------------
        # 4. Recalculate project risk score
        # ------------------------------------------------------------------
        project.recalculate_risk_score()

        self.stdout.write("\n" + self.style.SUCCESS(
            f"✓ Seeding complete!\n"
            f"  Project ID:  {project.id}\n"
            f"  Risk Score:  {project.overall_risk_score:.0%}\n"
            f"  Python File: {py_file.id}\n"
            f"  JS File:     {js_file.id}\n"
        ))
        self.stdout.write("  View at: http://localhost:8000/admin/")

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _create_shap_explanation(self, vulnerability, prediction, base_value, features, summary):
        exp = Explanation(
            vulnerability=vulnerability,
            method=ExplanationType.SHAP,
            explanation_data={
                "method":      "shap",
                "base_value":  base_value,
                "prediction":  prediction,
                "features":    features,
            },
            summary=summary,
        )
        exp.compute_top_feature()
        exp.save()
