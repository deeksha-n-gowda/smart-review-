"""
tests/test_analyzer.py — ML Analyzer Unit Tests
================================================
Tests the CodeAnalyzer for all four supported languages.
Validates that rules fire on known-vulnerable patterns and
do NOT fire on clean equivalents (no false positive regression).

Run with:
    cd backend
    pytest tests/test_analyzer.py -v
"""

import pytest
from ml.analyzer import CodeAnalyzer


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def analyze(language, source):
    """Runs CodeAnalyzer and returns the list of findings."""
    return CodeAnalyzer(language).analyze(source)["vulnerabilities"]


def rule_ids(findings):
    return {f["rule_id"] for f in findings}


def severities(findings):
    return [f["severity"] for f in findings]


# ---------------------------------------------------------------------------
# Python — Security rules
# ---------------------------------------------------------------------------

class TestPythonSecurity:

    # ── SQL Injection ──────────────────────────────────────────────────────

    def test_sql_injection_concat_detected(self):
        src = 'cursor.execute("SELECT * FROM users WHERE name=\'" + username + "\'")'
        findings = analyze("python", src)
        assert any(f["rule_id"].startswith("PY-SEC-001") for f in findings)

    def test_sql_injection_fstring_detected(self):
        src = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
        findings = analyze("python", src)
        assert any(f["rule_id"].startswith("PY-SEC-001") for f in findings)

    def test_parameterized_query_no_finding(self):
        src = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        findings = analyze("python", src)
        assert not any(f["rule_id"].startswith("PY-SEC-001") for f in findings)

    # ── OS Command Injection ───────────────────────────────────────────────

    def test_os_system_concat_detected(self):
        src = 'os.system("echo " + user_input)'
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-002" for f in findings)

    def test_subprocess_shell_true_detected(self):
        src = 'subprocess.run("ls " + path, shell=True)'
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-002b" for f in findings)

    def test_subprocess_list_no_finding(self):
        src = 'subprocess.run(["ls", "-la", path], shell=False)'
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-SEC-002b" for f in findings)

    # ── eval / exec ────────────────────────────────────────────────────────

    def test_eval_detected(self):
        src = "result = eval(user_code)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-003" for f in findings)

    def test_exec_detected(self):
        src = "exec(compile(source, '<string>', 'exec'))"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-003b" for f in findings)

    def test_ast_literal_eval_no_finding(self):
        src = "value = ast.literal_eval(user_string)"
        findings = analyze("python", src)
        # ast.literal_eval is safe — should not trigger eval rule
        assert not any(f["rule_id"] == "PY-SEC-003" for f in findings)

    # ── Weak hashing ───────────────────────────────────────────────────────

    def test_md5_detected(self):
        src = "h = hashlib.md5(password.encode()).hexdigest()"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-004" for f in findings)

    def test_sha1_detected(self):
        src = "h = hashlib.sha1(data).hexdigest()"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-004b" for f in findings)

    def test_sha256_no_finding(self):
        src = "h = hashlib.sha256(data).hexdigest()"
        findings = analyze("python", src)
        assert not any(f["rule_id"].startswith("PY-SEC-004") for f in findings)

    # ── Hardcoded secrets ──────────────────────────────────────────────────

    def test_hardcoded_password_detected(self):
        src = 'password = "super_secret_password_123"'
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-005" for f in findings)

    def test_hardcoded_api_key_detected(self):
        src = 'api_key = "sk-prod-abc123xyz789"'
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-005" for f in findings)

    def test_env_var_no_finding(self):
        src = 'password = os.environ["DB_PASSWORD"]'
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-SEC-005" for f in findings)

    # ── Insecure deserialization ───────────────────────────────────────────

    def test_pickle_loads_detected(self):
        src = "obj = pickle.loads(user_data)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-006" for f in findings)

    def test_yaml_load_without_loader_detected(self):
        src = "data = yaml.load(stream)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-007" for f in findings)

    def test_yaml_safe_load_no_finding(self):
        src = "data = yaml.safe_load(stream)"
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-SEC-007" for f in findings)

    # ── Flask debug ────────────────────────────────────────────────────────

    def test_flask_debug_true_detected(self):
        src = "app.run(host='0.0.0.0', port=5000, debug=True)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-SEC-010" for f in findings)

    def test_flask_debug_false_no_finding(self):
        src = "app.run(host='0.0.0.0', debug=False)"
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-SEC-010" for f in findings)


# ---------------------------------------------------------------------------
# Python — Maintainability rules
# ---------------------------------------------------------------------------

class TestPythonMaintainability:

    def test_bare_except_detected(self):
        src = "try:\n    do_thing()\nexcept:\n    pass"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-001" for f in findings)

    def test_specific_except_no_finding(self):
        src = "try:\n    do_thing()\nexcept ValueError as e:\n    pass"
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-MAINT-001" for f in findings)

    def test_mutable_default_list_detected(self):
        src = "def add_item(item, items=[]):\n    items.append(item)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-002" for f in findings)

    def test_mutable_default_dict_detected(self):
        src = "def update(key, val, cache={}):\n    cache[key] = val"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-002" for f in findings)

    def test_none_default_no_finding(self):
        src = "def add_item(item, items=None):\n    if items is None: items = []"
        findings = analyze("python", src)
        assert not any(f["rule_id"] == "PY-MAINT-002" for f in findings)

    def test_todo_comment_detected(self):
        src = "# TODO: fix this before release"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-003" for f in findings)

    def test_fixme_comment_detected(self):
        src = "# FIXME: this breaks on empty input"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-003" for f in findings)

    def test_print_statement_detected(self):
        src = "print(user.email)"
        findings = analyze("python", src)
        assert any(f["rule_id"] == "PY-MAINT-004" for f in findings)


# ---------------------------------------------------------------------------
# Python — Risk score
# ---------------------------------------------------------------------------

class TestRiskScore:

    def test_clean_file_low_risk(self):
        src = '''
def add(a, b):
    """Add two numbers."""
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"
'''
        result = CodeAnalyzer("python").analyze(src)
        assert result["risk_score"] < 0.30, \
            f"Clean file should have low risk, got {result['risk_score']}"

    def test_vulnerable_file_high_risk(self):
        src = '''
import os, hashlib, pickle

def login(user, pw):
    q = "SELECT * FROM users WHERE name='" + user + "'"
    cursor.execute(q)

def run(cmd):
    os.system("ls " + cmd)

def load(data):
    return pickle.loads(data)

pw_hash = hashlib.md5(b"admin").hexdigest()
secret = "hardcoded_key_12345"
result = eval(user_code)
'''
        result = CodeAnalyzer("python").analyze(src)
        assert result["risk_score"] >= 0.70, \
            f"Highly vulnerable file should have high risk, got {result['risk_score']}"

    def test_risk_score_bounded(self):
        src = "\n".join([
            f"eval(x{i})\nos.system(y{i})\npickle.loads(z{i})"
            for i in range(20)
        ])
        result = CodeAnalyzer("python").analyze(src)
        assert 0.0 <= result["risk_score"] <= 1.0

    def test_empty_file_zero_risk(self):
        result = CodeAnalyzer("python").analyze("")
        assert result["risk_score"] == 0.0
        assert result["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# Python — Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:

    def test_same_rule_same_line_deduplicated(self):
        # Two patterns that could both match line 1
        src = 'cursor.execute("SELECT * FROM users WHERE name=\'" + name + "\'")'
        findings = analyze("python", src)
        line1 = [f for f in findings if f["line_start"] == 1]
        rule_ids_line1 = [f["rule_id"] for f in line1]
        # Each rule_id should appear at most once per line
        assert len(rule_ids_line1) == len(set(rule_ids_line1))


# ---------------------------------------------------------------------------
# JavaScript rules
# ---------------------------------------------------------------------------

class TestJavaScript:

    def test_innerhtml_xss_detected(self):
        src = 'element.innerHTML = userData;'
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-SEC-001" for f in findings)

    def test_textcontent_no_finding(self):
        src = 'element.textContent = userData;'
        findings = analyze("javascript", src)
        assert not any(f["rule_id"] == "JS-SEC-001" for f in findings)

    def test_eval_detected(self):
        src = "const result = eval(userCode);"
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-SEC-002" for f in findings)

    def test_localstorage_token_detected(self):
        src = 'localStorage.setItem("authToken", token);'
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-SEC-003" for f in findings)

    def test_localstorage_nonsensitive_no_finding(self):
        src = 'localStorage.setItem("theme", "dark");'
        findings = analyze("javascript", src)
        assert not any(f["rule_id"] == "JS-SEC-003" for f in findings)

    def test_console_log_detected(self):
        src = "console.log(userData);"
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-MAINT-001" for f in findings)

    def test_hardcoded_api_key_detected(self):
        src = 'const apiKey = "sk-prod-abc123xyz789defghijklmn";'
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-SEC-005" for f in findings)

    def test_postmessage_wildcard_detected(self):
        src = 'window.postMessage(sensitiveData, "*");'
        findings = analyze("javascript", src)
        assert any(f["rule_id"] == "JS-SEC-006" for f in findings)

    def test_postmessage_specific_origin_no_finding(self):
        src = 'window.postMessage(data, "https://trusted.example.com");'
        findings = analyze("javascript", src)
        assert not any(f["rule_id"] == "JS-SEC-006" for f in findings)


# ---------------------------------------------------------------------------
# Java rules
# ---------------------------------------------------------------------------

class TestJava:

    def test_sql_injection_detected(self):
        src = 'Statement s = conn.prepareStatement("SELECT * FROM users WHERE id=" + userId);'
        findings = analyze("java", src)
        assert any(f["rule_id"] == "JAVA-SEC-001" for f in findings)

    def test_hardcoded_password_detected(self):
        src = 'String password = "super_secret_db_pass";'
        findings = analyze("java", src)
        assert any(f["rule_id"] == "JAVA-SEC-002" for f in findings)

    def test_util_random_detected(self):
        src = "Random rng = new Random();"
        findings = analyze("java", src)
        assert any(f["rule_id"] == "JAVA-SEC-004" for f in findings)

    def test_print_stack_trace_detected(self):
        src = "} catch (Exception e) { e.printStackTrace(); }"
        findings = analyze("java", src)
        assert any(f["rule_id"] == "JAVA-SEC-006" for f in findings)

    def test_empty_catch_detected(self):
        src = "try { doThing(); } catch (Exception e) { }"
        findings = analyze("java", src)
        assert any(f["rule_id"] == "JAVA-MAINT-001" for f in findings)


# ---------------------------------------------------------------------------
# C# rules
# ---------------------------------------------------------------------------

class TestCSharp:

    def test_sql_injection_detected(self):
        src = 'var cmd = new SqlCommand("SELECT * FROM Users WHERE id=" + userId, conn);'
        findings = analyze("csharp", src)
        assert any(f["rule_id"] == "CS-SEC-001" for f in findings)

    def test_binary_formatter_detected(self):
        src = "var bf = new BinaryFormatter();"
        findings = analyze("csharp", src)
        assert any(f["rule_id"] == "CS-SEC-003" for f in findings)

    def test_md5_detected(self):
        src = "var md5 = MD5.Create();"
        findings = analyze("csharp", src)
        assert any(f["rule_id"] == "CS-SEC-004" for f in findings)

    def test_empty_catch_detected(self):
        src = "try { DoThing(); } catch (Exception e) { }"
        findings = analyze("csharp", src)
        assert any(f["rule_id"] == "CS-MAINT-001" for f in findings)

    def test_todo_detected(self):
        src = "// TODO: remove this before production"
        findings = analyze("csharp", src)
        assert any(f["rule_id"] == "CS-MAINT-002" for f in findings)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class TestMetrics:

    def test_metrics_returned(self):
        src = "def foo():\n    pass\n\nclass Bar:\n    pass\n"
        result = CodeAnalyzer("python").analyze(src)
        m = result["metrics"]
        assert "line_count"     in m
        assert "function_count" in m
        assert "class_count"    in m
        assert m["line_count"] == 5

    def test_function_count(self):
        src = "\n".join([f"def fn{i}():\n    pass" for i in range(5)])
        result = CodeAnalyzer("python").analyze(src)
        assert result["metrics"]["function_count"] == 5

    def test_duration_ms_present(self):
        result = CodeAnalyzer("python").analyze("x = 1")
        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0

    def test_unsupported_language_returns_empty(self):
        result = CodeAnalyzer("cobol").analyze("IDENTIFICATION DIVISION.")
        assert result["vulnerabilities"] == []
        assert result["risk_score"] == 0.0
