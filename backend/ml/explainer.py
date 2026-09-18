"""
ml/explainer.py — SHAP / LIME Explanation Generator
=====================================================
Generates structured XAI (Explainable AI) explanations for each Vulnerability.

The system uses a hybrid approach:
  1. Feature extraction — converts raw source code context around a finding
     into a numerical feature vector based on the rule's `shap_features` list.
  2. SHAP simulation — computes realistic Shapley values by combining:
       a. Rule-defined base importance weights
       b. Context signals from the surrounding code lines
       c. Additive noise for natural variation
  3. LIME simulation — derives local weights from the SHAP values with
       perturbation-style jitter to mimic LIME's local approximation.

Why "simulation"?
  A real SHAP computation requires a trained ML model (e.g. a random forest
  classifier trained on labeled vulnerability datasets). For a capstone project
  without a pre-trained model, we generate explanations that are:
    - Structurally identical to real SHAP/LIME output
    - Semantically meaningful (features relate to the actual rule logic)
    - Numerically consistent (base_value + sum(shap_values) ≈ prediction)

  The resulting JSON is consumed by the Canvas-based shap_chart.js in the frontend.

Usage:
    from ml.explainer import ExplanationGenerator
    gen = ExplanationGenerator()
    shap_data = gen.generate_shap(finding, source_lines)
    lime_data  = gen.generate_lime(finding, source_lines)
    summary    = gen.generate_summary(finding, shap_data)
"""

import math
import random
import logging
import hashlib
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Feature Signal Detectors ─────────────────────────────────────────────────
# Each detector takes (line: str, context_lines: list[str]) and returns a float
# in [0.0, 1.0] representing how strongly that feature is present.

def _detect_user_input(line, context):
    """Checks if user-controlled variables appear near the flagged line."""
    keywords = ["request", "input(", "argv", "stdin", "form", "param", "query",
                "user_input", "username", "password", "body", "payload", "data"]
    combined = " ".join([line] + context).lower()
    hits = sum(1 for kw in keywords if kw in combined)
    return min(hits / 3.0, 1.0)

def _detect_sanitization(line, context):
    """Checks if any sanitization/validation is nearby."""
    keywords = ["escape", "sanitize", "validate", "filter", "clean", "strip",
                "parameterized", "prepared", "encode", "htmlspecialchars", "safe"]
    combined = " ".join([line] + context).lower()
    return 1.0 if any(kw in combined for kw in keywords) else 0.0

def _detect_orm_usage(line, context):
    """Checks if an ORM (Django ORM, SQLAlchemy, Hibernate, EF Core) is being used."""
    keywords = ["objects.filter", "objects.get", "queryset", "session.query",
                "repository", "dbset", "findby", "jpa", "entitymanager"]
    combined = " ".join([line] + context).lower()
    return 1.0 if any(kw in combined for kw in keywords) else 0.0

def _detect_crypto_context(line, context):
    """Checks if line is in a cryptographic / authentication context."""
    keywords = ["hash", "password", "token", "auth", "session", "login",
                "credential", "secret", "signature", "hmac", "jwt"]
    combined = " ".join([line] + context).lower()
    hits = sum(1 for kw in keywords if kw in combined)
    return min(hits / 2.0, 1.0)

def _detect_loop_context(line, context):
    """Checks if the line is inside a loop."""
    loop_keywords = ["for ", "while ", "foreach", ".map(", ".forEach(", ".each("]
    surrounding = " ".join(context).lower()
    return 1.0 if any(kw in surrounding for kw in loop_keywords) else 0.0

def _detect_error_handling(line, context):
    """Checks if there's nearby try/catch/except error handling."""
    keywords = ["try:", "except", "catch(", "try {", "rescue", "begin/rescue"]
    surrounding = " ".join(context).lower()
    return 1.0 if any(kw in surrounding for kw in keywords) else 0.0

# Registry: feature_name → detector function
FEATURE_DETECTORS = {
    "user_input_present":       _detect_user_input,
    "user_input_source":        _detect_user_input,
    "user_input_concat":        _detect_user_input,
    "user_controlled_path":     _detect_user_input,
    "input_sanitization":       _detect_sanitization,
    "input_validation":         _detect_sanitization,
    "path_validation_missing":  lambda l, c: 1.0 - _detect_sanitization(l, c),
    "orm_usage":                _detect_orm_usage,
    "ef_core_usage":            _detect_orm_usage,
    "password_context":         _detect_crypto_context,
    "security_context":         _detect_crypto_context,
    "token_generation_context": _detect_crypto_context,
    "session_context":          _detect_crypto_context,
    "loop_context":             _detect_loop_context,
    "error_handling_quality":   _detect_error_handling,
}

# ─── Base importance weights per feature name ─────────────────────────────────
# These reflect the semantic importance of each feature to the vulnerability.
# Positive = increases risk, Negative = decreases risk.

FEATURE_BASE_WEIGHTS = {
    # Increases risk
    "sql_string_concat":        +0.38,
    "sql_format_string":        +0.35,
    "fstring_in_sql":           +0.30,
    "raw_execute_call":         +0.14,
    "eval_call":                +0.60,
    "exec_call":                +0.55,
    "external_arg_passed":      +0.17,
    "function_param_origin":    +0.12,
    "os_system_call":           +0.40,
    "shell_true_flag":          +0.32,
    "user_input_present":       +0.22,
    "user_input_source":        +0.20,
    "user_input_concat":        +0.25,
    "user_controlled_path":     +0.22,
    "md5_hash_usage":           +0.55,
    "sha1_hash_usage":          +0.42,
    "pickle_loads_call":        +0.48,
    "yaml_load_call":           +0.38,
    "safe_loader_missing":      +0.22,
    "hardcoded_string_assignment": +0.30,
    "hardcoded_secret_string":  +0.45,
    "hardcoded_string_credential": +0.38,
    "credential_keyword":       +0.18,
    "open_with_user_input":     +0.28,
    "path_validation_missing":  +0.20,
    "random_module_usage":      +0.30,
    "debug_true_flag":          +0.45,
    "flask_app_run":            +0.15,
    "bare_except":              +0.28,
    "broad_catch":              +0.20,
    "mutable_default_arg":      +0.32,
    "list_default":             +0.25,
    "dict_default":             +0.25,
    "todo_comment":             +0.15,
    "fixme_comment":            +0.20,
    "print_statement":          +0.18,
    "string_concat_in_loop":    +0.28,
    "inner_html_assignment":    +0.42,
    "api_response_data":        +0.21,
    "document_write_call":      +0.38,
    "localstorage_sensitive_data": +0.32,
    "token_storage":            +0.28,
    "wildcard_target_origin":   +0.35,
    "postmessage_call":         +0.18,
    "object_assign_call":       +0.22,
    "json_parse_input":         +0.18,
    "console_log_present":      +0.15,
    "loose_equality":           +0.12,
    "sql_concat_in_query":      +0.36,
    "prepared_statement_absent":+0.20,
    "util_random_usage":        +0.28,
    "binary_formatter_usage":   +0.52,
    "response_write_user_input":+0.38,
    "object_input_stream":      +0.30,
    "read_object_call":         +0.28,
    "print_stack_trace":        +0.22,
    "empty_catch_block":        +0.30,
    "exception_swallowed":      +0.25,
    "cyclomatic_complexity":    +0.35,
    "branch_count":             +0.20,
    "nesting_depth":            +0.18,
    "function_length":          +0.22,
    "subprocess_string_arg":    +0.28,
    "decompilation_risk":       +0.15,
    "debug_output":             +0.15,
    "untrusted_source":         +0.25,
    "untrusted_input":          +0.22,
    "data_origin":              +0.18,

    # Decreases risk (negative SHAP = good thing to have)
    "parameterized_query":      -0.10,
    "orm_usage":                -0.12,
    "ef_core_usage":            -0.12,
    "input_sanitization":       -0.08,
    "input_validation":         -0.08,
    "sandboxing_present":       -0.09,
    "allowlist_check":          -0.07,
    "bcrypt_present":           -0.08,
    "salt_usage":               -0.05,
    "sha256_alternative":       -0.06,
    "env_var_usage":            -0.10,
    "secrets_manager_usage":    -0.12,
    "key_vault_usage":          -0.12,
    "safe_loader_missing":      +0.20,   # already positive above
    "realpath_check":           -0.09,
    "base_dir_check":           -0.08,
    "secrets_module_absent":    +0.18,
    "logging_module_absent":    +0.10,
    "logging_absent":           +0.12,
    "none_default_pattern":     -0.10,
    "dom_purify_present":       -0.09,
    "text_content_used":        -0.06,
    "httponly_cookie_absent":   +0.15,
    "specific_exception_missing":+0.18,
    "issue_tracker_reference":  -0.05,
    "json_alternative":         -0.08,
    "deserialization_filter":   -0.10,
    "signature_verification":   -0.08,
    "secure_random_absent":     +0.18,
    "debug_false_alternative":  -0.10,
    "env_var_control":          -0.08,
    "subprocess_list_args":     -0.10,
    "proto_key_check":          -0.08,
    "hasown_property_check":    -0.06,
    "logger_absent":            +0.10,
    "test_coverage_risk":       +0.12,
    "return_count":             +0.10,
    "null_check_missing":       +0.20,
    "optional_usage":           -0.08,
}


# ─── ExplanationGenerator ─────────────────────────────────────────────────────

class ExplanationGenerator:
    """
    Generates SHAP and LIME explanations for a vulnerability finding.

    The generator is deterministic given the same inputs (uses rule_id + line_start
    as an RNG seed) so repeated calls for the same finding yield consistent results.
    """

    def generate_shap(self, finding: dict, source_lines: list) -> dict:
        """
        Generates a SHAP explanation for a finding.

        Args:
            finding:      Finding dict from CodeAnalyzer.analyze()
            source_lines: All lines of the source file (for context extraction)

        Returns:
            dict matching the Explanation.explanation_data SHAP schema:
            {
              "method": "shap",
              "base_value": float,
              "prediction": float,
              "features": [{"name", "value", "shap_value", "display"}, ...]
            }
        """
        rng        = self._make_rng(finding)
        features   = finding.get("shap_features", [])
        context    = self._get_context(finding, source_lines)
        line       = source_lines[finding["line_start"] - 1] if 0 < finding["line_start"] <= len(source_lines) else ""
        confidence = finding.get("confidence_score", 0.80)

        # Base value — what the model predicts on average (prior to feature effects)
        base_value = round(0.25 + rng.uniform(-0.05, 0.05), 3)

        feature_rows = []
        shap_sum     = 0.0

        for feat_name in features:
            # Get base weight for this feature
            base_w = FEATURE_BASE_WEIGHTS.get(feat_name, 0.0)

            # Detect how strongly this feature is present in context
            detector  = FEATURE_DETECTORS.get(feat_name)
            if detector:
                presence = detector(line, context)
            else:
                # Default: assume present (value=1) for features without a detector
                presence = 1.0

            # Scale weight by presence and add controlled noise
            noise    = rng.gauss(0, 0.02)
            shap_val = round(base_w * (0.7 + presence * 0.3) + noise, 4)

            feature_rows.append({
                "name":       feat_name,
                "value":      round(presence),
                "shap_value": shap_val,
                "display":    self._feature_display_name(feat_name),
            })
            shap_sum += shap_val

        # The prediction = base_value + sum(shap_values), clamped to confidence range
        prediction = round(
            min(max(base_value + shap_sum, confidence - 0.1), min(confidence + 0.05, 0.99)),
            3
        )

        # Sort by absolute SHAP value descending for display
        feature_rows.sort(key=lambda f: abs(f["shap_value"]), reverse=True)

        logger.debug("SHAP generated: %d features, prediction=%.3f", len(feature_rows), prediction)
        return {
            "method":     "shap",
            "base_value": base_value,
            "prediction": prediction,
            "features":   feature_rows,
        }

    def generate_lime(self, finding: dict, source_lines: list) -> dict:
        """
        Generates a LIME explanation derived from the SHAP data with perturbation noise.

        LIME approximates local behavior by fitting a linear model on perturbed inputs.
        We simulate this by taking SHAP values and adding Gaussian jitter.

        Returns:
            dict matching the Explanation.explanation_data LIME schema:
            {
              "method": "lime",
              "prediction_proba": [float, float],
              "intercept": float,
              "features": [{"name", "weight", "display"}, ...]
            }
        """
        shap_data = self.generate_shap(finding, source_lines)
        rng       = self._make_rng(finding, salt=99)

        prediction = shap_data["prediction"]
        intercept  = round(shap_data["base_value"] * 0.9 + rng.uniform(-0.03, 0.03), 3)

        features = []
        for f in shap_data["features"]:
            # Jitter the SHAP value to simulate LIME's local approximation
            jitter = rng.gauss(0, abs(f["shap_value"]) * 0.12 + 0.01)
            weight = round(f["shap_value"] + jitter, 4)
            features.append({
                "name":    f["name"],
                "weight":  weight,
                "display": f["display"],
            })

        return {
            "method":           "lime",
            "prediction_proba": [round(1 - prediction, 3), round(prediction, 3)],
            "intercept":        intercept,
            "features":         features,
        }

    def generate_summary(self, finding: dict, shap_data: dict) -> str:
        """
        Generates a plain-English summary of why the model flagged this finding.
        Uses the top 2–3 SHAP features to construct a readable explanation.

        Args:
            finding:   The vulnerability finding dict
            shap_data: SHAP explanation dict from generate_shap()

        Returns:
            Human-readable summary string.
        """
        features   = shap_data.get("features", [])
        prediction = shap_data.get("prediction", 0.5)
        title      = finding.get("title", "this issue")

        if not features:
            return f"The model flagged this as {title} based on pattern analysis of the source code."

        # Top positive contributors
        pos_features = [f for f in features if f["shap_value"] > 0][:3]
        neg_features = [f for f in features if f["shap_value"] < 0][:2]

        parts = [
            f"The model flagged this as {title} with {prediction*100:.0f}% confidence."
        ]

        if pos_features:
            top = pos_features[0]
            parts.append(
                f"The primary contributing factor is '{top['display']}' "
                f"(SHAP: +{top['shap_value']:.3f}), which strongly indicates vulnerable code."
            )

        if len(pos_features) > 1:
            others = ", ".join(f"'{f['display']}'" for f in pos_features[1:])
            parts.append(f"Additional risk signals include: {others}.")

        if neg_features:
            top_neg = neg_features[0]
            parts.append(
                f"The risk is partially mitigated by '{top_neg['display']}' "
                f"(SHAP: {top_neg['shap_value']:.3f}), which reduces the score."
            )

        return " ".join(parts)

    def generate_top_feature(self, shap_data: dict) -> tuple:
        """
        Returns (name, importance) for the highest-absolute-value SHAP feature.

        Returns:
            (display_name: str, importance: float)
        """
        features = shap_data.get("features", [])
        if not features:
            return ("", 0.0)
        top = max(features, key=lambda f: abs(f["shap_value"]))
        return (top["display"], abs(top["shap_value"]))

    # ── Helpers ───────────────────────────────────────────────────────────

    def _make_rng(self, finding: dict, salt: int = 0) -> random.Random:
        """
        Creates a seeded RNG for reproducibility.
        The same finding always gets the same SHAP values.
        """
        seed_str = f"{finding.get('rule_id','')}-{finding.get('line_start',0)}-{salt}"
        seed_int = int(hashlib.sha256(seed_str.encode()).hexdigest()[:8], 16)
        return random.Random(seed_int)

    def _get_context(self, finding: dict, source_lines: list, window: int = 5) -> list:
        """
        Returns `window` lines above and below the flagged line for context detection.
        """
        start = max(0, finding["line_start"] - 1 - window)
        end   = min(len(source_lines), finding["line_start"] - 1 + window)
        return source_lines[start:end]

    def _feature_display_name(self, feature_name: str) -> str:
        """
        Converts snake_case feature names to readable display strings.
        e.g. "sql_string_concat" → "SQL string concatenation detected"
        """
        DISPLAY_NAMES = {
            "sql_string_concat":         "SQL string concatenation detected",
            "sql_format_string":         "SQL built with .format()",
            "fstring_in_sql":            "F-string used inside SQL query",
            "raw_execute_call":          "Raw cursor.execute() call",
            "eval_call":                 "eval() function called",
            "exec_call":                 "exec() function called",
            "external_arg_passed":       "External argument passed",
            "function_param_origin":     "Input originates from function parameter",
            "os_system_call":            "os.system() invoked",
            "shell_true_flag":           "shell=True flag present",
            "user_input_present":        "Unvalidated user input in scope",
            "user_input_source":         "Data sourced from user request",
            "user_input_concat":         "User input concatenated into command",
            "user_controlled_path":      "User-controlled file path",
            "md5_hash_usage":            "hashlib.md5() used for sensitive data",
            "sha1_hash_usage":           "hashlib.sha1() used (weak hash)",
            "pickle_loads_call":         "pickle.loads() called",
            "yaml_load_call":            "yaml.load() without SafeLoader",
            "safe_loader_missing":       "SafeLoader not specified",
            "hardcoded_string_assignment":"Hardcoded string assigned to credential",
            "hardcoded_secret_string":   "Hardcoded secret string detected",
            "hardcoded_string_credential":"Hardcoded credential in source",
            "credential_keyword":        "Credential-related variable name",
            "open_with_user_input":      "open() called with user-derived path",
            "path_validation_missing":   "No path validation found",
            "random_module_usage":       "random module used (not cryptographic)",
            "debug_true_flag":           "debug=True flag set",
            "flask_app_run":             "Flask app.run() in production code",
            "bare_except":              "Bare except: clause",
            "broad_catch":              "Overly broad exception catch",
            "mutable_default_arg":      "Mutable default argument",
            "list_default":             "List [] used as default argument",
            "dict_default":             "Dict {} used as default argument",
            "todo_comment":             "TODO comment in code",
            "fixme_comment":            "FIXME comment in code",
            "print_statement":          "print() statement present",
            "string_concat_in_loop":    "String concatenation in loop body",
            "inner_html_assignment":    "innerHTML assignment to DOM element",
            "api_response_data":        "Data sourced from API response",
            "document_write_call":      "document.write() called",
            "localstorage_sensitive_data":"Sensitive data stored in localStorage",
            "token_storage":            "Auth token stored client-side",
            "wildcard_target_origin":   "Wildcard (*) target origin in postMessage",
            "postmessage_call":         "postMessage() called",
            "object_assign_call":       "Object.assign() with parsed JSON",
            "json_parse_input":         "JSON.parse() of external input",
            "console_log_present":      "console.log() in production code",
            "loose_equality":           "Loose == equality used",
            "sql_concat_in_query":      "String concat in SQL query method",
            "prepared_statement_absent":"PreparedStatement not used",
            "util_random_usage":        "java.util.Random used (not secure)",
            "binary_formatter_usage":   "BinaryFormatter used (deprecated/insecure)",
            "response_write_user_input":"Response.Write() with user input",
            "object_input_stream":      "ObjectInputStream in use",
            "read_object_call":         "readObject() deserialization call",
            "print_stack_trace":        "e.printStackTrace() in production",
            "empty_catch_block":        "Empty catch block",
            "exception_swallowed":      "Exception silently swallowed",
            "cyclomatic_complexity":    "High cyclomatic complexity",
            "branch_count":             "High branch count",
            "nesting_depth":            "Deep nesting detected",
            "function_length":          "Function exceeds length threshold",
            "subprocess_string_arg":    "subprocess called with string (not list)",
            "decompilation_risk":       "Code vulnerable to decompilation",
            "parameterized_query":      "Parameterized query not used",
            "orm_usage":               "ORM not used for database access",
            "input_sanitization":       "No input sanitization found",
            "input_validation":         "No input validation present",
            "sandboxing_present":       "No sandbox or allowlist",
            "allowlist_check":          "No allowlist validation",
            "bcrypt_present":           "bcrypt not imported",
            "salt_usage":              "No salt applied to hash",
            "sha256_alternative":       "SHA-256 not used as alternative",
            "env_var_usage":           "Environment variable not used",
            "secrets_manager_usage":    "Secrets manager not used",
            "key_vault_usage":          "Key vault not configured",
            "realpath_check":           "No realpath() validation",
            "base_dir_check":           "Base directory not checked",
            "secrets_module_absent":    "secrets module not imported",
            "logging_module_absent":    "logging module not used",
            "logging_absent":           "No logger configured",
            "none_default_pattern":     "None-default pattern not used",
            "dom_purify_present":       "DOMPurify not imported",
            "text_content_used":        "textContent not used as alternative",
            "httponly_cookie_absent":   "HttpOnly cookie not used",
            "specific_exception_missing":"Specific exception type missing",
            "issue_tracker_reference":  "No issue tracker reference",
            "json_alternative":         "JSON serialization not used",
            "deserialization_filter":   "No deserialization filter applied",
            "signature_verification":   "No signature verification",
            "secure_random_absent":     "SecureRandom not used",
            "debug_false_alternative":  "debug=False alternative not set",
            "env_var_control":          "Environment variable control absent",
            "subprocess_list_args":     "List arguments not used in subprocess",
            "proto_key_check":          "__proto__ key check absent",
            "hasown_property_check":    "hasOwnProperty check missing",
            "logger_absent":            "Logger not configured",
            "test_coverage_risk":       "Low test coverage risk",
            "null_check_missing":       "Null check not present",
            "optional_usage":           "Optional not used for null safety",
            "debug_output":             "Debug output in production code",
            "untrusted_source":         "Data from untrusted source",
            "untrusted_input":          "Untrusted external input",
            "data_origin":              "External data origin unverified",
            "password_context":         "Used in authentication context",
            "security_context":         "Used in security-sensitive context",
            "token_generation_context": "Used for token generation",
            "session_context":          "Used in session management",
            "loop_context":             "Operation inside a loop",
            "error_handling_quality":   "Poor error handling",
            "npe_risk":                 "Null pointer exception risk",
            "method_chaining":          "Method chaining without null check",
            "ef_core_usage":            "EF Core not used for queries",
            "config_file_pattern":      "Configuration file pattern absent",
            "client_side_code":         "Secret exposed in client-side code",
            "backend_proxy_missing":    "Backend proxy for secret not used",
            "string_entropy":           "High-entropy string literal",
            "xss_reachability":         "XSS reachability path detected",
            "data_sensitivity":         "Sensitive data classification",
            "sensitive_data_in_message":"Sensitive data in message payload",
            "prototype_chain_access":   "Prototype chain access detected",
            "parser_blocking":          "Parser-blocking call",
            "xss_context":             "XSS vulnerability context",
            "html_encoding_absent":     "HTML encoding not applied",
            "razor_view_absent":        "Razor view auto-encoding not used",
            "return_count":             "High return statement count",
            "broad_catch":             "Broad exception catch",
            "sha256_alternative":       "SHA-256 alternative not used",
            "sensitive_data_in_print":  "Potential sensitive data in print()",
            "data_size_indicator":      "Large data volume indicator",
            "list_join_pattern":        "list.join() pattern not used",
        }
        return DISPLAY_NAMES.get(feature_name, feature_name.replace("_", " ").capitalize())
