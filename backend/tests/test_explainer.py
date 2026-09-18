"""
tests/test_explainer.py — ExplanationGenerator Unit Tests
==========================================================
Tests SHAP and LIME explanation generation, schema validation,
determinism, and summary generation.

Run with:
    cd backend
    pytest tests/test_explainer.py -v
"""

import pytest
from ml.explainer import ExplanationGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def gen():
    return ExplanationGenerator()


@pytest.fixture
def sql_finding():
    """A realistic SQL injection finding dict."""
    return {
        "rule_id":          "PY-SEC-001",
        "title":            "SQL Injection",
        "severity":         "critical",
        "line_start":       9,
        "line_end":         9,
        "confidence_score": 0.97,
        "shap_features": [
            "sql_string_concat", "user_input_present", "parameterized_query",
            "input_sanitization", "orm_usage", "raw_execute_call",
        ],
    }


@pytest.fixture
def eval_finding():
    """An eval() code injection finding."""
    return {
        "rule_id":          "PY-SEC-003",
        "title":            "Code Injection via eval()",
        "severity":         "critical",
        "line_start":       22,
        "confidence_score": 0.92,
        "shap_features": [
            "eval_call", "external_arg_passed", "function_param_origin",
            "sandboxing_present", "allowlist_check",
        ],
    }


SAMPLE_LINES = [
    "import sqlite3",
    "import hashlib",
    "",
    "def get_user(username, password):",
    "    conn = sqlite3.connect('users.db')",
    "    cursor = conn.cursor()",
    "    # vulnerable",
    "    query = \"SELECT * FROM users WHERE name='\" + username + \"'\"",
    "    cursor.execute(query)",
    "    user = cursor.fetchone()",
    "    if user:",
    "        hashed = hashlib.md5(password.encode()).hexdigest()",
    "        return user[2] == hashed",
    "    return None",
]


# ---------------------------------------------------------------------------
# SHAP — Schema validation
# ---------------------------------------------------------------------------

class TestSHAPSchema:

    def test_returns_dict(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert isinstance(result, dict)

    def test_method_field_is_shap(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert result["method"] == "shap"

    def test_has_base_value(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert "base_value" in result
        assert isinstance(result["base_value"], float)

    def test_has_prediction(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert "prediction" in result
        assert isinstance(result["prediction"], float)

    def test_has_features_list(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert "features" in result
        assert isinstance(result["features"], list)
        assert len(result["features"]) > 0

    def test_each_feature_has_required_keys(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        required = {"name", "value", "shap_value", "display"}
        for feat in result["features"]:
            assert required.issubset(feat.keys()), \
                f"Feature missing keys: {required - feat.keys()}"

    def test_feature_names_match_input(self, gen, sql_finding):
        result  = gen.generate_shap(sql_finding, SAMPLE_LINES)
        names   = {f["name"] for f in result["features"]}
        expected = set(sql_finding["shap_features"])
        assert names == expected

    def test_shap_values_are_floats(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        for feat in result["features"]:
            assert isinstance(feat["shap_value"], float), \
                f"shap_value for '{feat['name']}' is not float: {type(feat['shap_value'])}"

    def test_value_is_0_or_1(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        for feat in result["features"]:
            assert feat["value"] in (0, 1), \
                f"value for '{feat['name']}' should be 0 or 1, got {feat['value']}"

    def test_display_is_nonempty_string(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        for feat in result["features"]:
            assert isinstance(feat["display"], str)
            assert len(feat["display"]) > 0


# ---------------------------------------------------------------------------
# SHAP — Value range validation
# ---------------------------------------------------------------------------

class TestSHAPValues:

    def test_prediction_in_unit_interval(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert 0.0 <= result["prediction"] <= 1.0

    def test_base_value_in_unit_interval(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert 0.0 <= result["base_value"] <= 1.0

    def test_high_confidence_critical_has_high_prediction(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, SAMPLE_LINES)
        # Critical finding with 0.97 confidence should predict > 0.70
        assert result["prediction"] >= 0.70, \
            f"Critical finding should have high prediction, got {result['prediction']}"

    def test_shap_values_have_both_signs(self, gen, sql_finding):
        """A balanced rule set should have both positive (risk-increasing)
        and negative (risk-reducing) features."""
        result    = gen.generate_shap(sql_finding, SAMPLE_LINES)
        pos_count = sum(1 for f in result["features"] if f["shap_value"] > 0)
        neg_count = sum(1 for f in result["features"] if f["shap_value"] < 0)
        # At least one feature of each sign
        assert pos_count > 0, "Expected some positive SHAP values"
        assert neg_count > 0, "Expected some negative SHAP values"


# ---------------------------------------------------------------------------
# SHAP — Determinism
# ---------------------------------------------------------------------------

class TestSHAPDeterminism:

    def test_same_finding_same_output(self, gen, sql_finding):
        """Same finding + same source → identical SHAP values (seeded RNG)."""
        r1 = gen.generate_shap(sql_finding, SAMPLE_LINES)
        r2 = gen.generate_shap(sql_finding, SAMPLE_LINES)
        assert r1["prediction"] == r2["prediction"]
        assert r1["base_value"] == r2["base_value"]
        for f1, f2 in zip(r1["features"], r2["features"]):
            assert f1["shap_value"] == f2["shap_value"]

    def test_different_findings_different_outputs(self, gen, sql_finding, eval_finding):
        """Different findings should produce different SHAP values (different seeds)."""
        r1 = gen.generate_shap(sql_finding, SAMPLE_LINES)
        r2 = gen.generate_shap(eval_finding, SAMPLE_LINES)
        # Predictions should differ (different rule semantics)
        assert r1["features"] != r2["features"]

    def test_different_line_numbers_different_outputs(self, gen):
        """Same rule at different lines → different RNG seed → different values."""
        f1 = {"rule_id": "PY-SEC-001", "title": "SQL", "severity": "critical",
              "line_start": 5,  "confidence_score": 0.9, "shap_features": ["sql_string_concat"]}
        f2 = {"rule_id": "PY-SEC-001", "title": "SQL", "severity": "critical",
              "line_start": 20, "confidence_score": 0.9, "shap_features": ["sql_string_concat"]}
        r1 = gen.generate_shap(f1, SAMPLE_LINES)
        r2 = gen.generate_shap(f2, SAMPLE_LINES)
        assert r1["features"][0]["shap_value"] != r2["features"][0]["shap_value"]


# ---------------------------------------------------------------------------
# SHAP — Feature ordering
# ---------------------------------------------------------------------------

class TestSHAPOrdering:

    def test_features_sorted_by_absolute_value(self, gen, sql_finding):
        result   = gen.generate_shap(sql_finding, SAMPLE_LINES)
        abs_vals = [abs(f["shap_value"]) for f in result["features"]]
        assert abs_vals == sorted(abs_vals, reverse=True), \
            "Features should be sorted by absolute SHAP value descending"


# ---------------------------------------------------------------------------
# SHAP — Empty feature list
# ---------------------------------------------------------------------------

class TestSHAPEdgeCases:

    def test_empty_shap_features(self, gen):
        finding = {
            "rule_id": "PY-MAINT-003", "title": "TODO", "severity": "info",
            "line_start": 3, "confidence_score": 0.99, "shap_features": [],
        }
        result = gen.generate_shap(finding, SAMPLE_LINES)
        assert result["method"] == "shap"
        assert result["features"] == []

    def test_out_of_range_line(self, gen, sql_finding):
        """Line number beyond source length should not crash."""
        finding = {**sql_finding, "line_start": 9999}
        result  = gen.generate_shap(finding, SAMPLE_LINES)
        assert result["method"] == "shap"

    def test_empty_source_lines(self, gen, sql_finding):
        result = gen.generate_shap(sql_finding, [])
        assert result["method"] == "shap"


# ---------------------------------------------------------------------------
# LIME — Schema validation
# ---------------------------------------------------------------------------

class TestLIMESchema:

    def test_returns_dict(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        assert isinstance(result, dict)

    def test_method_field_is_lime(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        assert result["method"] == "lime"

    def test_has_prediction_proba(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        assert "prediction_proba" in result
        proba = result["prediction_proba"]
        assert len(proba) == 2
        assert abs(proba[0] + proba[1] - 1.0) < 0.01, \
            f"Probabilities should sum to ~1.0, got {proba}"

    def test_has_intercept(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        assert "intercept" in result
        assert isinstance(result["intercept"], float)

    def test_has_features_list(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        assert isinstance(result["features"], list)
        assert len(result["features"]) > 0

    def test_each_lime_feature_has_required_keys(self, gen, sql_finding):
        result   = gen.generate_lime(sql_finding, SAMPLE_LINES)
        required = {"name", "weight", "display"}
        for feat in result["features"]:
            assert required.issubset(feat.keys())

    def test_lime_weights_are_floats(self, gen, sql_finding):
        result = gen.generate_lime(sql_finding, SAMPLE_LINES)
        for feat in result["features"]:
            assert isinstance(feat["weight"], float)

    def test_lime_differs_from_shap(self, gen, sql_finding):
        """LIME weights should differ from SHAP values due to jitter."""
        shap = gen.generate_shap(sql_finding, SAMPLE_LINES)
        lime = gen.generate_lime(sql_finding, SAMPLE_LINES)
        shap_vals = [f["shap_value"] for f in shap["features"]]
        lime_vals = [f["weight"]     for f in lime["features"]]
        # They should not be identical (jitter applied)
        assert shap_vals != lime_vals


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------

class TestSummaryGeneration:

    def test_returns_string(self, gen, sql_finding):
        shap   = gen.generate_shap(sql_finding, SAMPLE_LINES)
        result = gen.generate_summary(sql_finding, shap)
        assert isinstance(result, str)

    def test_summary_is_nonempty(self, gen, sql_finding):
        shap   = gen.generate_shap(sql_finding, SAMPLE_LINES)
        result = gen.generate_summary(sql_finding, shap)
        assert len(result) > 20

    def test_summary_mentions_title(self, gen, sql_finding):
        shap   = gen.generate_shap(sql_finding, SAMPLE_LINES)
        result = gen.generate_summary(sql_finding, shap)
        assert "SQL Injection" in result

    def test_summary_mentions_confidence(self, gen, sql_finding):
        shap   = gen.generate_shap(sql_finding, SAMPLE_LINES)
        result = gen.generate_summary(sql_finding, shap)
        assert "%" in result

    def test_summary_no_features(self, gen):
        finding = {"rule_id": "X", "title": "Test Issue", "severity": "low",
                   "line_start": 1, "confidence_score": 0.5, "shap_features": []}
        shap    = gen.generate_shap(finding, [])
        result  = gen.generate_summary(finding, shap)
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Top feature extraction
# ---------------------------------------------------------------------------

class TestTopFeature:

    def test_returns_tuple(self, gen, sql_finding):
        shap = gen.generate_shap(sql_finding, SAMPLE_LINES)
        name, importance = gen.generate_top_feature(shap)
        assert isinstance(name, str)
        assert isinstance(importance, float)

    def test_importance_is_nonnegative(self, gen, sql_finding):
        shap = gen.generate_shap(sql_finding, SAMPLE_LINES)
        _, importance = gen.generate_top_feature(shap)
        assert importance >= 0.0

    def test_top_feature_is_highest_absolute_value(self, gen, sql_finding):
        shap = gen.generate_shap(sql_finding, SAMPLE_LINES)
        _, importance = gen.generate_top_feature(shap)
        all_abs = [abs(f["shap_value"]) for f in shap["features"]]
        assert importance == max(all_abs)

    def test_empty_features_returns_defaults(self, gen):
        shap = {"method": "shap", "features": [], "base_value": 0.3, "prediction": 0.5}
        name, importance = gen.generate_top_feature(shap)
        assert name == ""
        assert importance == 0.0
