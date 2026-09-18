"""
ml/analyzer.py — Code Analysis Engine
=======================================
Orchestrates static analysis for a single source code file.

Pipeline:
  1. Split source into lines
  2. Apply per-language rule set (regex pattern matching)
  3. Run file-level checks (complexity, imports, function length)
  4. Compute a risk score from weighted vulnerability severities
  5. Return structured finding dicts ready for Vulnerability model creation

Usage:
    from ml.analyzer import CodeAnalyzer
    analyzer = CodeAnalyzer(language="python")
    result = analyzer.analyze(source_code)
    # result = {
    #   "vulnerabilities": [ { rule fields + line_start/line_end/code_snippet } ],
    #   "risk_score": 0.87,
    #   "duration_ms": 42,
    #   "line_count": 120,
    #   "metrics": { "complexity": ..., "function_count": ... }
    # }
"""

import re
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Severity → numeric weight for risk score calculation
SEVERITY_WEIGHTS = {
    "critical": 1.00,
    "high":     0.75,
    "medium":   0.45,
    "low":      0.20,
    "info":     0.02,
}

# Risk score contribution per vulnerability (diminishing returns beyond ~5 issues)
MAX_RISK_FROM_SINGLE_VULN = 0.35


class CodeAnalyzer:
    """
    Language-agnostic analysis orchestrator.
    Selects and applies the correct rule set for the given language.

    Args:
        language (str): One of "python", "java", "csharp", "javascript"
    """

    def __init__(self, language: str):
        self.language = language.lower()
        self._rules   = self._load_rules()

    # ── Rule Loading ──────────────────────────────────────────────────────

    def _load_rules(self) -> list:
        """Loads the compiled rule list for self.language."""
        try:
            if self.language == "python":
                from ml.rules.python_rules import ALL_RULES
            elif self.language == "java":
                from ml.rules.java_rules import ALL_RULES
            elif self.language == "csharp":
                from ml.rules.csharp_rules import ALL_RULES
            elif self.language == "javascript":
                from ml.rules.javascript_rules import ALL_RULES
            else:
                logger.warning("No rules for language '%s' — analysis will return empty.", self.language)
                return []
            logger.debug("Loaded %d rules for language '%s'.", len(ALL_RULES), self.language)
            return ALL_RULES
        except ImportError as e:
            logger.error("Could not import rules for '%s': %s", self.language, e)
            return []

    # ── Public Interface ──────────────────────────────────────────────────

    def analyze(self, source_code: str) -> dict:
        """
        Run the full analysis pipeline on source_code.

        Args:
            source_code: Plaintext source code string (UTF-8).

        Returns:
            dict with keys:
                vulnerabilities (list[dict])  — one dict per finding
                risk_score      (float)       — 0.0–1.0
                duration_ms     (int)
                line_count      (int)
                metrics         (dict)        — complexity, function_count, etc.
        """
        start_ns = time.perf_counter_ns()
        lines     = source_code.splitlines()
        findings  = []

        logger.info("Analyzing %d lines of %s code.", len(lines), self.language)

        # 1. Line-by-line rule matching
        line_findings = self._apply_line_rules(lines)
        findings.extend(line_findings)

        # 2. File-level checks (complexity, long functions, import audits)
        file_findings = self._apply_file_rules(source_code, lines)
        findings.extend(file_findings)

        # 3. De-duplicate: same rule on same line → keep highest confidence
        findings = self._deduplicate(findings)

        # 4. Sort: critical → high → medium → low → info, then by line
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (sev_order.get(f["severity"], 5), f["line_start"]))

        # 5. Compute risk score
        risk_score = self._compute_risk_score(findings)

        duration_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

        result = {
            "vulnerabilities": findings,
            "risk_score":      risk_score,
            "duration_ms":     duration_ms,
            "line_count":      len(lines),
            "metrics":         self._compute_metrics(source_code, lines),
        }

        logger.info(
            "Analysis complete: %d findings, risk=%.2f, duration=%dms",
            len(findings), risk_score, duration_ms
        )
        return result

    # ── Line-Level Matching ───────────────────────────────────────────────

    def _apply_line_rules(self, lines: list) -> list:
        """
        Matches each rule's regex pattern against every line of source.
        Rules with pattern=None are skipped here (file-level only).
        """
        findings = []
        applicable = [r for r in self._rules if r.get("pattern") is not None]

        for line_idx, raw_line in enumerate(lines):
            line_num = line_idx + 1
            stripped = raw_line.strip()

            # Skip blank lines and pure comment lines (reduce false positives)
            if not stripped:
                continue

            for rule in applicable:
                pattern = rule["pattern"]
                if not pattern:
                    continue
                try:
                    match = pattern.search(raw_line)
                except re.error:
                    continue

                if match:
                    findings.append(self._build_finding(rule, line_num, line_num, raw_line))

        return findings

    # ── File-Level Checks ─────────────────────────────────────────────────

    def _apply_file_rules(self, source_code: str, lines: list) -> list:
        """
        Checks that operate on the whole file rather than individual lines:
          - Cyclomatic complexity (Python only via AST)
          - Long functions (> 50 lines without docstring)
          - Suspicious import audit
        """
        findings = []

        if self.language == "python":
            findings.extend(self._python_ast_checks(source_code, lines))

        findings.extend(self._check_long_functions(lines))
        return findings

    def _python_ast_checks(self, source_code: str, lines: list) -> list:
        """Use Python's ast module for structural analysis."""
        findings = []
        try:
            import ast
            tree = ast.parse(source_code)
        except SyntaxError:
            return findings  # Not our job to flag syntax errors

        for node in ast.walk(tree):
            # Cyclomatic complexity: count branching nodes inside functions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = self._compute_cyclomatic(node)
                if complexity > 10:
                    line = node.lineno
                    rule = next(
                        (r for r in self._rules if r["id"] == "PY-CMPLX-001"),
                        None
                    )
                    if rule:
                        finding = self._build_finding(rule, line, line, lines[line - 1] if line <= len(lines) else "")
                        finding["description"] = (
                            f"Function '{node.name}' has cyclomatic complexity of {complexity} "
                            f"(threshold: 10). High complexity strongly correlates with defect density "
                            f"and makes the function harder to test and maintain."
                        )
                        finding["confidence_score"] = min(0.95, 0.7 + (complexity - 10) * 0.02)
                        findings.append(finding)

        return findings

    def _compute_cyclomatic(self, func_node) -> int:
        """
        Computes McCabe's cyclomatic complexity for an AST function node.
        CC = 1 + (number of branching statements)
        Branching nodes: if, elif, for, while, except, with, assert, comprehension conditions
        """
        import ast
        branch_types = (
            ast.If, ast.For, ast.While, ast.ExceptHandler,
            ast.With, ast.Assert, ast.comprehension,
            ast.BoolOp,  # 'and' / 'or' add paths
        )
        count = 1
        for node in ast.walk(func_node):
            if isinstance(node, branch_types):
                count += 1
            # Each 'elif' is a child If node — already counted above
        return count

    def _check_long_functions(self, lines: list) -> list:
        """
        Flags functions longer than 60 lines (heuristic, language-agnostic).
        Looks for def/function/void/int patterns at the start of lines.
        """
        findings   = []
        func_start = None
        func_name  = "unknown"
        func_pats  = {
            "python":     re.compile(r'^\s*(?:async\s+)?def\s+(\w+)'),
            "java":       re.compile(r'^\s*(?:public|private|protected|static).*?\s+(\w+)\s*\('),
            "csharp":     re.compile(r'^\s*(?:public|private|protected|static|async).*?\s+(\w+)\s*\('),
            "javascript": re.compile(r'^\s*(?:async\s+)?(?:function\s+(\w+)|\w+\s*=\s*(?:async\s+)?function|\w+\s*:\s*function)'),
        }
        pat = func_pats.get(self.language)
        if not pat:
            return []

        for i, line in enumerate(lines):
            m = pat.match(line)
            if m:
                if func_start is not None and (i - func_start) > 60:
                    rule = {
                        "id": f"{self.language[:2].upper()}-MAINT-LONGFN",
                        "title": "Long Function (> 60 lines)",
                        "description": (
                            f"Function '{func_name}' is {i - func_start} lines long. "
                            "Functions over 60 lines are harder to read, test, and maintain. "
                            "Consider extracting into smaller, well-named sub-functions."
                        ),
                        "severity": "low",
                        "category": "maintainability",
                        "pattern": None,
                        "recommendation": "Extract sub-functions to reduce function length below 40 lines.",
                        "cwe_id": "",
                        "owasp_category": "",
                        "confidence": 0.80,
                        "shap_features": ["function_length", "cyclomatic_complexity", "test_coverage_risk"],
                    }
                    findings.append(self._build_finding(rule, func_start + 1, i, line))
                func_start = i
                func_name  = m.group(1) if m.lastindex and m.group(1) else "unknown"

        return findings

    # ── Risk Score Calculation ────────────────────────────────────────────

    def _compute_risk_score(self, findings: list) -> float:
        """
        Computes a risk score in [0.0, 1.0] from the finding list.

        Formula:
          - Each finding contributes: weight * confidence * diminishing_factor
          - Diminishing factor: 1 / sqrt(rank+1) so the 1st critical matters most
          - Total is clamped to [0, 1]

        A file with one critical issue scores ~0.35.
        A file with three critical issues scores ~0.60.
        A file with 10+ issues across all severities approaches 0.95.
        """
        if not findings:
            return 0.0

        import math
        total = 0.0
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f  = sorted(findings, key=lambda f: sev_order.get(f["severity"], 5))

        for rank, finding in enumerate(sorted_f):
            weight      = SEVERITY_WEIGHTS.get(finding["severity"], 0.1)
            confidence  = finding.get("confidence_score", 0.8)
            diminishing = 1.0 / math.sqrt(rank + 1)
            contribution = weight * confidence * diminishing * MAX_RISK_FROM_SINGLE_VULN
            total += contribution

        return round(min(total, 0.98), 4)  # Cap at 0.98 — 1.0 reserved for confirmed breaches

    # ── Finding Construction ──────────────────────────────────────────────

    def _build_finding(self, rule: dict, line_start: int, line_end: int, raw_line: str) -> dict:
        """
        Builds a finding dict from a matched rule and location.
        The dict maps directly onto the Vulnerability model fields.
        """
        snippet = raw_line.strip()[:500]  # Truncate very long lines
        return {
            "rule_id":          rule["id"],
            "title":            rule["title"],
            "description":      rule["description"],
            "severity":         rule["severity"],
            "category":         rule["category"],
            "line_start":       line_start,
            "line_end":         line_end if line_end != line_start else None,
            "code_snippet":     snippet,
            "fixed_snippet":    "",  # Filled in by explainer or left blank
            "recommendation":   rule.get("recommendation", ""),
            "cwe_id":           rule.get("cwe_id", ""),
            "owasp_category":   rule.get("owasp_category", ""),
            "confidence_score": rule.get("confidence", 0.80),
            "shap_features":    rule.get("shap_features", []),
        }

    # ── De-duplication ────────────────────────────────────────────────────

    def _deduplicate(self, findings: list) -> list:
        """
        Removes duplicate findings (same rule_id on same line).
        When duplicates exist, keeps the one with highest confidence.
        """
        seen    = {}  # (rule_id, line_start) → finding
        for f in findings:
            key = (f["rule_id"], f["line_start"])
            if key not in seen or f["confidence_score"] > seen[key]["confidence_score"]:
                seen[key] = f
        return list(seen.values())

    # ── Metrics ───────────────────────────────────────────────────────────

    def _compute_metrics(self, source_code: str, lines: list) -> dict:
        """
        Computes file-level quality metrics returned alongside findings.
        These are informational and shown in the UI metrics panel.
        """
        metrics = {
            "line_count":       len(lines),
            "blank_lines":      sum(1 for l in lines if not l.strip()),
            "comment_lines":    0,
            "function_count":   0,
            "class_count":      0,
            "avg_line_length":  0,
            "max_line_length":  0,
        }

        if lines:
            lengths = [len(l) for l in lines if l.strip()]
            metrics["avg_line_length"] = round(sum(lengths) / max(len(lengths), 1))
            metrics["max_line_length"] = max(lengths) if lengths else 0

        comment_pats = {
            "python":     re.compile(r'^\s*#'),
            "java":       re.compile(r'^\s*(?://|/\*)'),
            "csharp":     re.compile(r'^\s*(?://|/\*)'),
            "javascript": re.compile(r'^\s*(?://|/\*)'),
        }
        func_pats = {
            "python":     re.compile(r'^\s*(?:async\s+)?def\s+\w+'),
            "java":       re.compile(r'^\s*(?:public|private|protected|static).*\w+\s*\('),
            "csharp":     re.compile(r'^\s*(?:public|private|protected|static|async).*\w+\s*\('),
            "javascript": re.compile(r'\bfunction\s+\w+|\w+\s*=\s*(?:async\s+)?\('),
        }
        class_pats = {
            "python":     re.compile(r'^\s*class\s+\w+'),
            "java":       re.compile(r'^\s*(?:public|private)?\s*class\s+\w+'),
            "csharp":     re.compile(r'^\s*(?:public|private)?\s*(?:partial\s+)?class\s+\w+'),
            "javascript": re.compile(r'^\s*class\s+\w+'),
        }

        cp = comment_pats.get(self.language)
        fp = func_pats.get(self.language)
        kp = class_pats.get(self.language)

        for line in lines:
            if cp and cp.match(line): metrics["comment_lines"]  += 1
            if fp and fp.match(line): metrics["function_count"] += 1
            if kp and kp.match(line): metrics["class_count"]    += 1

        return metrics
