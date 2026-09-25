"""
backend/api/microservice_client.py
====================================
HTTP client helpers used by the Django backend to call the
Java compiler microservice and the C# analysis daemon.

The Django backend is the orchestrator — it calls these services
after its own Python-based analysis to enrich the results with
compile-time errors and Roslyn diagnostics.

Usage (from views.py):

    from api.microservice_client import JavaServiceClient, CSharpServiceClient

    # Java: compile a Java snippet
    java  = JavaServiceClient()
    r = java.compile(source_code, class_name="Main", check_only=True)
    if r["compile_ok"]:
        print("No compile errors!")
    else:
        for diag in r["diagnostics"]:
            print(diag["kind"], "line", diag["line"], "—", diag["message"])

    # C#: analyse a C# snippet
    csharp = CSharpServiceClient()
    r = csharp.analyze(source_code, filename="Program.cs")
    for finding in r["findings"]:
        print(finding["severity"], finding["title"], "at line", finding["line"])
"""

import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# ── Shared constants ──────────────────────────────────────────────────────────

_DEFAULT_TIMEOUT = 15   # seconds — individual request timeout
_CONNECT_TIMEOUT = 3    # seconds — connection establishment timeout


class ServiceUnavailableError(Exception):
    """Raised when a microservice is unreachable or returns an unexpected error."""
    pass


# ── Java Compiler Client ──────────────────────────────────────────────────────

class JavaServiceClient:
    """
    Client for the Java compiler microservice (port 9090).
    Wraps HTTP calls with error handling and response normalisation.
    """

    def __init__(self):
        # Full base URL — settings resolves local/Docker (http://host:port)
        # and Render (https://<service>.onrender.com) variants.
        self.base_url = getattr(
            settings, "JAVA_SERVICE_URL", "http://localhost:9090"
        ).rstrip("/")

    def health(self) -> dict:
        """
        GET /health — Check if the Java service is reachable.

        Returns:
            dict: Health response, or {"status": "unreachable"} on failure.
        """
        try:
            resp = requests.get(
                f"{self.base_url}/health",
                timeout=(_CONNECT_TIMEOUT, _DEFAULT_TIMEOUT),
            )
            return resp.json()
        except requests.RequestException:
            return {"status": "unreachable", "service": "Java Compiler"}

    def compile(
        self,
        source_code: str,
        class_name:  str  = None,
        check_only:  bool = True,
        timeout_ms:  int  = 5000,
    ) -> dict:
        """
        POST /compile — Compile a Java source snippet.

        Args:
            source_code: Raw Java source code string.
            class_name:  Public class name (auto-detected if None).
            check_only:  If True, compile only — do not execute.
            timeout_ms:  Compilation/execution timeout in milliseconds.

        Returns:
            dict: Full response from the Java service including:
                {
                  "success": bool,
                  "compile_ok": bool,
                  "diagnostics": [...],
                  "stdout": str,
                  "stderr": str,
                  "duration_ms": int
                }

        Raises:
            ServiceUnavailableError: If the Java service cannot be reached.
        """
        payload = {
            "source_code": source_code,
            "check_only":  check_only,
            "timeout_ms":  timeout_ms,
        }
        if class_name:
            payload["class_name"] = class_name

        try:
            resp = requests.post(
                f"{self.base_url}/compile",
                json=payload,
                timeout=(_CONNECT_TIMEOUT, timeout_ms / 1000 + 5),
            )
            result = resp.json()
            logger.debug(
                "Java compile: compile_ok=%s, %d diagnostics, %dms",
                result.get("compile_ok"),
                len(result.get("diagnostics", [])),
                result.get("duration_ms", 0),
            )
            return result

        except requests.ConnectionError:
            logger.warning("Java service unreachable at %s", self.base_url)
            raise ServiceUnavailableError(
                f"Java compiler service is not running at {self.base_url}. "
                "Start it with: java -jar java_service/target/code-review-service-1.0.jar"
            )
        except requests.Timeout:
            raise ServiceUnavailableError(
                f"Java compiler service timed out after {timeout_ms}ms."
            )
        except requests.RequestException as e:
            raise ServiceUnavailableError(f"Java service request failed: {e}")

    def compile_safe(self, source_code: str, **kwargs) -> dict:
        """
        Like compile(), but never raises — returns an error dict on failure.
        Use this when Java compilation is optional enrichment (not required).
        """
        try:
            return self.compile(source_code, **kwargs)
        except ServiceUnavailableError as e:
            logger.info("Java service unavailable (non-fatal): %s", e)
            return {
                "success":     False,
                "compile_ok":  None,
                "diagnostics": [],
                "error":       str(e),
                "duration_ms": 0,
            }


# ── C# Analysis Daemon Client ─────────────────────────────────────────────────

class CSharpServiceClient:
    """
    Client for the C# analysis daemon (port 9091).
    Falls back gracefully if the service is unavailable.
    """

    def __init__(self):
        # Full base URL — settings resolves local/Docker (http://host:port)
        # and Render (https://<service>.onrender.com) variants.
        self.base_url = getattr(
            settings, "CSHARP_SERVICE_URL", "http://localhost:9091"
        ).rstrip("/")

    def health(self) -> dict:
        """GET /health — Check if the C# daemon is reachable."""
        try:
            resp = requests.get(
                f"{self.base_url}/health",
                timeout=(_CONNECT_TIMEOUT, _DEFAULT_TIMEOUT),
            )
            return resp.json()
        except requests.RequestException:
            return {"status": "unreachable", "service": "C# Daemon"}

    def analyze(
        self,
        source_code:       str,
        filename:          str  = "Snippet.cs",
        semantic_analysis: bool = False,
        language_version:  str  = "Latest",
    ) -> dict:
        """
        POST /analyze — Analyse a C# source snippet with Roslyn.

        Args:
            source_code:       Raw C# source code string.
            filename:          Filename hint for diagnostic messages.
            semantic_analysis: If True, also run type-checking.
            language_version:  C# language version ("Latest", "12", "11", etc.)

        Returns:
            dict: Full response from the C# daemon including:
                {
                  "success": bool,
                  "syntax_ok": bool,
                  "diagnostics": [...],
                  "metrics": {...},
                  "findings": [...],
                  "duration_ms": int
                }

        Raises:
            ServiceUnavailableError: If the daemon cannot be reached.
        """
        payload = {
            "source_code":       source_code,
            "filename":          filename,
            "semantic_analysis": semantic_analysis,
            "language_version":  language_version,
        }

        try:
            resp = requests.post(
                f"{self.base_url}/analyze",
                json=payload,
                timeout=(_CONNECT_TIMEOUT, _DEFAULT_TIMEOUT),
            )
            result = resp.json()
            logger.debug(
                "C# analyze: syntax_ok=%s, %d findings, %dms",
                result.get("syntax_ok"),
                len(result.get("findings", [])),
                result.get("duration_ms", 0),
            )
            return result

        except requests.ConnectionError:
            logger.warning("C# daemon unreachable at %s", self.base_url)
            raise ServiceUnavailableError(
                f"C# analysis daemon is not running at {self.base_url}. "
                "Start it with: dotnet run --project csharp_service"
            )
        except requests.Timeout:
            raise ServiceUnavailableError("C# daemon timed out.")
        except requests.RequestException as e:
            raise ServiceUnavailableError(f"C# daemon request failed: {e}")

    def analyze_safe(self, source_code: str, **kwargs) -> dict:
        """
        Like analyze(), but never raises — returns an error dict on failure.
        Use this when C# analysis is optional enrichment.
        """
        try:
            return self.analyze(source_code, **kwargs)
        except ServiceUnavailableError as e:
            logger.info("C# daemon unavailable (non-fatal): %s", e)
            return {
                "success":     False,
                "syntax_ok":   None,
                "diagnostics": [],
                "findings":    [],
                "metrics":     {},
                "error":       str(e),
                "duration_ms": 0,
            }


# ── Convenience: check all services at once ───────────────────────────────────

def check_all_services() -> dict:
    """
    Checks the health of all microservices in parallel.
    Returns a dict mapping service name → health response.
    Used by the health_check view (?services=1).

    Never raises: a service that fails or times out is reported as
    "error"/"timeout" while the others still return their real status.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    checks = {
        "java":   JavaServiceClient().health,
        "csharp": CSharpServiceClient().health,
    }

    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(fn): name for name, fn in checks.items()}
        try:
            for future in as_completed(futures, timeout=5):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = {"status": "error", "error": str(e)}
        except TimeoutError:
            # Partial results are still useful; the remaining futures are
            # collected below once the pool has drained.
            pass

    # The pool has drained — pick up anything that finished after the
    # as_completed deadline, and mark the rest as timed out.
    for future, name in futures.items():
        if name in results:
            continue
        try:
            results[name] = future.result(timeout=0)
        except Exception as e:
            results[name] = {"status": "timeout", "error": f"no response within 5s ({e})"}

    return results
