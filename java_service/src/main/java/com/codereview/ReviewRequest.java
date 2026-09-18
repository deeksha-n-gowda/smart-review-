package com.codereview;

import java.util.List;
import java.util.ArrayList;

/**
 * ReviewRequest.java — Data Models for the Compiler Microservice
 * ===============================================================
 * Plain Old Java Objects (POJOs) used for JSON serialization/deserialization
 * via Gson. These mirror the shapes the Django backend sends and expects.
 *
 * Request shape (Django → Java):
 * {
 *   "source_code": "public class Hello { ... }",
 *   "class_name":  "Hello",          // optional — auto-detected if absent
 *   "check_only":  true,             // if true, compile but don't run
 *   "timeout_ms":  5000              // max execution time in ms
 * }
 *
 * Response shape (Java → Django):
 * {
 *   "success":      true,
 *   "class_name":   "Hello",
 *   "compile_ok":   true,
 *   "run_ok":       false,
 *   "stdout":       "",
 *   "stderr":       "",
 *   "diagnostics":  [...],
 *   "duration_ms":  42,
 *   "error":        null
 * }
 */
public class ReviewRequest {

    // ── Incoming request fields ───────────────────────────────────────────

    /** The raw Java source code to compile and/or run. Required. */
    public String source_code;

    /**
     * The public class name inside source_code (used as the filename).
     * If null, the service attempts to extract it from the source via regex.
     */
    public String class_name;

    /**
     * If true, only compile (check syntax/types) — do not execute the code.
     * Default: true (safer for a code review tool).
     */
    public boolean check_only = true;

    /**
     * Maximum wall-clock time allowed for compilation + execution in milliseconds.
     * Default: 5000 ms. The service kills the process if it exceeds this.
     */
    public int timeout_ms = 5000;


    // ── Response / result fields ──────────────────────────────────────────

    /**
     * True if the overall request was handled without an internal service error.
     * Does NOT mean the code compiled successfully — check compile_ok for that.
     */
    public boolean success = false;

    /** The class name that was actually used for compilation. */
    public String resolved_class_name;

    /** True if javac reported zero errors. Warnings are allowed. */
    public boolean compile_ok = false;

    /** True if the compiled program ran and exited with code 0. */
    public boolean run_ok = false;

    /** Captured stdout from program execution (empty if check_only=true). */
    public String stdout = "";

    /** Captured stderr from program execution or compiler output. */
    public String stderr = "";

    /** Structured list of compiler diagnostics (errors + warnings). */
    public List<Diagnostic> diagnostics = new ArrayList<>();

    /** Total wall-clock time from receiving request to sending response. */
    public long duration_ms = 0;

    /** If success=false, this contains the internal error description. */
    public String error = null;


    // ── Nested types ──────────────────────────────────────────────────────

    /**
     * A single compiler diagnostic (error or warning) from javac.
     * Maps directly to javax.tools.Diagnostic.
     */
    public static class Diagnostic {
        /** "ERROR" | "WARNING" | "NOTE" | "OTHER" */
        public String kind;

        /** 1-indexed line number in source_code (0 if not applicable). */
        public long line;

        /** 1-indexed column offset (0 if not applicable). */
        public long column;

        /** The diagnostic message from javac. */
        public String message;

        /** The specific source text fragment that caused the diagnostic. */
        public String source_fragment;

        public Diagnostic(String kind, long line, long column, String message, String sourceFragment) {
            this.kind            = kind;
            this.line            = line;
            this.column          = column;
            this.message         = message;
            this.source_fragment = sourceFragment;
        }

        @Override
        public String toString() {
            return String.format("[%s] line %d:%d — %s", kind, line, column, message);
        }
    }


    /**
     * Health check response model — returned by GET /health.
     */
    public static class HealthResponse {
        public String status   = "ok";
        public String service  = "CodeLens Java Compiler Service";
        public String version  = "1.0";
        public String java_version;
        public long   uptime_ms;

        public HealthResponse(long uptimeMs) {
            this.java_version = System.getProperty("java.version");
            this.uptime_ms    = uptimeMs;
        }
    }


    /**
     * Error response model — returned when the service encounters an
     * unexpected exception before it can produce a full ReviewResult.
     */
    public static class ErrorResponse {
        public boolean success = false;
        public String  error;
        public String  detail;

        public ErrorResponse(String error, String detail) {
            this.error  = error;
            this.detail = detail;
        }
    }
}
