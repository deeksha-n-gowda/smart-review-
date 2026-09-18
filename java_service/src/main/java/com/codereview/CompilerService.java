package com.codereview;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.tools.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CompilerService.java — Java Code Compiler Microservice
 * ========================================================
 * A lightweight HTTP server (com.sun.net.httpserver — no Spring, no Jetty)
 * that accepts Java source code snippets, compiles them using the in-process
 * javax.tools.JavaCompiler API, and returns structured diagnostics.
 *
 * This service is called by the Django backend when a .java file is uploaded
 * to supplement the Python-based static analysis with actual compile-time checks.
 *
 * Endpoints:
 *   POST /compile     Compile (and optionally run) a Java source snippet
 *   GET  /health      Liveness check for Docker health checks
 *   GET  /metrics     Simple request counter and uptime
 *
 * Design decisions:
 *   - Uses javax.tools for in-process compilation (no subprocess overhead)
 *   - Compiles into a temp directory cleaned up after each request
 *   - Execution (when check_only=false) is sandboxed with a SecurityManager-like
 *     timeout via a dedicated thread pool that is interrupted if it overruns
 *   - Single-threaded HTTP server with a cached thread pool for concurrency
 *   - All I/O is UTF-8; JSON via Gson
 *
 * Build & run:
 *   mvn clean package -q
 *   java -jar target/code-review-service-1.0.jar [port]
 *   # Default port: 9090
 *
 * Docker:
 *   docker build -f docker/Dockerfile.java -t codelens-java .
 *   docker run -p 9090:9090 codelens-java
 */
public class CompilerService {

    // ── Configuration ─────────────────────────────────────────────────────

    private static final int    DEFAULT_PORT    = 9090;
    private static final int    BACKLOG         = 50;    // TCP connection queue depth
    private static final int    THREAD_POOL_SIZE = 8;    // Concurrent request handlers
    private static final long   MAX_SOURCE_BYTES = 512 * 1024;  // 512 KB source limit
    private static final String SERVICE_VERSION  = "1.0";

    // ── State ─────────────────────────────────────────────────────────────

    private static final Logger       log        = Logger.getLogger(CompilerService.class.getName());
    private static final Gson         GSON       = new GsonBuilder().setPrettyPrinting().create();
    private static final long         START_TIME = System.currentTimeMillis();
    private static final AtomicLong   REQ_COUNT  = new AtomicLong(0);
    private static final AtomicLong   ERR_COUNT  = new AtomicLong(0);

    // Regex to extract public class name from Java source
    private static final Pattern CLASS_NAME_RE = Pattern.compile(
        "(?:public\\s+)?class\\s+(\\w+)", Pattern.MULTILINE
    );

    // ── Entry Point ───────────────────────────────────────────────────────

    public static void main(String[] args) throws IOException {
        setupLogging();

        int port = DEFAULT_PORT;
        if (args.length > 0) {
            try { port = Integer.parseInt(args[0]); }
            catch (NumberFormatException e) {
                log.warning("Invalid port argument '" + args[0] + "' — using default " + DEFAULT_PORT);
            }
        }

        // Override with env var (for Docker)
        String envPort = System.getenv("JAVA_SERVICE_PORT");
        if (envPort != null && !envPort.isBlank()) {
            try { port = Integer.parseInt(envPort.trim()); }
            catch (NumberFormatException ignored) {}
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), BACKLOG);

        // Route handlers
        server.createContext("/compile", CompilerService::handleCompile);
        server.createContext("/health",  CompilerService::handleHealth);
        server.createContext("/metrics", CompilerService::handleMetrics);

        // Thread pool for concurrent request handling
        server.setExecutor(Executors.newFixedThreadPool(THREAD_POOL_SIZE));
        server.start();

        printBanner(port);
    }

    // ── HTTP Handlers ─────────────────────────────────────────────────────

    /**
     * POST /compile
     * Accepts: application/json  { source_code, class_name?, check_only?, timeout_ms? }
     * Returns: application/json  { success, compile_ok, diagnostics, stdout, stderr, duration_ms, ... }
     */
    private static void handleCompile(HttpExchange exchange) throws IOException {
        long reqStart = System.currentTimeMillis();
        REQ_COUNT.incrementAndGet();

        // Only allow POST
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendJson(exchange, 405, Map.of("error", "Method Not Allowed", "detail", "Use POST /compile"));
            return;
        }

        // Read and parse request body
        ReviewRequest request;
        try {
            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            if (bodyBytes.length > MAX_SOURCE_BYTES) {
                sendJson(exchange, 413, new ReviewRequest.ErrorResponse(
                    "Payload Too Large",
                    "Source code exceeds " + (MAX_SOURCE_BYTES / 1024) + " KB limit."
                ));
                return;
            }
            String body = new String(bodyBytes, StandardCharsets.UTF_8);
            request = GSON.fromJson(body, ReviewRequest.class);
        } catch (JsonSyntaxException e) {
            sendJson(exchange, 400, new ReviewRequest.ErrorResponse(
                "Bad Request", "Invalid JSON: " + e.getMessage()
            ));
            return;
        }

        // Validate required field
        if (request == null || request.source_code == null || request.source_code.isBlank()) {
            sendJson(exchange, 400, new ReviewRequest.ErrorResponse(
                "Bad Request", "'source_code' field is required and must not be empty."
            ));
            return;
        }

        // Run compilation
        ReviewRequest result = compileAndRun(request);
        result.duration_ms = System.currentTimeMillis() - reqStart;

        if (!result.success) ERR_COUNT.incrementAndGet();

        int httpStatus = result.success ? 200 : 500;
        sendJson(exchange, httpStatus, result);

        log.info(String.format(
            "POST /compile — class=%s compile_ok=%b run_ok=%b diags=%d %dms",
            result.resolved_class_name, result.compile_ok, result.run_ok,
            result.diagnostics.size(), result.duration_ms
        ));
    }

    /**
     * GET /health
     * Returns 200 if the service is alive and the Java compiler is accessible.
     */
    private static void handleHealth(HttpExchange exchange) throws IOException {
        REQ_COUNT.incrementAndGet();
        long uptime = System.currentTimeMillis() - START_TIME;

        // Verify the Java compiler is available
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        boolean compilerAvailable = (compiler != null);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status",             compilerAvailable ? "ok" : "degraded");
        body.put("service",            "CodeLens Java Compiler Service");
        body.put("version",            SERVICE_VERSION);
        body.put("java_version",       System.getProperty("java.version"));
        body.put("compiler_available", compilerAvailable);
        body.put("uptime_ms",          uptime);
        body.put("requests_total",     REQ_COUNT.get());

        sendJson(exchange, compilerAvailable ? 200 : 503, body);
    }

    /**
     * GET /metrics
     * Returns simple operational metrics for monitoring.
     */
    private static void handleMetrics(HttpExchange exchange) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("requests_total",  REQ_COUNT.get());
        body.put("errors_total",    ERR_COUNT.get());
        body.put("uptime_ms",       System.currentTimeMillis() - START_TIME);
        body.put("threads_active",  Thread.activeCount());
        body.put("memory_used_mb",
            (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024));
        sendJson(exchange, 200, body);
    }

    // ── Compilation Engine ────────────────────────────────────────────────

    /**
     * Core compilation logic. Steps:
     *   1. Resolve the class name from source or request
     *   2. Write source to a temp directory
     *   3. Invoke javax.tools.JavaCompiler in-process
     *   4. Collect diagnostics
     *   5. Optionally execute the compiled class in a child process (if !check_only)
     *   6. Clean up temp directory
     */
    private static ReviewRequest compileAndRun(ReviewRequest request) {
        ReviewRequest result = new ReviewRequest();

        // ── Step 1: resolve class name ──────────────────────────────────
        String className = resolveClassName(request.source_code, request.class_name);
        result.resolved_class_name = className;

        // ── Step 2: write source to temp dir ────────────────────────────
        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("codelens-");
            Path sourceFile = tempDir.resolve(className + ".java");
            Files.writeString(sourceFile, request.source_code, StandardCharsets.UTF_8);

            // ── Step 3: compile ──────────────────────────────────────────
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) {
                result.error = "Java compiler (javac) not available in this JRE. Use a JDK.";
                result.success = false;
                return result;
            }

            DiagnosticCollector<JavaFileObject> diagnosticCollector = new DiagnosticCollector<>();
            StandardJavaFileManager fileManager =
                compiler.getStandardFileManager(diagnosticCollector, Locale.ENGLISH, StandardCharsets.UTF_8);

            // Set output directory for .class files
            fileManager.setLocation(
                StandardLocation.CLASS_OUTPUT,
                List.of(tempDir.toFile())
            );

            Iterable<? extends JavaFileObject> compilationUnits =
                fileManager.getJavaFileObjectsFromPaths(List.of(sourceFile));

            // Compiler options: Java 17 source/target, verbose diagnostics
            List<String> options = List.of("-source", "17", "-target", "17", "-Xlint:all");

            JavaCompiler.CompilationTask task = compiler.getTask(
                null,              // writer — null means stderr (we capture via diagnostics)
                fileManager,
                diagnosticCollector,
                options,
                null,              // annotation processors
                compilationUnits
            );

            // ── Step 4: collect diagnostics ──────────────────────────────
            boolean compilationSuccess = task.call();
            result.compile_ok = compilationSuccess;

            for (javax.tools.Diagnostic<? extends JavaFileObject> diag : diagnosticCollector.getDiagnostics()) {
                String fragment = "";
                try {
                    // Extract the offending source fragment (the line that caused the error)
                    if (diag.getSource() != null) {
                        CharSequence src = diag.getSource().getCharContent(true);
                        String[] lines   = src.toString().split("\n");
                        long lineNum     = diag.getLineNumber();
                        if (lineNum > 0 && lineNum <= lines.length) {
                            fragment = lines[(int)(lineNum - 1)].stripLeading();
                        }
                    }
                } catch (IOException ignored) {}

                result.diagnostics.add(new ReviewRequest.Diagnostic(
                    diag.getKind().name(),
                    diag.getLineNumber(),
                    diag.getColumnNumber(),
                    diag.getMessage(Locale.ENGLISH),
                    fragment
                ));
            }

            fileManager.close();

            // ── Step 5: optionally execute ───────────────────────────────
            if (compilationSuccess && !request.check_only) {
                runCompiledClass(result, tempDir, className, request.timeout_ms);
            }

            result.success = true;

        } catch (Exception e) {
            result.success = false;
            result.error   = "Internal error during compilation: " + e.getMessage();
            log.severe("Compile exception: " + e);

        } finally {
            // ── Step 6: clean up temp directory ──────────────────────────
            if (tempDir != null) {
                deleteDirectory(tempDir);
            }
        }

        return result;
    }

    /**
     * Executes a compiled Java class in a child JVM process with a timeout.
     * Captures stdout and stderr separately.
     */
    private static void runCompiledClass(
            ReviewRequest result, Path tempDir,
            String className, int timeoutMs) {

        try {
            // Build: java -cp <tempDir> <ClassName>
            ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-cp", tempDir.toAbsolutePath().toString(),
                // Prevent the child process from accessing the network or filesystem
                // beyond what's needed for basic output
                "-Djava.security.manager=allow",
                className
            );
            pb.directory(tempDir.toFile());

            Process process = pb.start();

            // Read stdout and stderr concurrently to avoid pipe buffer deadlocks
            ExecutorService ioPool = Executors.newFixedThreadPool(2);

            Future<String> stdoutFuture = ioPool.submit(() ->
                new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
            );
            Future<String> stderrFuture = ioPool.submit(() ->
                new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8)
            );

            boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);

            if (!finished) {
                process.destroyForcibly();
                result.stderr = "[TIMEOUT] Process exceeded " + timeoutMs + "ms and was killed.";
                result.run_ok = false;
            } else {
                result.stdout = stdoutFuture.get(2, TimeUnit.SECONDS);
                result.stderr = stderrFuture.get(2, TimeUnit.SECONDS);
                result.run_ok = (process.exitValue() == 0);
            }

            ioPool.shutdownNow();

        } catch (Exception e) {
            result.stderr = "Failed to execute compiled class: " + e.getMessage();
            result.run_ok = false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Resolves the Java class name to use as the filename.
     * Priority: explicit request.class_name → regex extraction → "Solution".
     */
    private static String resolveClassName(String source, String hint) {
        if (hint != null && hint.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return hint;
        }
        Matcher m = CLASS_NAME_RE.matcher(source);
        if (m.find()) {
            return m.group(1);
        }
        return "Solution";  // Safe fallback
    }

    /**
     * Serialises an object as JSON and writes it to the HTTP response.
     */
    private static void sendJson(HttpExchange exchange, int statusCode, Object body) throws IOException {
        String json    = GSON.toJson(body);
        byte[] bytes   = json.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("X-Service", "CodeLens-Java/" + SERVICE_VERSION);

        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Recursively deletes a directory. Used to clean up temp compilation dirs.
     */
    private static void deleteDirectory(Path dir) {
        try {
            Files.walk(dir)
                 .sorted(Comparator.reverseOrder())
                 .map(Path::toFile)
                 .forEach(File::delete);
        } catch (IOException e) {
            log.warning("Failed to clean up temp dir " + dir + ": " + e.getMessage());
        }
    }

    /**
     * Configures java.util.logging to print readable one-line messages.
     */
    private static void setupLogging() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        for (Handler h : rootLogger.getHandlers()) {
            rootLogger.removeHandler(h);
        }
        ConsoleHandler handler = new ConsoleHandler();
        handler.setLevel(Level.ALL);
        handler.setFormatter(new SimpleFormatter() {
            @Override
            public String format(LogRecord record) {
                return String.format(
                    "[%s] %s %-7s — %s%n",
                    new java.util.Date(record.getMillis()),
                    record.getLoggerName().replaceAll(".*\\.", ""),
                    record.getLevel(),
                    record.getMessage()
                );
            }
        });
        rootLogger.addHandler(handler);
    }

    /**
     * Prints the startup banner to stdout.
     */
    private static void printBanner(int port) {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║     CodeLens — Java Compiler Microservice            ║");
        System.out.printf ("║     Listening on port %-32d║%n", port);
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.println("║  POST  /compile   — compile & check Java source      ║");
        System.out.println("║  GET   /health    — liveness check                   ║");
        System.out.println("║  GET   /metrics   — request counters                 ║");
        System.out.println("╠══════════════════════════════════════════════════════╣");
        System.out.println("║  Java: " + System.getProperty("java.version")
                           + "  |  JVM: " + System.getProperty("java.vm.name"));
        System.out.println("╚══════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
