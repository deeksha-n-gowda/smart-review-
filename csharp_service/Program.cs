// Program.cs — CodeLens C# Analysis Daemon
// ==========================================
// Entry point for the C# static analysis microservice.
//
// Transport modes (configured by command-line args or environment variables):
//
//   --mode http   (default)  Listens on an HTTP port for JSON requests.
//                            Compatible with the Docker setup and the Django backend's
//                            requests.post() calls.
//
//   --mode pipe              Listens on a Windows Named Pipe (or Unix domain socket).
//                            Mimics the IPC channel that VS Code's C# extension uses
//                            to communicate with OmniSharp/Roslyn language server.
//
// Endpoints (HTTP mode):
//   POST /analyze   — Analyse a C# source snippet
//   GET  /health    — Liveness check
//   GET  /metrics   — Request counters and uptime
//
// Build:
//   dotnet build
//   dotnet run -- --mode http --port 9091
//
// Docker:
//   docker build -f docker/Dockerfile.csharp -t codelens-csharp .
//   docker run -p 9091:9091 codelens-csharp
//
// Named pipe (Windows only):
//   dotnet run -- --mode pipe --pipe CodeReviewDaemonPipe

using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Diagnostics;
using System.Collections.Concurrent;

namespace CodeReview;

// ── JSON Options ──────────────────────────────────────────────────────────────
// Shared across both transport modes
file static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive    = true,
        PropertyNamingPolicy           = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition         = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented                  = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}

// ── Program Entry Point ───────────────────────────────────────────────────────
internal static class Program
{
    private static readonly long          StartTime     = Stopwatch.GetTimestamp();
    private static          long          RequestsTotal = 0;
    private static          long          ErrorsTotal   = 0;
    private static readonly AnalysisEngine Engine       = new();

    // ── Argument parsing ──────────────────────────────────────────────────

    private static string GetArg(string[] args, string flag, string defaultValue)
    {
        int idx = Array.IndexOf(args, flag);
        return (idx >= 0 && idx + 1 < args.Length) ? args[idx + 1] : defaultValue;
    }

    // ── Main ──────────────────────────────────────────────────────────────

    static async Task Main(string[] args)
    {
        // Parse mode + config from args or environment
        string mode     = GetArg(args, "--mode",  Environment.GetEnvironmentVariable("DAEMON_MODE")  ?? "http");
        string portStr  = GetArg(args, "--port",  Environment.GetEnvironmentVariable("CSHARP_PORT") ?? "9091");
        string pipeName = GetArg(args, "--pipe",  Environment.GetEnvironmentVariable("CSHARP_PIPE_NAME") ?? "CodeReviewDaemonPipe");

        int port = int.TryParse(portStr, out int p) ? p : 9091;

        PrintBanner(mode, port, pipeName);

        // Graceful shutdown on Ctrl+C or SIGTERM
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\n[Daemon] Shutting down gracefully…");
            cts.Cancel();
        };

        if (mode.Equals("pipe", StringComparison.OrdinalIgnoreCase))
        {
            await RunPipeServerAsync(pipeName, cts.Token);
        }
        else
        {
            await RunHttpServerAsync(port, cts.Token);
        }
    }

    // =========================================================================
    // HTTP Mode
    // =========================================================================

    private static async Task RunHttpServerAsync(int port, CancellationToken ct)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://*:{port}/");

        try
        {
            listener.Start();
            Console.WriteLine($"[HTTP] Listening on http://0.0.0.0:{port}/");
        }
        catch (HttpListenerException ex)
        {
            // On Windows, binding to * requires admin or a URL reservation.
            // Fall back to localhost only.
            Console.WriteLine($"[HTTP] Could not bind to *:{port} ({ex.Message}). Falling back to localhost.");
            listener = new HttpListener();
            listener.Prefixes.Add($"http://localhost:{port}/");
            listener.Start();
            Console.WriteLine($"[HTTP] Listening on http://localhost:{port}/");
        }

        // Use a thread pool to handle concurrent requests
        var semaphore = new SemaphoreSlim(16, 16);

        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await listener.GetContextAsync().WaitAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[HTTP] Accept error: {ex.Message}");
                continue;
            }

            // Handle each request concurrently but bounded
            _ = Task.Run(async () =>
            {
                await semaphore.WaitAsync(ct);
                try { await HandleHttpRequestAsync(ctx); }
                finally { semaphore.Release(); }
            }, ct);
        }

        listener.Stop();
    }

    private static async Task HandleHttpRequestAsync(HttpListenerContext ctx)
    {
        Interlocked.Increment(ref RequestsTotal);
        var sw = Stopwatch.StartNew();

        string method = ctx.Request.HttpMethod.ToUpperInvariant();
        string path   = ctx.Request.Url?.AbsolutePath ?? "/";

        // CORS preflight
        if (method == "OPTIONS")
        {
            ctx.Response.AddHeader("Access-Control-Allow-Origin",  "*");
            ctx.Response.AddHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            ctx.Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");
            ctx.Response.StatusCode = 204;
            ctx.Response.Close();
            return;
        }

        try
        {
            switch (path)
            {
                case "/analyze" when method == "POST":
                    await HandleAnalyzeAsync(ctx);
                    break;

                case "/health" when method == "GET":
                    await HandleHealthAsync(ctx);
                    break;

                case "/metrics" when method == "GET":
                    await HandleMetricsAsync(ctx);
                    break;

                default:
                    await SendJsonAsync(ctx, 404,
                        new { error = "Not Found", detail = $"No route for {method} {path}" });
                    break;
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref ErrorsTotal);
            Console.Error.WriteLine($"[HTTP] Unhandled error: {ex}");
            try { await SendJsonAsync(ctx, 500, new { error = "Internal Server Error", detail = ex.Message }); }
            catch { /* response already started */ }
        }

        sw.Stop();
        Console.WriteLine($"[HTTP] {method} {path} → {ctx.Response.StatusCode} ({sw.ElapsedMilliseconds}ms)");
    }

    // ── /analyze ─────────────────────────────────────────────────────────

    private static async Task HandleAnalyzeAsync(HttpListenerContext ctx)
    {
        // Read and deserialise request body
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(body))
        {
            await SendJsonAsync(ctx, 400, new
            {
                error  = "Bad Request",
                detail = "Request body is empty. Send JSON with 'source_code' field."
            });
            return;
        }

        AnalysisRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<AnalysisRequest>(body, Json.Options);
        }
        catch (JsonException ex)
        {
            await SendJsonAsync(ctx, 400, new { error = "Bad Request", detail = $"Invalid JSON: {ex.Message}" });
            return;
        }

        if (request is null || string.IsNullOrWhiteSpace(request.SourceCode))
        {
            await SendJsonAsync(ctx, 400, new
            {
                error  = "Bad Request",
                detail = "'source_code' field is required and must not be empty."
            });
            return;
        }

        // Run analysis (CPU-bound — offload to thread pool)
        AnalysisResult result = await Task.Run(() => Engine.Analyse(request));

        int statusCode = result.Success ? 200 : 500;
        await SendJsonAsync(ctx, statusCode, result);
    }

    // ── /health ──────────────────────────────────────────────────────────

    private static async Task HandleHealthAsync(HttpListenerContext ctx)
    {
        long uptimeMs = (long)((Stopwatch.GetTimestamp() - StartTime) * 1000.0 / Stopwatch.Frequency);
        await SendJsonAsync(ctx, 200, new HealthResponse
        {
            Status         = "ok",
            RoslynAvailable = true,
            UptimeMs       = uptimeMs,
            RequestsTotal  = Interlocked.Read(ref RequestsTotal),
        });
    }

    // ── /metrics ─────────────────────────────────────────────────────────

    private static async Task HandleMetricsAsync(HttpListenerContext ctx)
    {
        long uptimeMs = (long)((Stopwatch.GetTimestamp() - StartTime) * 1000.0 / Stopwatch.Frequency);
        await SendJsonAsync(ctx, 200, new
        {
            requests_total  = Interlocked.Read(ref RequestsTotal),
            errors_total    = Interlocked.Read(ref ErrorsTotal),
            uptime_ms       = uptimeMs,
            dotnet_version  = Environment.Version.ToString(),
            gc_memory_mb    = GC.GetTotalMemory(false) / (1024 * 1024),
        });
    }

    // ── JSON response helper ──────────────────────────────────────────────

    private static async Task SendJsonAsync(HttpListenerContext ctx, int statusCode, object body)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body, Json.Options);
        ctx.Response.StatusCode  = statusCode;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.AddHeader("Access-Control-Allow-Origin", "*");
        ctx.Response.AddHeader("X-Service", "CodeLens-CSharp/1.0");
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    // =========================================================================
    // Named Pipe Mode (VS Code extension daemon simulation)
    // =========================================================================

    private static async Task RunPipeServerAsync(string pipeName, CancellationToken ct)
    {
        Console.WriteLine($"[Pipe] Listening on named pipe: {pipeName}");
        Console.WriteLine("[Pipe] Send newline-delimited JSON requests.");

        while (!ct.IsCancellationRequested)
        {
            // Each client connection gets its own NamedPipeServerStream instance
            var pipeServer = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous
            );

            try
            {
                Console.WriteLine("[Pipe] Waiting for client connection…");
                await pipeServer.WaitForConnectionAsync(ct);
                Console.WriteLine("[Pipe] Client connected.");

                // Handle this client connection asynchronously
                _ = Task.Run(() => HandlePipeClientAsync(pipeServer, ct), ct);
            }
            catch (OperationCanceledException)
            {
                pipeServer.Dispose();
                break;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Pipe] Connection error: {ex.Message}");
                pipeServer.Dispose();
            }
        }

        Console.WriteLine("[Pipe] Server stopped.");
    }

    private static async Task HandlePipeClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        Interlocked.Increment(ref RequestsTotal);

        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            await using var writer = new StreamWriter(pipe, Encoding.UTF8, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine   = "\n",
            };

            // Read one newline-delimited JSON message per connection
            string? line = await reader.ReadLineAsync(ct);
            if (string.IsNullOrWhiteSpace(line))
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(
                    new { error = "Empty request" }, Json.Options));
                return;
            }

            AnalysisRequest? request;
            try
            {
                request = JsonSerializer.Deserialize<AnalysisRequest>(line, Json.Options);
            }
            catch
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(
                    new { error = "Invalid JSON" }, Json.Options));
                return;
            }

            if (request is null || string.IsNullOrWhiteSpace(request.SourceCode))
            {
                await writer.WriteLineAsync(JsonSerializer.Serialize(
                    new { error = "source_code is required" }, Json.Options));
                return;
            }

            // Run analysis
            AnalysisResult result = await Task.Run(() => Engine.Analyse(request), ct);

            string json = JsonSerializer.Serialize(result, Json.Options);
            await writer.WriteLineAsync(json);

            Console.WriteLine(
                $"[Pipe] Analysis complete: {result.Findings.Count} findings, " +
                $"syntax_ok={result.SyntaxOk}, {result.DurationMs}ms");
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref ErrorsTotal);
            Console.Error.WriteLine($"[Pipe] Client handler error: {ex.Message}");
        }
        finally
        {
            if (pipe.IsConnected) pipe.Disconnect();
            pipe.Dispose();
        }
    }

    // ── Startup banner ─────────────────────────────────────────────────────

    private static void PrintBanner(string mode, int port, string pipeName)
    {
        Console.WriteLine();
        Console.WriteLine("╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║     CodeLens — C# Analysis Daemon                   ║");
        Console.WriteLine("╠══════════════════════════════════════════════════════╣");
        if (mode.Equals("pipe", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"║  Mode:  Named Pipe                                   ║");
            Console.WriteLine($"║  Pipe:  {pipeName,-43}║");
        }
        else
        {
            Console.WriteLine($"║  Mode:  HTTP                                         ║");
            Console.WriteLine($"║  Port:  {port,-43}║");
            Console.WriteLine($"║  POST   /analyze  — analyse C# source snippet        ║");
            Console.WriteLine($"║  GET    /health   — liveness check                   ║");
            Console.WriteLine($"║  GET    /metrics  — request counters                 ║");
        }
        Console.WriteLine("╠══════════════════════════════════════════════════════╣");
        Console.WriteLine($"║  .NET:  {Environment.Version,-43}║");
        Console.WriteLine($"║  OS:    {Environment.OSVersion.Platform,-43}║");
        Console.WriteLine("╠══════════════════════════════════════════════════════╣");
        Console.WriteLine("║  Press Ctrl+C to stop                                ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.WriteLine();
    }
}
