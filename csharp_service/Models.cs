// Models.cs — Data Models for the C# Analysis Daemon
// =====================================================
// Request and response types used for IPC communication between the
// Django backend and this daemon via named pipe or HTTP.
//
// Serialized as JSON using System.Text.Json.

using System.Text.Json.Serialization;

namespace CodeReview;

/// <summary>
/// Incoming analysis request from the Django backend.
/// </summary>
public sealed class AnalysisRequest
{
    /// <summary>Raw C# source code to analyse. Required.</summary>
    [JsonPropertyName("source_code")]
    public string SourceCode { get; set; } = string.Empty;

    /// <summary>
    /// Optional filename/context hint used in diagnostic messages.
    /// Defaults to "Snippet.cs" if not provided.
    /// </summary>
    [JsonPropertyName("filename")]
    public string Filename { get; set; } = "Snippet.cs";

    /// <summary>
    /// If true, run semantic analysis in addition to syntax parsing.
    /// Semantic analysis catches type errors, missing references, etc.
    /// More thorough but slightly slower.
    /// </summary>
    [JsonPropertyName("semantic_analysis")]
    public bool SemanticAnalysis { get; set; } = false;

    /// <summary>
    /// Language version for the Roslyn parser.
    /// Defaults to "Latest" (C# 12 for .NET 8).
    /// </summary>
    [JsonPropertyName("language_version")]
    public string LanguageVersion { get; set; } = "Latest";
}

/// <summary>
/// Full analysis result returned to the Django backend.
/// </summary>
public sealed class AnalysisResult
{
    /// <summary>True if the daemon processed the request without internal errors.</summary>
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    /// <summary>The filename used for this analysis (echoed from request).</summary>
    [JsonPropertyName("filename")]
    public string Filename { get; set; } = string.Empty;

    /// <summary>True if the source parsed without syntax errors.</summary>
    [JsonPropertyName("syntax_ok")]
    public bool SyntaxOk { get; set; }

    /// <summary>True if semantic analysis passed (only set when semantic_analysis=true).</summary>
    [JsonPropertyName("semantic_ok")]
    public bool? SemanticOk { get; set; }

    /// <summary>Total number of errors (severity Error or Fatal).</summary>
    [JsonPropertyName("error_count")]
    public int ErrorCount { get; set; }

    /// <summary>Total number of warnings.</summary>
    [JsonPropertyName("warning_count")]
    public int WarningCount { get; set; }

    /// <summary>Structured list of diagnostics (errors + warnings) from Roslyn.</summary>
    [JsonPropertyName("diagnostics")]
    public List<DiagnosticItem> Diagnostics { get; set; } = new();

    /// <summary>High-level code metrics extracted from the syntax tree.</summary>
    [JsonPropertyName("metrics")]
    public CodeMetrics Metrics { get; set; } = new();

    /// <summary>Pattern-based vulnerability findings (mirrors the Python rule engine).</summary>
    [JsonPropertyName("findings")]
    public List<Finding> Findings { get; set; } = new();

    /// <summary>Total analysis time in milliseconds.</summary>
    [JsonPropertyName("duration_ms")]
    public long DurationMs { get; set; }

    /// <summary>If Success=false, describes what went wrong internally.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

/// <summary>
/// A single Roslyn diagnostic (error or warning).
/// </summary>
public sealed class DiagnosticItem
{
    /// <summary>"Error" | "Warning" | "Info" | "Hidden"</summary>
    [JsonPropertyName("severity")]
    public string Severity { get; set; } = string.Empty;

    /// <summary>Roslyn diagnostic ID, e.g. "CS0103".</summary>
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    /// <summary>Human-readable diagnostic message.</summary>
    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    /// <summary>1-indexed line number (0 = not applicable).</summary>
    [JsonPropertyName("line")]
    public int Line { get; set; }

    /// <summary>1-indexed column offset (0 = not applicable).</summary>
    [JsonPropertyName("column")]
    public int Column { get; set; }

    /// <summary>The source text fragment that triggered the diagnostic.</summary>
    [JsonPropertyName("source_fragment")]
    public string SourceFragment { get; set; } = string.Empty;
}

/// <summary>
/// High-level metrics derived from the Roslyn syntax tree.
/// </summary>
public sealed class CodeMetrics
{
    [JsonPropertyName("line_count")]
    public int LineCount { get; set; }

    [JsonPropertyName("class_count")]
    public int ClassCount { get; set; }

    [JsonPropertyName("method_count")]
    public int MethodCount { get; set; }

    [JsonPropertyName("property_count")]
    public int PropertyCount { get; set; }

    [JsonPropertyName("namespace_count")]
    public int NamespaceCount { get; set; }

    [JsonPropertyName("using_count")]
    public int UsingCount { get; set; }

    [JsonPropertyName("comment_count")]
    public int CommentCount { get; set; }

    [JsonPropertyName("max_nesting_depth")]
    public int MaxNestingDepth { get; set; }

    [JsonPropertyName("has_async_methods")]
    public bool HasAsyncMethods { get; set; }

    [JsonPropertyName("has_unsafe_blocks")]
    public bool HasUnsafeBlocks { get; set; }
}

/// <summary>
/// A pattern-based vulnerability finding from the AnalysisEngine rule set.
/// These supplement the Roslyn diagnostics with security-focused checks.
/// </summary>
public sealed class Finding
{
    [JsonPropertyName("rule_id")]
    public string RuleId { get; set; } = string.Empty;

    [JsonPropertyName("title")]
    public string Title { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "medium";

    [JsonPropertyName("category")]
    public string Category { get; set; } = "security";

    [JsonPropertyName("line")]
    public int Line { get; set; }

    [JsonPropertyName("snippet")]
    public string Snippet { get; set; } = string.Empty;

    [JsonPropertyName("recommendation")]
    public string Recommendation { get; set; } = string.Empty;

    [JsonPropertyName("cwe_id")]
    public string CweId { get; set; } = string.Empty;
}

/// <summary>Service health check response.</summary>
public sealed class HealthResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "ok";

    [JsonPropertyName("service")]
    public string Service { get; set; } = "CodeLens C# Analysis Daemon";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0.0";

    [JsonPropertyName("dotnet_version")]
    public string DotNetVersion { get; set; } = Environment.Version.ToString();

    [JsonPropertyName("roslyn_available")]
    public bool RoslynAvailable { get; set; } = true;

    [JsonPropertyName("uptime_ms")]
    public long UptimeMs { get; set; }

    [JsonPropertyName("requests_total")]
    public long RequestsTotal { get; set; }
}
