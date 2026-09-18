// AnalysisEngine.cs — Roslyn-Based C# Static Analysis Engine
// =============================================================
// Uses the Microsoft.CodeAnalysis.CSharp (Roslyn) API to:
//   1. Parse C# source into a SyntaxTree
//   2. Walk the tree to extract code metrics
//   3. Apply pattern-based security rules
//   4. Optionally run semantic analysis (type checking)
//
// The Roslyn API gives us a proper AST representation — far more reliable
// than regex-based analysis for a strongly-typed language like C#.
//
// Architecture note:
//   This class is purely functional (stateless, thread-safe).
//   The daemon in Program.cs creates one instance and reuses it.

using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace CodeReview;

/// <summary>
/// Core Roslyn analysis engine. Parses C# source and produces
/// diagnostics, metrics, and security findings.
/// </summary>
public sealed class AnalysisEngine
{
    // ── Roslyn language version mapping ──────────────────────────────────

    private static readonly Dictionary<string, LanguageVersion> LangVersionMap = new(
        StringComparer.OrdinalIgnoreCase)
    {
        ["6"]      = LanguageVersion.CSharp6,
        ["7"]      = LanguageVersion.CSharp7,
        ["8"]      = LanguageVersion.CSharp8,
        ["9"]      = LanguageVersion.CSharp9,
        ["10"]     = LanguageVersion.CSharp10,
        ["11"]     = LanguageVersion.CSharp11,
        ["12"]     = LanguageVersion.CSharp12,
        ["latest"] = LanguageVersion.Latest,
        ["preview"]= LanguageVersion.Preview,
    };

    // ── Security rule patterns (regex applied to individual lines) ────────

    private static readonly List<(string RuleId, string Title, string Pattern,
        string Severity, string Category, string Description,
        string Recommendation, string CweId)> SecurityRules = new()
    {
        (
            "CS-SEC-001",
            "SQL Injection",
            @"(?:SqlCommand|ExecuteNonQuery|ExecuteReader|ExecuteScalar)\s*\([^)]*\+",
            "critical", "security",
            "String concatenation used to build SQL commands — classic SQL injection vulnerability. " +
            "An attacker can manipulate the query to bypass authentication or extract arbitrary data.",
            "Use parameterized queries: cmd.Parameters.AddWithValue(\"@id\", userId);",
            "CWE-89"
        ),
        (
            "CS-SEC-002",
            "BinaryFormatter (Insecure Deserialization)",
            @"\bBinaryFormatter\b",
            "critical", "security",
            "BinaryFormatter is insecure and obsolete in .NET 5+. Deserializing untrusted data " +
            "with BinaryFormatter can result in arbitrary code execution.",
            "Use System.Text.Json or MessagePack for serialization instead.",
            "CWE-502"
        ),
        (
            "CS-SEC-003",
            "Hardcoded Connection String / Credential",
            @"(?:connectionString|password|Password|ApiKey|Secret)\s*=\s""[^""]{8,}""",
            "high", "security",
            "A password, connection string, or API key appears hardcoded in source. " +
            "These end up in compiled assemblies and version control history.",
            "Use IConfiguration with appsettings.json or environment variable overrides. " +
            "For production secrets, use Azure Key Vault or AWS Secrets Manager.",
            "CWE-798"
        ),
        (
            "CS-SEC-004",
            "Weak Cryptography (MD5 / SHA1)",
            @"MD5\.Create\(\)|SHA1\.Create\(\)|new\s+MD5CryptoServiceProvider|new\s+SHA1CryptoServiceProvider",
            "high", "security",
            "MD5 and SHA1 are cryptographically broken. Practical collision attacks " +
            "have been demonstrated against both algorithms.",
            "Use SHA256.Create() or SHA256.HashData(data) for integrity checks. " +
            "For passwords, use BCrypt.Net or Microsoft.AspNetCore.Identity.",
            "CWE-327"
        ),
        (
            "CS-SEC-005",
            "Path Traversal",
            @"(?:File\.Read|File\.Write|File\.Open|Path\.Combine)\s*\([^)]*Request\.\w+",
            "high", "security",
            "User-controlled input used to construct a file path without validation. " +
            "An attacker can use '../' sequences to access files outside the intended directory.",
            "Validate paths with Path.GetFullPath() and verify they start with the allowed root directory.",
            "CWE-22"
        ),
        (
            "CS-SEC-006",
            "XSS via Response.Write()",
            @"Response\.Write\s*\([^)]*Request\.",
            "high", "security",
            "Response.Write() with unsanitized user input enables cross-site scripting (XSS). " +
            "The user's content is rendered directly as HTML in the browser.",
            "HTML-encode output: Response.Write(HttpUtility.HtmlEncode(input)); " +
            "Or use Razor views which auto-encode by default.",
            "CWE-79"
        ),
        (
            "CS-SEC-007",
            "Empty catch Block",
            @"catch\s*(?:\([^)]+\))?\s*\{\s*\}",
            "medium", "maintainability",
            "Empty catch block silently swallows exceptions, making bugs invisible " +
            "and preventing proper error recovery.",
            "At minimum log the exception: _logger.LogError(ex, \"Unexpected error occurred\");",
            "CWE-390"
        ),
        (
            "CS-MAINT-001",
            "TODO / FIXME Comment",
            @"//\s*(?:TODO|FIXME|HACK|XXX)\b",
            "info", "maintainability",
            "Known unfinished or potentially broken code marker left in source.",
            "Create a tracked issue and remove or resolve the comment.",
            ""
        ),
        (
            "CS-PERF-001",
            "String Concatenation in Loop",
            @"\+\s*=\s*[""'\w]",
            "medium", "performance",
            "String '+=' inside a loop creates a new string object per iteration (O(n²)). " +
            "For large datasets this causes significant performance degradation.",
            "Use StringBuilder: var sb = new StringBuilder(); sb.Append(x); result = sb.ToString();",
            ""
        ),
    };

    // ── Public API ─────────────────────────────────────────────────────────

    /// <summary>
    /// Runs the full analysis pipeline on the given C# source code.
    /// </summary>
    /// <param name="request">The incoming analysis request.</param>
    /// <returns>A populated AnalysisResult.</returns>
    public AnalysisResult Analyse(AnalysisRequest request)
    {
        var sw     = Stopwatch.StartNew();
        var result = new AnalysisResult
        {
            Filename = request.Filename,
            Success  = false,
        };

        try
        {
            // 1. Parse into a Roslyn SyntaxTree
            var langVersion = LangVersionMap.GetValueOrDefault(
                request.LanguageVersion, LanguageVersion.Latest);

            var parseOptions = CSharpParseOptions.Default
                .WithLanguageVersion(langVersion);

            var syntaxTree = CSharpSyntaxTree.ParseText(
                request.SourceCode,
                parseOptions,
                request.Filename
            );

            var root = syntaxTree.GetRoot();

            // 2. Collect Roslyn parse diagnostics (syntax errors / warnings)
            var roslynDiags = syntaxTree.GetDiagnostics().ToList();
            result.Diagnostics = roslynDiags
                .Where(d => d.Severity >= DiagnosticSeverity.Warning)
                .Select(d => BuildDiagnosticItem(d, request.SourceCode))
                .ToList();

            result.ErrorCount   = roslynDiags.Count(d => d.Severity == DiagnosticSeverity.Error);
            result.WarningCount = roslynDiags.Count(d => d.Severity == DiagnosticSeverity.Warning);
            result.SyntaxOk     = result.ErrorCount == 0;

            // 3. Walk the tree to compute code metrics
            result.Metrics = ComputeMetrics(root, request.SourceCode);

            // 4. Apply security + quality rules
            result.Findings = ApplyRules(request.SourceCode);

            // 5. Optional semantic analysis
            if (request.SemanticAnalysis)
            {
                result.SemanticOk = RunSemanticAnalysis(syntaxTree, result);
            }

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Error   = $"Internal analysis error: {ex.Message}";
            result.Success = false;
        }

        sw.Stop();
        result.DurationMs = sw.ElapsedMilliseconds;
        return result;
    }

    // ── Roslyn Diagnostic → DiagnosticItem ───────────────────────────────

    private static DiagnosticItem BuildDiagnosticItem(Diagnostic diag, string source)
    {
        var location = diag.Location.GetLineSpan();
        int line     = location.StartLinePosition.Line + 1;   // Roslyn is 0-indexed
        int column   = location.StartLinePosition.Character + 1;

        // Extract the offending source line
        string fragment = string.Empty;
        try
        {
            var lines = source.Split('\n');
            if (line > 0 && line <= lines.Length)
                fragment = lines[line - 1].TrimStart();
        }
        catch { /* non-fatal */ }

        return new DiagnosticItem
        {
            Severity       = diag.Severity.ToString(),
            Id             = diag.Id,
            Message        = diag.GetMessage(),
            Line           = line,
            Column         = column,
            SourceFragment = fragment,
        };
    }

    // ── Code Metrics ──────────────────────────────────────────────────────

    private static CodeMetrics ComputeMetrics(SyntaxNode root, string source)
    {
        var walker  = new MetricsWalker();
        walker.Visit(root);

        var lines = source.Split('\n');
        int commentCount = lines.Count(l =>
            l.TrimStart().StartsWith("//") || l.TrimStart().StartsWith("/*"));

        return new CodeMetrics
        {
            LineCount       = lines.Length,
            ClassCount      = walker.ClassCount,
            MethodCount     = walker.MethodCount,
            PropertyCount   = walker.PropertyCount,
            NamespaceCount  = walker.NamespaceCount,
            UsingCount      = walker.UsingCount,
            CommentCount    = commentCount,
            MaxNestingDepth = walker.MaxNestingDepth,
            HasAsyncMethods = walker.HasAsyncMethods,
            HasUnsafeBlocks = walker.HasUnsafeBlocks,
        };
    }

    // ── Pattern-based Security Rules ──────────────────────────────────────

    private static List<Finding> ApplyRules(string source)
    {
        var findings = new List<Finding>();
        var lines    = source.Split('\n');

        foreach (var (ruleId, title, pattern, severity, category,
                      description, recommendation, cweId) in SecurityRules)
        {
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            for (int i = 0; i < lines.Length; i++)
            {
                if (regex.IsMatch(lines[i]))
                {
                    // Deduplicate: same rule, same line
                    bool alreadyFound = findings.Any(f => f.RuleId == ruleId && f.Line == i + 1);
                    if (!alreadyFound)
                    {
                        findings.Add(new Finding
                        {
                            RuleId         = ruleId,
                            Title          = title,
                            Description    = description,
                            Severity       = severity,
                            Category       = category,
                            Line           = i + 1,
                            Snippet        = lines[i].TrimStart()[..Math.Min(200, lines[i].TrimStart().Length)],
                            Recommendation = recommendation,
                            CweId          = cweId,
                        });
                    }
                }
            }
        }

        // Sort: critical → high → medium → low → info, then by line
        var severityOrder = new Dictionary<string, int>
        {
            ["critical"] = 0, ["high"] = 1, ["medium"] = 2,
            ["low"] = 3, ["info"] = 4
        };
        findings.Sort((a, b) =>
        {
            int sc = severityOrder.GetValueOrDefault(a.Severity, 5)
                   - severityOrder.GetValueOrDefault(b.Severity, 5);
            return sc != 0 ? sc : a.Line - b.Line;
        });

        return findings;
    }

    // ── Semantic Analysis ──────────────────────────────────────────────────

    private static bool RunSemanticAnalysis(SyntaxTree syntaxTree, AnalysisResult result)
    {
        try
        {
            // Build a minimal compilation — no real references since we're
            // analysing snippets without a full project context. This catches
            // type resolution errors within the snippet itself.
            var compilation = CSharpCompilation.Create(
                "CodeLensAnalysis",
                new[] { syntaxTree },
                new[]
                {
                    MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                    MetadataReference.CreateFromFile(typeof(Console).Assembly.Location),
                    MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
                },
                new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)
                    .WithNullableContextOptions(NullableContextOptions.Enable)
            );

            var semanticDiags = compilation.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .ToList();

            // Merge semantic-only errors into result.Diagnostics
            foreach (var d in semanticDiags)
            {
                var item = BuildDiagnosticItem(d, string.Empty);
                item.Id  = "SEMANTIC-" + item.Id;
                result.Diagnostics.Add(item);
                result.ErrorCount++;
            }

            return semanticDiags.Count == 0;
        }
        catch
        {
            return false;   // Semantic analysis is optional; don't fail the whole request
        }
    }
}

// ── Syntax Tree Walker for Metrics ────────────────────────────────────────────

/// <summary>
/// Walks the Roslyn SyntaxTree to count structural elements and
/// compute code quality metrics.
/// </summary>
internal sealed class MetricsWalker : CSharpSyntaxWalker
{
    public int  ClassCount      { get; private set; }
    public int  MethodCount     { get; private set; }
    public int  PropertyCount   { get; private set; }
    public int  NamespaceCount  { get; private set; }
    public int  UsingCount      { get; private set; }
    public int  MaxNestingDepth { get; private set; }
    public bool HasAsyncMethods { get; private set; }
    public bool HasUnsafeBlocks { get; private set; }

    private int _currentDepth;

    public override void VisitClassDeclaration(ClassDeclarationSyntax node)
    {
        ClassCount++;
        base.VisitClassDeclaration(node);
    }

    public override void VisitStructDeclaration(StructDeclarationSyntax node)
    {
        ClassCount++;   // Count structs alongside classes
        base.VisitStructDeclaration(node);
    }

    public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
    {
        MethodCount++;
        if (node.Modifiers.Any(m => m.IsKind(SyntaxKind.AsyncKeyword)))
            HasAsyncMethods = true;
        base.VisitMethodDeclaration(node);
    }

    public override void VisitPropertyDeclaration(PropertyDeclarationSyntax node)
    {
        PropertyCount++;
        base.VisitPropertyDeclaration(node);
    }

    public override void VisitNamespaceDeclaration(NamespaceDeclarationSyntax node)
    {
        NamespaceCount++;
        base.VisitNamespaceDeclaration(node);
    }

    public override void VisitFileScopedNamespaceDeclaration(FileScopedNamespaceDeclarationSyntax node)
    {
        NamespaceCount++;
        base.VisitFileScopedNamespaceDeclaration(node);
    }

    public override void VisitUsingDirective(UsingDirectiveSyntax node)
    {
        UsingCount++;
        base.VisitUsingDirective(node);
    }

    public override void VisitUnsafeStatement(UnsafeStatementSyntax node)
    {
        HasUnsafeBlocks = true;
        base.VisitUnsafeStatement(node);
    }

    // Track nesting depth by overriding block-opening nodes
    public override void VisitBlock(BlockSyntax node)
    {
        _currentDepth++;
        MaxNestingDepth = Math.Max(MaxNestingDepth, _currentDepth);
        base.VisitBlock(node);
        _currentDepth--;
    }
}
