# CodeLens — System Architecture

## Overview

CodeLens is a four-service architecture designed to demonstrate a realistic
multi-language code review system with explainable AI analysis.

```
Browser
  │
  │  HTTP (port 8000)
  ▼
┌──────────────────────────────────────────────┐
│           Django Backend (Python)            │
│                                              │
│  ┌──────────────┐   ┌─────────────────────┐  │
│  │  REST API    │   │   ML Pipeline       │  │
│  │  (api/)      │   │   (ml/)             │  │
│  │              │   │                     │  │
│  │  /upload     │──▶│  CodeAnalyzer       │  │
│  │  /analyze    │   │  ExplanationGen     │  │
│  │  /files      │   │  (SHAP / LIME)      │  │
│  └──────────────┘   └─────────────────────┘  │
│                                              │
│  ┌──────────────┐   ┌─────────────────────┐  │
│  │  AES-256-GCM │   │  PostgreSQL / SQLite │  │
│  │  Encryption  │   │  (core models)       │  │
│  └──────────────┘   └─────────────────────┘  │
└──────────────┬───────────────┬───────────────┘
               │               │
         HTTP  │               │  HTTP
         :9090 │               │  :9091
               ▼               ▼
   ┌───────────────┐   ┌───────────────┐
   │  Java Service │   │  C# Daemon    │
   │               │   │               │
   │  javax.tools  │   │  Roslyn SDK   │
   │  CompilerAPI  │   │  SyntaxTree   │
   │  (in-process) │   │  Semantic     │
   └───────────────┘   └───────────────┘
```

## Service Responsibilities

### Django Backend (Port 8000)
- Receives file uploads via REST API
- Encrypts source code with AES-256-GCM before DB storage
- Runs Python-based rule engine (`ml/analyzer.py`) for all four languages
- Generates SHAP/LIME explanations (`ml/explainer.py`)
- Optionally calls Java service for `.java` compile-time checks
- Optionally calls C# daemon for Roslyn diagnostics on `.cs` files
- Serves the Vanilla JS frontend from `/frontend/`

### Java Microservice (Port 9090)
- Accepts Java source snippets via `POST /compile`
- Uses `javax.tools.JavaCompiler` (in-process javac) for compilation
- Returns structured diagnostics (errors, warnings, line numbers)
- Optionally executes compiled code with a configurable timeout

### C# Daemon (Port 9091)
- Accepts C# source snippets via `POST /analyze`
- Uses Microsoft Roslyn SDK to parse into a full syntax tree
- Returns Roslyn diagnostics, code metrics, and pattern-based findings
- Supports both HTTP mode (default) and Named Pipe mode (VS Code simulation)

## Data Flow — File Upload

```
1. Client uploads file via POST /api/v1/projects/<id>/upload/
2. Django validates file (size, extension)
3. Source code read as UTF-8 string
4. AES-256-GCM encrypt → store in CodeFile.encrypted_source
5. CodeAnalyzer.analyze() runs language-specific rules
6. Each finding → Vulnerability model created in DB
7. ExplanationGenerator.generate_shap() → Explanation model created
8. If language == java:  JavaServiceClient.compile_safe() called
9. If language == csharp: CSharpServiceClient.analyze_safe() called
10. CodeFile.mark_complete(risk_score, duration_ms)
11. Project.recalculate_risk_score()
12. Return CodeFileDetailSerializer response
```

## Security Architecture

### Encryption at Rest
All uploaded source code is stored encrypted using AES-256-GCM:
- 32-byte key loaded from `AES_SECRET_KEY` environment variable
- Fresh 16-byte random nonce per file — identical files produce different ciphertext
- 16-byte GCM authentication tag — tamper detection on read
- Wire format: `[nonce (16)] [tag (16)] [ciphertext (N)]`

### Transport Security
- CORS configured to allow only specified origins
- All inter-service communication is internal (Docker bridge network)
- No authentication between services (intended for local/containerised deployment)

## Database Schema

```
Project (1) ──────── (many) CodeFile
                               │
                       (many) Vulnerability (1) ── (1) Explanation
```

All PKs are UUIDs (not sequential integers) to avoid enumeration attacks.

## Adding a New Language

1. Create `backend/ml/rules/<language>_rules.py` with `ALL_RULES` list
2. Add the language to `SUPPORTED_LANGUAGES` in `settings.py`
3. Add the file extension to `FileUploadSerializer.ALLOWED_EXTENSIONS`
4. Add a tokenizer in `frontend/js/editor.js` → `Tokenizers` object
5. Add a `lang-tag.<language>` CSS class in `main.css`
