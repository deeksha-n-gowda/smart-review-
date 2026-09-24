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
- Merges Java/C# service diagnostics into the findings (`api/enrichment.py`)
- Generates SHAP/LIME-style explanations (`ml/explainer.py`)
- Calls Java service for `.java` compile-time checks (when `MICROSERVICES_ENABLED=True`)
- Calls C# daemon for Roslyn diagnostics on `.cs` files (when `MICROSERVICES_ENABLED=True`)
- Serves the Vanilla JS frontend from `/frontend/`

### Explainability Note (SHAP / LIME)

The "SHAP" and "LIME" explanations produced by `ml/explainer.py` are
**illustrative attributions, not a trained model**. There is no training
data, no fitted estimator, and no `shap`/`lime` library dependency:

- **SHAP-style values** are computed as `feature_base_weight × feature_presence`
  from a hand-tuned weight table (`FEATURE_BASE_WEIGHTS`) plus deterministic,
  seeded noise — the same feature-detection regexes that drive the rule
  engine determine which features are "present".
- **LIME-style values** are the SHAP-style values with small deterministic
  jitter, simulating LIME's local-linear approximation.
- Both are generated on the fly at analysis time and persisted on the
  `Explanation` model; the UI charts them identically to real attributions.

This keeps the XAI pipeline dependency-free and reproducible while
demonstrating how attribution output is surfaced in a review UI.

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
6. If MICROSERVICES_ENABLED and language == java/csharp:
   api/enrichment.py calls the service, maps its diagnostics to
   findings, merges (local findings win on duplicates), re-sorts,
   and recomputes the risk score
7. Each finding (local + merged) → Vulnerability model created in DB
8. ExplanationGenerator.generate_shap() / generate_lime() → Explanation model created
9. CodeFile.mark_complete(risk_score, duration_ms)
10. Project.recalculate_risk_score()
11. Return CodeFileDetailSerializer response
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
