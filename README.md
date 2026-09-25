# Smart Review — AI-Powered Code Review Assistant

**Live demo:** **[https://smart-review-django.onrender.com](https://smart-review-django.onrender.com)** · Admin: [`/admin/`](https://smart-review-django.onrender.com/admin/) (see [Deployment](#deployment-render) for credentials)

A full-stack intelligent code review system built as a capstone project. It performs static analysis across four languages, explains every finding with illustrative SHAP/LIME-style attributions, encrypts all uploaded source code with AES-256-GCM, and is fully containerised with Docker.

---

## What It Does

- Accepts code file uploads via REST API or the web UI
- Runs a rule-based ML pipeline to detect vulnerabilities (SQL injection, XSS, hardcoded secrets, insecure patterns, and more)
- Generates SHAP/LIME-style explanations for every finding — not just "what" but "why". (Explanations are illustrative: they are computed from a built-in rule-weight model, not a trained ML model — see [`docs/architecture.md`](docs/architecture.md).)
- Encrypts source code at rest using AES-256-GCM before storing to the database
- Delegates Java compilation checks to a Java microservice (javax.tools) and merges its diagnostics into the findings
- Delegates C# syntax analysis to a .NET 8 daemon using Roslyn and merges its diagnostics into the findings
- Serves a Vanilla JS frontend with a code editor view and visual feedback panels

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Django 4.2, Django REST Framework |
| ML / XAI | Rule-based static analysis, illustrative SHAP / LIME attributions |
| Encryption | PyCryptodome — AES-256-GCM |
| Frontend | Vanilla JS (ES6+), HTML5, CSS3 — no frameworks |
| Java Service | Java 17, com.sun.net.httpserver (no framework), javax.tools JavaCompiler |
| C# Daemon | .NET 8, Roslyn SDK, HTTP + Named Pipe modes |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Containers | Docker 24+, Docker Compose v2 |

---

## Project Structure

```
smart-review/
├── backend/                    Django project root
│   ├── manage.py
│   ├── config/                 Settings, URLs, WSGI
│   ├── core/                   Models — Project, CodeFile, Vulnerability, Explanation
│   ├── api/                    REST API — views, serializers, URL routing
│   │   └── enrichment.py       Merges Java/C# service diagnostics into findings
│   ├── ml/                     ML pipeline
│   │   ├── analyzer.py         Static analysis engine
│   │   ├── explainer.py        Illustrative SHAP / LIME attribution generator
│   │   └── rules/              Per-language rule definitions
│   │       ├── python_rules.py
│   │       ├── java_rules.py
│   │       ├── csharp_rules.py
│   │       └── javascript_rules.py
│   ├── security/
│   │   └── encryption.py       AES-256-GCM helper
│   ├── static/                 Django static files (collectstatic target)
│   ├── tests/                  Pytest test suite
│   ├── conftest.py
│   └── pytest.ini
│
├── frontend/                   Vanilla JS frontend
│   ├── index.html              Upload and dashboard page
│   ├── review.html             Code editor + AI feedback panel
│   ├── css/
│   └── js/
│
├── java_service/               Java compiler microservice, port 9090 (pure Java 17 — no framework)
│   ├── pom.xml
│   └── src/
│
├── csharp_service/             .NET 8 analysis daemon (port 9091)
│   ├── CodeReviewDaemon.csproj
│   ├── Program.cs
│   ├── AnalysisEngine.cs
│   └── Models.cs
│
├── docker/
│   ├── Dockerfile              Django container
│   ├── Dockerfile.java         Java service container
│   ├── Dockerfile.csharp       C# daemon container
│   ├── docker-compose.yml      Orchestrates all four services
│   ├── entrypoint.sh           Runs migrations then starts gunicorn
│   └── postgres-init.sql
│
├── docs/
│   ├── architecture.md
│   └── api_reference.md
│
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Quick Start with Docker

### 1. Clone and configure environment

```bash
git clone https://github.com/deeksha-n-gowda/smart-review-.git
cd smart-review-
cp .env.example .env
```

Open `.env` and set at minimum:

```env
SECRET_KEY=your-long-random-django-secret-key
AES_SECRET_KEY=your-32-byte-base64-encoded-key==
```

Generate the AES key with:

```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

### 2. Build all images

```bash
docker-compose -f docker/docker-compose.yml build --no-cache
```

### 3. Start the stack

```bash
docker-compose -f docker/docker-compose.yml up
```

This starts four services:

| Service | Port | Description |
|---|---|---|
| django | 8000 | Django backend + frontend |
| java | 9090 | Java compilation microservice |
| csharp | 9091 | C# Roslyn analysis daemon |
| db | 5432 | PostgreSQL database |

### 4. Run migrations and seed data

Once the backend is listening on port 8000, open a second terminal:

```bash
docker-compose -f docker/docker-compose.yml exec django python manage.py migrate
docker-compose -f docker/docker-compose.yml exec django python manage.py seed_dev_data
```

### 5. Access the application

Local (Docker) endpoints:

- Web UI: `http://localhost:8000`
- API: `http://localhost:8000/api/v1/health/`
- Admin: `http://localhost:8000/admin/` (user: `admin`, password: `admin`)

Or use the hosted deployment: **<https://smart-review-django.onrender.com>**

---

## Local Development (without Docker)

### Prerequisites

- Python 3.11+
- Java 17+ (for the Java service)
- .NET 8 SDK (for the C# daemon)
- PostgreSQL or use the default SQLite

### Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r ../requirements.txt
cp ../.env.example ../.env   # Edit .env with your values
python manage.py migrate
python manage.py seed_dev_data
python manage.py runserver
```

---

## Deployment (Render)

The project deploys to [Render](https://render.com) free tier via the blueprint in [`render.yaml`](render.yaml).

**Live site:** **[https://smart-review-django.onrender.com](https://smart-review-django.onrender.com)**

The blueprint provisions four resources:

| Resource | Type | Notes |
|---|---|---|
| `smart-review-django` | Web service (Docker) | Django + frontend, runs migrations and seeds data on boot |
| `smart-review-java` | Web service (Docker) | Java 17 compiler microservice |
| `smart-review-csharp` | Web service (Docker) | .NET 8 Roslyn analysis daemon |
| `smart-review-db` | PostgreSQL 16 | Free instance (expires after 30 days — see below) |

### Redeploying

Push to `main` on GitHub — Render auto-syncs the blueprint on every push (webhook configured in repo settings). If a push ever doesn't trigger a deploy, run it manually in the Render dashboard: **smart-review-django → Manual Deploy → Deploy latest commit**.

### Secrets

Two environment variables are intentionally **not** stored in the repository (`sync: false` in `render.yaml`). Set them in the Render dashboard under **Blueprint → Env**:

- `AES_SECRET_KEY` — base64-encoded 32-byte key for AES-256-GCM encryption
- `DJANGO_SUPERUSER_PASSWORD` — admin password for the seeded `admin` user (email: `admin@example.com`)

### Free-tier caveats

- Services **sleep after ~15 minutes of idle time**; the first request takes 30–50 seconds to wake them up.
- The Java/C# enrichment step uses a 3-second timeout, so the very first analysis after a cold start may skip language-specific enrichment (the core ML analysis still runs — graceful by design).
- The free PostgreSQL instance **expires 30 days after creation**; upgrade or recreate it before then.
- 750 instance-hours/month are shared across all three web services.

---

## Running Tests

Inside the container:

```bash
docker-compose -f docker/docker-compose.yml exec django pytest
```

Or locally:

```bash
cd backend
pytest
```

The test suite covers the ML analyzer, explainer, enrichment mapping, AES encryption, and REST API endpoints.

---

## API Overview

Base URL: `https://smart-review-django.onrender.com/api/v1` (locally: `http://localhost:8000/api/v1`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health/` | Health check (`?services=1` also probes the Java/C# services) |
| GET | `/projects/` | List all projects |
| POST | `/projects/` | Create a project |
| GET | `/projects/{id}/` | Project detail |
| DELETE | `/projects/{id}/` | Delete project |
| POST | `/projects/{id}/upload/` | Upload file for analysis |
| GET | `/files/{id}/` | File detail with vulnerabilities |
| POST | `/files/{id}/analyze/` | Re-run analysis on a file |
| GET | `/files/{id}/source/` | Decrypt and return source |
| GET | `/vulnerabilities/{id}/` | Vulnerability detail |
| GET | `/vulnerabilities/{id}/explanation/` | SHAP/LIME-style explanation (illustrative) |

Full API documentation is in [`docs/api_reference.md`](docs/api_reference.md).

---

## Security Design

- **Encryption at rest** — all uploaded source code is encrypted with AES-256-GCM using a fresh random nonce per file before being stored in the database
- **UUID primary keys** — all models use UUID PKs to prevent enumeration attacks
- **Non-root containers** — all Docker containers run as a dedicated `appuser` (UID 1001)
- **Internal networking** — Java and C# services are only reachable within the Docker bridge network, never exposed directly

---

## Supported Languages

| Language | Extension | Rules Engine | External Service |
|---|---|---|---|
| Python | `.py` | `python_rules.py` | — |
| Java | `.java` | `java_rules.py` | Java service (port 9090) |
| C# | `.cs` | `csharp_rules.py` | C# daemon (port 9091) |
| JavaScript | `.js` | `javascript_rules.py` | — |

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full system diagram and data flow.

```
Browser
    │  HTTP :8000
    ▼
Django Backend
    ├── REST API  →  ML Analyzer  →  Enricher (javac / Roslyn)  →  Explainer (illustrative SHAP/LIME)
    ├── AES-256-GCM Encryption
    ├── PostgreSQL / SQLite
    ├── → Java Service  :9090  (javax.tools javac)
    └── → C# Daemon     :9091  (Roslyn SyntaxTree)
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Django secret key |
| `AES_SECRET_KEY` | Yes | 32-byte base64 key for AES encryption |
| `DEBUG` | No | `True` for development (default: `False`) |
| `DATABASE_URL` | No | PostgreSQL URL — omit to use SQLite |
| `ALLOWED_HOSTS` | No | Comma-separated hostnames |
| `JAVA_SERVICE_HOST` | No | Java service hostname (default: `localhost`; `java` in Docker) |
| `JAVA_SERVICE_PORT` | No | Java service port (default: `9090`) |
| `CSHARP_SERVICE_HOST` | No | C# daemon hostname (default: `localhost`; `csharp` in Docker) |
| `CSHARP_SERVICE_PORT` | No | C# daemon port (default: `9091`) |
| `MICROSERVICES_ENABLED` | No | `True` merges Java/C# service diagnostics into findings; `False` runs analysis fully locally (default: `True`) |
| `SEED_DEV_DATA` | No | Set `true` to auto-seed on container start |

See [`.env.example`](.env.example) for the full list.

---

## Capstone Project Info
**Repository:** https://github.com/deeksha-n-gowda/smart-review-.git
