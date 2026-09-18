# Smart Review — AI-Powered Code Review Assistant

A full-stack intelligent code review system built as a capstone project. It performs static analysis across four languages, explains every finding using SHAP/LIME, encrypts all uploaded source code with AES-256-GCM, and is fully containerised with Docker.

---

## What It Does

- Accepts code file uploads via REST API or the web UI
- Runs a rule-based ML pipeline to detect vulnerabilities (SQL injection, XSS, hardcoded secrets, insecure patterns, and more)
- Generates SHAP/LIME explanations for every finding — not just "what" but "why"
- Encrypts source code at rest using AES-256-GCM before storing to the database
- Delegates Java compilation checks to a Java microservice (javax.tools)
- Delegates C# syntax analysis to a .NET 8 daemon using Roslyn
- Serves a Vanilla JS frontend with a code editor view and visual feedback panels

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Django 4.2, Django REST Framework |
| ML / XAI | Rule-based static analysis, SHAP / LIME explanations |
| Encryption | PyCryptodome — AES-256-GCM |
| Frontend | Vanilla JS (ES6+), HTML5, CSS3 — no frameworks |
| Java Service | Java 17, Spring Boot, javax.tools JavaCompiler |
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
│   ├── ml/                     ML pipeline
│   │   ├── analyzer.py         Static analysis engine
│   │   ├── explainer.py        SHAP / LIME explanation generator
│   │   └── rules/              Per-language rule definitions
│   │       ├── python_rules.py
│   │       ├── java_rules.py
│   │       ├── csharp_rules.py
│   │       └── javascript_rules.py
│   ├── security/
│   │   └── encryption.py       AES-256-GCM helper
│   ├── templates/dashboard/    Django HTML templates
│   ├── static/                 CSS, JS, images
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
├── java_service/               Java Spring Boot microservice (port 9090)
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
cd smart-review
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
docker-compose -f docker/docker-compose.yml exec backend python manage.py migrate
docker-compose -f docker/docker-compose.yml exec backend python manage.py seed_dev_data
```

### 5. Access the application

- Web UI: http://localhost:8000
- API: http://localhost:8000/api/v1/health/
- Admin: http://localhost:8000/admin/ (user: `admin`, password: `admin`)

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

## Running Tests

Inside the container:

```bash
docker-compose -f docker/docker-compose.yml exec backend pytest
```

Or locally:

```bash
cd backend
pytest
```

The test suite covers the ML analyzer, SHAP explainer, AES encryption, and REST API endpoints.

---

## API Overview

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health/` | Health check |
| GET | `/projects/` | List all projects |
| POST | `/projects/` | Create a project |
| GET | `/projects/{id}/` | Project detail |
| DELETE | `/projects/{id}/` | Delete project |
| POST | `/projects/{id}/upload/` | Upload file for analysis |
| GET | `/files/{id}/` | File detail with vulnerabilities |
| POST | `/files/{id}/analyze/` | Re-run analysis on a file |
| GET | `/files/{id}/source/` | Decrypt and return source (debug only) |
| GET | `/vulnerabilities/{id}/` | Vulnerability detail |
| GET | `/vulnerabilities/{id}/explanation/` | SHAP/LIME explanation |

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
    ├── REST API  →  ML Analyzer  →  SHAP Explainer
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
| `JAVA_SERVICE_HOST` | No | Java service hostname (default: `java`) |
| `JAVA_SERVICE_PORT` | No | Java service port (default: `9090`) |
| `SEED_DEV_DATA` | No | Set `true` to auto-seed on container start |

See [`.env.example`](.env.example) for the full list.

---

## Capstone Project Info

**Institution:** Computer Science Department  
**Repository:** https://github.com/deeksha-n-gowda/smart-review-.git
