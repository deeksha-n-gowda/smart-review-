# AI-Powered Code Review Assistant with Explainable AI
### Capstone Project — Computer Science Department

A full-stack intelligent code review system that uses ML-based static analysis with SHAP/LIME
explainability, AES-encrypted code handling, and a modular microservice architecture.

---

## Project Directory Structure

```
ai_code_review/
│
├── README.md                        ← You are here
├── requirements.txt                 ← Python dependencies (Django, cryptography, etc.)
├── .env.example                     ← Environment variable template
├── .gitignore
│
├── backend/                         ← Django project root
│   ├── manage.py
│   ├── config/                      ← Django project config package
│   │   ├── __init__.py
│   │   ├── settings.py              ← Main settings (dev + prod split)
│   │   ├── urls.py                  ← Root URL configuration
│   │   └── wsgi.py
│   │
│   ├── core/                        ← Core Django app (models, admin, migrations)
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py                ← Projects, CodeFiles, Vulnerabilities, Explanations
│   │   └── migrations/
│   │       └── __init__.py
│   │
│   ├── api/                         ← REST API app (views, serializers, URLs)
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── urls.py
│   │   ├── views.py                 ← Upload, review, results endpoints
│   │   ├── serializers.py
│   │   └── migrations/
│   │       └── __init__.py
│   │
│   ├── ml/                          ← ML pipeline (analysis + explainability)
│   │   ├── __init__.py
│   │   ├── analyzer.py              ← Static analysis engine (rule-based + mock ML)
│   │   ├── explainer.py             ← SHAP/LIME mock explanation generator
│   │   └── rules/                   ← Per-language rule definitions
│   │       ├── __init__.py
│   │       ├── python_rules.py
│   │       ├── java_rules.py
│   │       ├── csharp_rules.py
│   │       └── javascript_rules.py
│   │
│   ├── security/                    ← Encryption & security utilities
│   │   ├── __init__.py
│   │   └── encryption.py            ← AES-256-GCM encryption helper
│   │
│   ├── templates/                   ← Django HTML templates
│   │   └── dashboard/
│   │       ├── base.html
│   │       ├── index.html
│   │       └── review.html
│   │
│   └── static/                      ← Backend-served static files (fallback)
│       ├── css/
│       ├── js/
│       └── img/
│
├── frontend/                        ← Vanilla JS frontend (served by Django or standalone)
│   ├── index.html                   ← Upload & dashboard page
│   ├── review.html                  ← Code review editor + AI feedback panel
│   ├── css/
│   │   ├── main.css                 ← Global styles, CSS variables, layout
│   │   ├── editor.css               ← Code editor view, line highlights
│   │   └── panels.css               ← Feedback panels, SHAP charts, vulnerability cards
│   ├── js/
│   │   ├── api.js                   ← Fetch wrappers for backend API calls
│   │   ├── editor.js                ← Code editor rendering + line annotation
│   │   ├── shap_chart.js            ← SHAP bar chart visualizer (Canvas API)
│   │   └── review.js                ← Main review page controller
│   └── assets/
│       └── logo.svg
│
├── java_service/                    ← Lightweight Java microservice
│   ├── pom.xml                      ← Maven build config
│   └── src/main/
│       ├── java/com/codereview/
│       │   ├── CompilerService.java  ← Socket server: compiles/tests Java snippets
│       │   └── ReviewRequest.java    ← Request model POJO
│       └── resources/
│           └── application.properties
│
├── csharp_service/                  ← C# .NET console utility
│   ├── CodeReviewDaemon.csproj
│   ├── Program.cs                   ← Entry point, listens on named pipe / HTTP
│   ├── AnalysisEngine.cs            ← Roslyn-based C# syntax analysis
│   └── Models.cs                    ← Request/response models
│
├── docker/                          ← Container configuration
│   ├── Dockerfile                   ← Django app container
│   ├── Dockerfile.java              ← Java service container
│   └── docker-compose.yml           ← Orchestrates all services
│
└── docs/                            ← Project documentation
    ├── architecture.md
    ├── api_reference.md
    └── explainability_notes.md
```

---

## Tech Stack

| Layer         | Technology                                      |
|---------------|-------------------------------------------------|
| Backend       | Python 3.11, Django 4.2, Django REST Framework  |
| ML/XAI        | scikit-learn (mock), SHAP, LIME concepts        |
| Encryption    | PyCryptodome — AES-256-GCM                      |
| Frontend      | Vanilla JS (ES6+), HTML5, CSS3 (no frameworks)  |
| Java Service  | Java 17, plain socket server (no Spring Boot)   |
| C# Service    | .NET 8, Roslyn SDK, named pipe IPC              |
| Database      | SQLite (dev) / PostgreSQL (prod via env var)    |
| Containers    | Docker 24+, Docker Compose v2                  |

---

## Phases

- **Phase 1** — Django backend config, database models, encryption helper ✅
- **Phase 2** — Frontend UI, code editor view, feedback panels
- **Phase 3** — ML pipeline (analyzer + SHAP/LIME explainer)
- **Phase 4** — REST API endpoints + serializers
- **Phase 5** — Java microservice + C# utility
- **Phase 6** — Docker + docker-compose deployment
