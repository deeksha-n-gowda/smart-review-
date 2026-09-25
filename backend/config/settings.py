"""
Django Settings — AI Code Review Assistant
==========================================
This configuration handles both development (SQLite, DEBUG=True) and production
(PostgreSQL, DEBUG=False) environments via environment variables loaded from .env.

To run in development:
    1. Copy .env.example to .env and fill in values
    2. Run: python manage.py runserver

Author: Capstone Project Team
"""

import os
import base64
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Base directory — this is /backend/
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from the project root's .env file
# (one level up from /backend/)
load_dotenv(BASE_DIR.parent / ".env")


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    # Fallback dev key — NEVER use this in production
    "django-insecure-dev-key-replace-this-in-production-env"
)

DEBUG = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

ALLOWED_HOSTS_ENV = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1")
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS_ENV.split(",") if h.strip()]

# On Render the public hostname is injected at runtime — add it automatically
# so API calls and admin logins work without per-service env edits.
RENDER_EXTERNAL_HOSTNAME = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# Django runs behind Render's HTTPS-terminating proxy. Trust X-Forwarded-Proto
# so request.is_secure() and CSRF's HTTPS referer checks behave correctly.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# CSRF requires the full origin (scheme + host) for POSTs such as admin login.
CSRF_TRUSTED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
]
if RENDER_EXTERNAL_HOSTNAME:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RENDER_EXTERNAL_HOSTNAME}")
    # Only mark cookies Secure when actually served over the HTTPS domain.
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True


# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    # Django built-ins
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party
    "rest_framework",         # Django REST Framework for the API
    "corsheaders",            # CORS handling for frontend fetch calls

    # Our apps
    "core",                   # Models: Project, CodeFile, Vulnerability, Explanation
    "api",                    # REST API views and serializers
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",        # Must be before CommonMiddleware
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",   # Serve collectstatic output (prod)
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],   # /backend/templates/
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Default: SQLite for quick development startup.
# Set DATABASE_URL in .env to switch to PostgreSQL for production:
#   DATABASE_URL=postgresql://user:pass@host:5432/dbname

_DATABASE_URL = os.environ.get("DATABASE_URL", "")

if _DATABASE_URL.startswith("postgresql://") or _DATABASE_URL.startswith("postgres://"):
    # Parse PostgreSQL URL manually (avoids needing dj-database-url)
    import urllib.parse as _up
    _parsed = _up.urlparse(_DATABASE_URL)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _parsed.path.lstrip("/"),
            "USER": _parsed.username,
            "PASSWORD": _parsed.password,
            "HOST": _parsed.hostname,
            "PORT": _parsed.port or 5432,
        }
    }
else:
    # Development default: SQLite stored in /backend/
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# ---------------------------------------------------------------------------
# Password Validation
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ---------------------------------------------------------------------------
# Static & Media Files
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]  # Dev static files in /backend/static/
# collectstatic output for production. The Docker image overrides this via
# env var (the container layout lacks the local backend/ sub-directory).
STATIC_ROOT = Path(
    os.environ.get("STATIC_ROOT", str(BASE_DIR.parent / "staticfiles"))
)

MEDIA_URL = "/media/"
# Uploaded files. Overridable the same way (see Dockerfile ENV MEDIA_ROOT).
MEDIA_ROOT = Path(
    os.environ.get("MEDIA_ROOT", str(BASE_DIR.parent / "mediafiles"))
)

# WhiteNoise serves STATIC_ROOT in production — this deployment has no nginx.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}


# ---------------------------------------------------------------------------
# Default primary key type
# ---------------------------------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    # Use session auth for the browsable API in dev; token auth is wired up
    # via the API key header for programmatic access.
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        # Open for development — tighten in production
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",  # Handy during dev
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min",   # 60 requests per minute for anonymous users
    },
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
}


# ---------------------------------------------------------------------------
# CORS Configuration (django-cors-headers)
# ---------------------------------------------------------------------------
_cors_env = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500")
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]

# During development, allow all origins if DEBUG is True
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOW_CREDENTIALS = True


# ---------------------------------------------------------------------------
# AES Encryption Settings
# ---------------------------------------------------------------------------
# The AES key used to encrypt code snippets before storage.
# Must be a base64-encoded 32-byte (256-bit) key.
# Generate: python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
_aes_key_b64 = os.environ.get("AES_SECRET_KEY", "")

if _aes_key_b64:
    try:
        AES_SECRET_KEY_BYTES = base64.b64decode(_aes_key_b64)
        if len(AES_SECRET_KEY_BYTES) != 32:
            raise ValueError("AES key must be exactly 32 bytes after base64 decode.")
    except Exception as e:
        raise RuntimeError(f"Invalid AES_SECRET_KEY in .env: {e}")
else:
    # Development fallback — generates a random key each restart.
    # This means stored encrypted snippets won't survive a server restart in dev.
    import os as _os
    AES_SECRET_KEY_BYTES = _os.urandom(32)
    if not DEBUG:
        raise RuntimeError(
            "AES_SECRET_KEY must be set in .env for production! "
            "See .env.example for instructions."
        )


# ---------------------------------------------------------------------------
# External Microservice Endpoints
# ---------------------------------------------------------------------------
def _service_base_url(host: str, port: int) -> str:
    """Build a microservice base URL.

    - Full URLs (http://… / https://…) pass through unchanged.
    - On Render, free services can only reach each other over the public
      onrender.com HTTPS domain (no private networking on the free plan),
      so a bare hostname becomes https://<host> (port 443).
    - Locally and in Docker Compose: http://host:port as before.
    """
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    if RENDER_EXTERNAL_HOSTNAME:  # running on Render
        return f"https://{host.rstrip('/')}"
    return f"http://{host}:{port}"


JAVA_SERVICE_HOST = os.environ.get("JAVA_SERVICE_HOST", "localhost")
JAVA_SERVICE_PORT = int(os.environ.get("JAVA_SERVICE_PORT", "9090"))
JAVA_SERVICE_URL = os.environ.get("JAVA_SERVICE_URL") or _service_base_url(
    JAVA_SERVICE_HOST, JAVA_SERVICE_PORT
)

CSHARP_PIPE_NAME = os.environ.get("CSHARP_PIPE_NAME", "CodeReviewDaemonPipe")

# HTTP mode for the C# analysis daemon (used by api/microservice_client.py).
# In Docker Compose the daemon runs as service "csharp" on the compose network.
CSHARP_SERVICE_HOST = os.environ.get("CSHARP_SERVICE_HOST", "localhost")
CSHARP_SERVICE_PORT = int(os.environ.get("CSHARP_SERVICE_PORT", "9091"))
CSHARP_SERVICE_URL = os.environ.get("CSHARP_SERVICE_URL") or _service_base_url(
    CSHARP_SERVICE_HOST, CSHARP_SERVICE_PORT
)

# Master switch for calling the Java / C# microservices during analysis.
# When False the backend runs purely on the local Python rule engine —
# no network calls are made. Set to "False" in tests (see conftest.py) and
# for local runs without the Java/C# services up.
MICROSERVICES_ENABLED = os.environ.get("MICROSERVICES_ENABLED", "True").lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Code Analysis Settings
# ---------------------------------------------------------------------------
# Maximum file size (in bytes) allowed for upload and analysis
MAX_CODE_FILE_SIZE_BYTES = 1024 * 1024  # 1 MB

# Supported languages and their file extensions
SUPPORTED_LANGUAGES = {
    "python":     [".py"],
    "java":       [".java"],
    "csharp":     [".cs"],
    "javascript": [".js", ".mjs"],
}

# Severity levels used across the system
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name} — {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG" if DEBUG else "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "core": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "api": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "ml": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
    },
}
