"""
Django Settings — AI Code Review Assistant
=================================================================
This configuration handles both development (SQLite, DEBUG=True) and
production (PostgreSQL, DEBUG=False) environments via environment
variables loaded from .env.

To run in development:
    1. Copy .env.example to .env and fill in values
    2. Run: python manage.py runserver

Author: Smart Review Team
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
    "django-insecure-change-this-in-production"
)

DEBUG = os.environ.get("DEBUG", "True").lower() in ("true", "1", "yes")

ALLOWED_HOSTS_ENV = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1")
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS_ENV.split(",") if h.strip()]

# On Render the public hostname is injected at runtime — add it automatically
# so API calls and admin logins work without per-service env edits.
RENDER_EXTERNAL_HOSTNAME = os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# Always include testserver for Django test client compatibility
if "testserver" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("testserver")

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


# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    "rest_framework",
    "corsheaders",

    "core",
    "api",
    "ml",
    "security",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
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
        "DIRS": [BASE_DIR / "templates"],
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
_DATABASE_URL = os.environ.get("DATABASE_URL", "")

if _DATABASE_URL.startswith("postgresql://") or _DATABASE_URL.startswith("postgres://"):
    import urllib.parse as _up
    _parsed = _up.urlparse(_DATABASE_URL)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _parsed.path.lstrip("/"),
            "USER": _parsed.username,
            "PASSWORD": _parsed.password,
            "HOST": _parsed.hostname,
            "PORT": _parsed.port,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributePasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files (CSS, JavaScript, Images)
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"


# ---------------------------------------------------------------------------
# Default primary key field type
# ---------------------------------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# File upload limits
# ---------------------------------------------------------------------------
# Maximum size of uploaded code files (1 MB by default)
MAX_CODE_FILE_SIZE_BYTES = int(os.environ.get("MAX_CODE_FILE_SIZE_BYTES", 1_048_576))


# ---------------------------------------------------------------------------
# AES Encryption key
# ---------------------------------------------------------------------------
# AES encryption key (32 bytes for AES-256) — loaded from env as base64
AES_SECRET_KEY = os.environ.get("AES_SECRET_KEY", "gV9r02DLBMHdCLyfZNeRqKc7sAMA5hmkkdKYKqCy8R8=")
AES_SECRET_KEY_BYTES = base64.b64decode(AES_SECRET_KEY)


# ---------------------------------------------------------------------------
# Django REST Framework Configuration
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.AllowAny",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "50/minute",
        "user": "100/minute",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Smart Review API",
    "VERSION": "2.0.0",
    "DESCRIPTION": "AI-Powered Code Review Assistant — enterprise-grade code analysis",
    "SECRET_KEY": os.environ.get("SECRET_KEY"),
    "SERVE_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "SWAGGER_UI_URL": "/api/docs/",
    "REDOC_URL": "/api/redoc/",
}


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{levelname}] {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "[{levelname}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": True,
        },
        "api": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "ml": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}