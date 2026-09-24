"""
conftest.py — Shared Pytest Fixtures
======================================
Placed in /backend/ so it is auto-loaded by pytest for all test modules.

Provides:
  - Django settings overrides for testing (in-memory SQLite, fast password hasher)
  - Shared factory fixtures for common model objects
  - The @pytest.mark.django_db marker is applied via django_db_setup

Run all tests:
    cd backend
    pytest

Run with coverage:
    pytest --cov=. --cov-report=term-missing --cov-report=html
"""

import os
import pytest

# Make sure Django settings are configured before any import
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")


# ---------------------------------------------------------------------------
# Django settings overrides for testing
# ---------------------------------------------------------------------------

# These are applied before Django is set up, ensuring the test database
# uses fast in-memory SQLite and skips unnecessary middleware.
from django.conf import settings as django_settings


def pytest_configure(config):
    """
    Override Django settings for the test run.
    Called by pytest before any tests are collected.
    """
    # Use a fast in-memory SQLite DB for tests — no file I/O, auto-wiped
    django_settings.DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    }

    # Use a fixed AES key for tests — predictable, no .env required
    import base64
    django_settings.AES_SECRET_KEY_BYTES = base64.b64decode(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )[:32]
    # Pad to 32 bytes just in case
    if len(django_settings.AES_SECRET_KEY_BYTES) < 32:
        django_settings.AES_SECRET_KEY_BYTES = django_settings.AES_SECRET_KEY_BYTES.ljust(32, b'\x00')

    # Use Django's fast (unsalted MD5) password hasher in tests — not for real passwords,
    # just to speed up any User creation in tests
    django_settings.PASSWORD_HASHERS = [
        "django.contrib.auth.hashers.MD5PasswordHasher",
    ]

    # Disable Django's rate limiting in tests
    django_settings.REST_FRAMEWORK = {
        **django_settings.REST_FRAMEWORK,
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES": {},
    }

    # Silence migration output during test DB creation
    django_settings.MIGRATION_MODULES = {}

    # Never call the Java/C# microservices from tests — analysis must be
    # fully local and deterministic (see api/enrichment.py).
    django_settings.MICROSERVICES_ENABLED = False


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_python_source():
    """A Python source snippet with known vulnerabilities for testing."""
    return '''
import sqlite3
import hashlib
import os

def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        # Weak hash
        hashed = hashlib.md5(password.encode()).hexdigest()
        return user[2] == hashed
    return None

def run_command(user_input):
    # Command injection
    os.system("echo " + user_input)

class UserSession:
    def login(self, username, password):
        user = login(username, password)
        if user:
            # Predictable token
            self.token = hashlib.md5(username.encode()).hexdigest()
            return True
        return False
'''


@pytest.fixture
def sample_javascript_source():
    """A JavaScript source snippet with known vulnerabilities."""
    return '''
async function loadProfile(userId) {
    const response = await fetch(`/api/users/${userId}`);
    const data = await response.json();
    document.getElementById("bio").innerHTML = data.bio;
    localStorage.setItem("authToken", data.token);
}

function applyFilter(filterCode) {
    return eval(filterCode);
}

const API_KEY = "sk-prod-abc123xyz789defghijklm";
'''


@pytest.fixture
def clean_python_source():
    """A clean Python source snippet with no vulnerabilities."""
    return '''
from typing import Optional
import hashlib
import secrets
import logging

logger = logging.getLogger(__name__)


def get_user(conn, user_id: int) -> Optional[dict]:
    """Retrieve a user safely using parameterized queries."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (secure)."""
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def generate_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_hex(32)
'''
