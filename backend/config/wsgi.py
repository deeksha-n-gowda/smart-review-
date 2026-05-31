"""
WSGI entry point for the AI Code Review Assistant Django application.
Used by production WSGI servers (gunicorn, uWSGI).

Run locally with gunicorn:
    gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_wsgi_application()
