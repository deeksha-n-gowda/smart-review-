"""
core/apps.py — Django AppConfig for the core application.

The 'core' app owns the main data models:
    - Project
    - CodeFile
    - Vulnerability
    - Explanation
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    verbose_name = "Code Review Core"
