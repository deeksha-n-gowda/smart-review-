# Generated migration for core models
# Run: python manage.py migrate

import uuid
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        # ------------------------------------------------------------------
        # Project
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="Project",
            fields=[
                ("id",                 models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name",               models.CharField(help_text="Human-readable project name.", max_length=255)),
                ("description",        models.TextField(blank=True, default="")),
                ("created_at",         models.DateTimeField(auto_now_add=True)),
                ("updated_at",         models.DateTimeField(auto_now=True)),
                ("overall_risk_score", models.FloatField(blank=True, null=True)),
            ],
            options={"ordering": ["-created_at"], "verbose_name": "Project", "verbose_name_plural": "Projects"},
        ),

        # ------------------------------------------------------------------
        # CodeFile
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="CodeFile",
            fields=[
                ("id",                   models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("project",              models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="code_files", to="core.project")),
                ("filename",             models.CharField(max_length=512)),
                ("language",             models.CharField(choices=[("python","Python"),("java","Java"),("csharp","C#"),("javascript","JavaScript")], max_length=20)),
                ("status",               models.CharField(choices=[("pending","Pending"),("analyzing","Analyzing"),("complete","Complete"),("failed","Failed")], default="pending", max_length=20)),
                ("encrypted_source",     models.BinaryField()),
                ("line_count",           models.PositiveIntegerField(blank=True, null=True)),
                ("size_bytes",           models.PositiveIntegerField(blank=True, null=True)),
                ("risk_score",           models.FloatField(blank=True, null=True)),
                ("analysis_duration_ms", models.PositiveIntegerField(blank=True, null=True)),
                ("error_message",        models.TextField(blank=True, default="")),
                ("uploaded_at",          models.DateTimeField(auto_now_add=True)),
                ("analyzed_at",          models.DateTimeField(blank=True, null=True)),
            ],
            options={"ordering": ["uploaded_at"], "verbose_name": "Code File", "verbose_name_plural": "Code Files"},
        ),

        # ------------------------------------------------------------------
        # Vulnerability
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="Vulnerability",
            fields=[
                ("id",               models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code_file",        models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="vulnerabilities", to="core.codefile")),
                ("line_start",       models.PositiveIntegerField()),
                ("line_end",         models.PositiveIntegerField(blank=True, null=True)),
                ("title",            models.CharField(max_length=255)),
                ("description",      models.TextField()),
                ("category",         models.CharField(choices=[("security","Security"),("performance","Performance"),("maintainability","Maintainability"),("style","Style / Convention"),("correctness","Correctness / Logic"),("complexity","Complexity")], default="security", max_length=30)),
                ("severity",         models.CharField(choices=[("critical","Critical"),("high","High"),("medium","Medium"),("low","Low"),("info","Info")], default="medium", max_length=10)),
                ("confidence_score", models.FloatField(default=1.0)),
                ("rule_id",          models.CharField(blank=True, default="", max_length=100)),
                ("recommendation",   models.TextField(blank=True, default="")),
                ("code_snippet",     models.TextField(blank=True, default="")),
                ("fixed_snippet",    models.TextField(blank=True, default="")),
                ("cwe_id",           models.CharField(blank=True, default="", max_length=20)),
                ("owasp_category",   models.CharField(blank=True, default="", max_length=100)),
                ("created_at",       models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-severity", "line_start"], "verbose_name": "Vulnerability", "verbose_name_plural": "Vulnerabilities"},
        ),

        # ------------------------------------------------------------------
        # Explanation
        # ------------------------------------------------------------------
        migrations.CreateModel(
            name="Explanation",
            fields=[
                ("id",                    models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("vulnerability",         models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="explanation", to="core.vulnerability")),
                ("method",                models.CharField(choices=[("shap","SHAP (SHapley Additive exPlanations)"),("lime","LIME (Local Interpretable Model-Agnostic Explanations)"),("rule","Rule-Based (Deterministic)")], default="shap", max_length=10)),
                ("explanation_data",      models.JSONField()),
                ("summary",               models.TextField(blank=True, default="")),
                ("top_feature_name",      models.CharField(blank=True, default="", max_length=200)),
                ("top_feature_importance",models.FloatField(blank=True, null=True)),
                ("generated_at",          models.DateTimeField(auto_now_add=True)),
            ],
            options={"verbose_name": "Explanation", "verbose_name_plural": "Explanations"},
        ),
    ]
