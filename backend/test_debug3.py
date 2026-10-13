import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
os.environ['DEBUG'] = 'False'
import django
django.setup()
from django.test import Client
from core.models import CodeFile, Project

client = Client()

# Create a test project and file
project = Project.objects.create(name='Test', description='Test')
code_file = CodeFile.objects.create(
    project=project,
    filename='test.py',
    language='python',
    status='complete',
)
code_file.set_source('print("hello")')
code_file.save()

# Test the source endpoint
response = client.get(f'/api/v1/files/{code_file.id}/source/')
print('Status:', response.status_code)
print('Response:', response.content)

# Also test analyze endpoint
response = client.post(f'/api/v1/files/{code_file.id}/analyze/')
print('Analyze Status:', response.status_code)
print('Analyze Response:', response.content)