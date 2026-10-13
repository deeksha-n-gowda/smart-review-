import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
os.environ['DEBUG'] = 'False'
import django
django.setup()
from core.models import CodeFile, Project

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

# Try to decrypt
try:
    source = code_file.get_decrypted_source()
    print('Decrypted:', source)
except Exception as e:
    print('Error:', e)
    import traceback
    traceback.print_exc()