
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zacoo.settings')

app = Celery('zacoo')

# Use the 'spawn' start method for Windows
app.conf.update(
    worker_pool = 'solo',  # This can be used if 'spawn' is problematic, for some use cases
)

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

