"""
config/settings/development.py
──────────────────────────────────────────────────────────────────────
Configuración para entorno de desarrollo local.
"""
from .base import *  


DEBUG = True


import os
_extra_hosts = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()]
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', 'app.dockershield.lat', 'testserver', *_extra_hosts]

INTERNAL_IPS = ['127.0.0.1', 'localhost']


TEMPLATES[0]['OPTIONS']['loaders'] = [
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
]
