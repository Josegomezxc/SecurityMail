"""
config/settings/development.py
──────────────────────────────────────────────────────────────────────
Configuración para entorno de desarrollo local.
"""
from .base import *  # noqa: F401, F403


DEBUG = True

# En desarrollo aceptamos localhost + 127.0.0.1 + lo que venga en .env
# (típicamente el subdominio temporal de ngrok).
import os
_extra_hosts = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()]
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', *_extra_hosts]

# Helpers de debug (Django Debug Toolbar opcional, no obligatorio)
INTERNAL_IPS = ['127.0.0.1', 'localhost']
