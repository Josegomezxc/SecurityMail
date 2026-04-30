"""
config/settings/testing.py
──────────────────────────────────────────────────────────────────────
Configuración para correr tests automatizados.

  - BD SQLite en memoria (rápida, no persistente)
  - Email backend en memoria (no envía correos reales)
  - Hashers de contraseña rápidos (no bcrypt)
  - Cache en memoria local
"""
from .base import *  # noqa: F401, F403


DEBUG = False

ALLOWED_HOSTS = ['*']

# BD en memoria — los tests crean/destruyen sin tocar disco
DATABASES = {
    'default': {
        'ENGINE':  'django.db.backends.sqlite3',
        'NAME':    ':memory:',
    }
}

# Hashers rápidos para que los tests no tarden en User.create_user()
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Email no se envía realmente — queda en outbox para asserts
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Cache en memoria local (no Redis)
CACHES = {
    'default': {
        'BACKEND':  'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'tests',
    }
}
