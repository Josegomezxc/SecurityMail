"""
config/settings/production.py
──────────────────────────────────────────────────────────────────────
Configuración para entorno de producción.

Hardening de seguridad: cookies seguras, HSTS, redirect HTTPS, etc.
Usar con `DJANGO_SETTINGS_MODULE=config.settings.production`.
"""
from .base import *  # noqa: F401, F403


DEBUG = False

# En producción ALLOWED_HOSTS DEBE venir explícitamente en .env.
# Si no se define, Django bloquea todas las requests por seguridad.

# ═══════════════════════════════════════════════════════════════════
#  HARDENING HTTPS / COOKIES / HSTS
# ═══════════════════════════════════════════════════════════════════

# Forzar HTTPS — el reverse proxy (nginx/Cloudflare) debe tener cert SSL
SECURE_SSL_REDIRECT = True

# Cookies solo viajan por HTTPS
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE    = True

# HSTS: el navegador recuerda 1 año que este dominio es solo HTTPS.
# Solo activarlo si estás 100% seguro de que TODO el dominio será HTTPS.
SECURE_HSTS_SECONDS               = 60 * 60 * 24 * 365   # 1 año
SECURE_HSTS_INCLUDE_SUBDOMAINS    = True
SECURE_HSTS_PRELOAD               = True

# Otros headers de seguridad
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY      = 'same-origin'
X_FRAME_OPTIONS             = 'DENY'

# Sesiones más cortas en producción
SESSION_COOKIE_AGE = 60 * 60 * 8   # 8 horas
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
