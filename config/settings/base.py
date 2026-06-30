"""
config/settings/base.py
──────────────────────────────────────────────────────────────────────
Configuración común a TODOS los entornos. Las variantes específicas
(development/production/testing) heredan de este archivo y solo
sobrescriben lo que cambia en su entorno.
"""
import os
from pathlib import Path

# BASE_DIR ahora apunta a la raíz del proyecto (un nivel ARRIBA de config/)
BASE_DIR = Path(__file__).resolve().parent.parent.parent


# ─── Carga de .env (sin dependencias externas) ─────────────────────────
# Lee BASE_DIR/.env y pone cada línea KEY=VALUE en os.environ si no está ya.
def _load_dotenv():
    env_path = BASE_DIR / '.env'
    if not env_path.exists():
        return
    try:
        for line in env_path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
    except Exception:
        pass  # No bloqueamos el arranque si el .env está malformado


_load_dotenv()


# SECRET_KEY es OBLIGATORIA — debe estar definida en .env.
# Si no existe Django lanzará ImproperlyConfigured al arrancar.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise Exception(
        "SECRET_KEY no encontrada. Añádela al archivo .env en la raíz del proyecto."
    )

# DEBUG se define en cada environment (development/production)
DEBUG = False

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    if h.strip()
]

# CSRF: orígenes confiables para POST (formularios) detrás de un reverse
# proxy con HTTPS (ngrok / dominio en producción). Si falta el origen
# del navegador, Django responde 403 Forbidden a cualquier POST.
# Para cada host con punto al inicio (.ngrok-free.dev), agregamos su variante
# con esquema https://*.dominio que es la sintaxis exacta que Django acepta.
CSRF_TRUSTED_ORIGINS = []
for h in ALLOWED_HOSTS:
    if h in ('localhost', '127.0.0.1'):
        CSRF_TRUSTED_ORIGINS += [f'http://{h}:8000', f'http://{h}']
    elif h.startswith('.'):
        # subdominio wildcard (ej: .ngrok-free.dev → https://*.ngrok-free.dev)
        CSRF_TRUSTED_ORIGINS.append(f'https://*{h}')
    else:
        CSRF_TRUSTED_ORIGINS += [f'https://{h}', f'http://{h}']

# Detrás de ngrok / Nginx / Cloudflare, Django ve el request como HTTP
# pero el cliente lo envió por HTTPS. Esto le dice a Django que confíe
# en el header X-Forwarded-Proto que el proxy nos pone para detectar HTTPS.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Vista personalizada para errores CSRF (token inválido/expirado).
CSRF_FAILURE_VIEW = 'apps.core.views.csrf_failure_view'

# Dominio que se usa para generar las direcciones de los alias.
# Tiene que coincidir con el dominio verificado en Resend.
MAIL_DOMAIN = os.environ.get('MAIL_DOMAIN', 'dockershield.lat').strip()

# ─── CONFIGURACIÓN GLOBAL DE CORREO DE DJANGO ───────────────────────
# Remitente por defecto para Auth, formularios nativos y apps de terceros
DEFAULT_FROM_EMAIL = f'DockerShield <noreply@{MAIL_DOMAIN}>'

# Remitente de las alertas del sistema (errores 500) enviadas a los ADMINS
SERVER_EMAIL = f'root@{MAIL_DOMAIN}'

# ═══════════════════════════════════════════════════════════════════
#  APPS
# ═══════════════════════════════════════════════════════════════════

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Apps del proyecto (modular monolith)
    'apps.core',
    'apps.accounts',
    'apps.aliases',
    'apps.mail',
    'apps.sandbox',
    'apps.notifications',
]


# ═══════════════════════════════════════════════════════════════════
#  SESIONES — sesión dura 1 año sin importar inactividad; solo se
#  cierra con logout manual.
# ═══════════════════════════════════════════════════════════════════

SESSION_COOKIE_AGE = 60 * 60 * 24 * 365   # 1 año
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# ═══════════════════════════════════════════════════════════════════
#  MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # Una sesión por usuario: si alguien hace login en otro navegador,
    # la sesión anterior queda inválida y se desloguea en su próximo request.
    'apps.core.middleware.SingleSessionMiddleware',
    # Evita que el navegador conserve páginas autenticadas en caché — al
    # presionar "atrás" tras logout/eliminar cuenta NO se muestra la página
    # vieja, sino que se redirige a /login/.
    'apps.core.middleware.NoCacheAuthMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# ═══════════════════════════════════════════════════════════════════
#  URLS / WSGI / ASGI
# ═══════════════════════════════════════════════════════════════════

ROOT_URLCONF       = 'config.urls'
WSGI_APPLICATION   = 'config.wsgi.application'
ASGI_APPLICATION   = 'config.asgi.application'


# ═══════════════════════════════════════════════════════════════════
#  TEMPLATES
# ═══════════════════════════════════════════════════════════════════

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # Templates globales viven en la raíz del proyecto (templates/)
        'DIRS': [BASE_DIR / 'templates'],
        'OPTIONS': {
            'loaders': [
                ('django.template.loaders.cached.Loader', [
                    'django.template.loaders.filesystem.Loader',
                    'django.template.loaders.app_directories.Loader',
                ]),
            ],
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.core.context_processors.sidebar_counts',
            ],
        },
    },
]


# ═══════════════════════════════════════════════════════════════════
#  BASE DE DATOS (PostgreSQL)
# ═══════════════════════════════════════════════════════════════════

DATABASES = {
    'default': {
        'ENGINE':   'django.db.backends.postgresql',
        'NAME':     os.environ.get('DB_NAME',     'db_email_seguro'),
        'USER':     os.environ.get('DB_USER',     'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST':     os.environ.get('DB_HOST',     'localhost'),
        'PORT':     os.environ.get('DB_PORT',     '5432'),
        # Conexiones persistentes: evita abrir/cerrar TCP en cada request
        'CONN_MAX_AGE': int(os.environ.get('CONN_MAX_AGE', 600)),
    }
}


# ═══════════════════════════════════════════════════════════════════
#  CACHÉ
# ═══════════════════════════════════════════════════════════════════

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-default-cache',
    }
}

# Sesiones en DB (comportamiento por defecto de Django)


# ═══════════════════════════════════════════════════════════════════
#  AUTH / VALIDADORES
# ═══════════════════════════════════════════════════════════════════

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ═══════════════════════════════════════════════════════════════════
#  I18N / TZ
# ═══════════════════════════════════════════════════════════════════

LANGUAGE_CODE = 'es'
TIME_ZONE = 'America/Guayaquil'
USE_I18N = True
USE_TZ = True


# ═══════════════════════════════════════════════════════════════════
#  STATIC / MEDIA
# ═══════════════════════════════════════════════════════════════════

STATIC_URL = '/static/'
# La carpeta 'static/' de la raíz del proyecto contiene archivos
# estáticos globales (logos, etc.).
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []

# Archivos subidos por usuarios (avatares, adjuntos analizados)
MEDIA_URL  = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# URL pública del sitio (para construir links en correos)
SITE_URL = os.environ.get('SITE_URL', 'http://127.0.0.1:8000').rstrip('/')
