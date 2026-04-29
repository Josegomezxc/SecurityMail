import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


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

DEBUG = os.environ.get('DEBUG', 'True').lower() in ('1', 'true', 'yes')

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

# Dominio que se usa para generar las direcciones de los alias.
# Tiene que coincidir con el dominio cuyo MX apunta al Inbound Parse de SendGrid.
MAIL_DOMAIN = os.environ.get('MAIL_DOMAIN', 'dockershield.lat').strip()

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # Una sesión por usuario: si alguien hace login en otro navegador,
    # la sesión anterior queda inválida y se desloguea en su próximo request.
    'app.middleware.SingleSessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'email_seguro.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'app.context_processors.sidebar_counts',
            ],
        },
    },
]

WSGI_APPLICATION = 'email_seguro.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE':   'django.db.backends.postgresql',
        'NAME':     os.environ.get('DB_NAME',     'db_email_seguro'),
        'USER':     os.environ.get('DB_USER',     'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST':     os.environ.get('DB_HOST',     'localhost'),
        'PORT':     os.environ.get('DB_PORT',     '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'es'
TIME_ZONE = 'America/Guayaquil'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'

# ─── Archivos subidos (adjuntos de correos) ────────────────────────────
MEDIA_URL  = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ─── Envío de correos (Gmail SMTP) ─────────────────────────────────────
#
# Para que Gmail acepte el envío necesitas una "Contraseña de aplicación"
# (NO tu contraseña normal de Gmail):
#   1. Ve a  https://myaccount.google.com/security
#   2. Activa la verificación en 2 pasos (si no la tienes).
#   3. Entra en "Contraseñas de aplicaciones" y crea una para "Correo".
#   4. Copia la contraseña de 16 caracteres y ponla en .env como
#      EMAIL_HOST_PASSWORD (sin espacios).
#
# Si EMAIL_HOST_USER o EMAIL_HOST_PASSWORD están vacíos, Django usará
# el backend de consola: los correos se imprimen en el terminal (útil
# para desarrollo sin tener que configurar Gmail).
#
EMAIL_HOST          = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT          = int(os.environ.get('EMAIL_PORT', '587'))
EMAIL_USE_TLS       = os.environ.get('EMAIL_USE_TLS', 'True').lower() in ('1', 'true', 'yes')
EMAIL_HOST_USER     = os.environ.get('EMAIL_HOST_USER', '').strip()
# Google muestra la contraseña de aplicación con espacios por legibilidad.
# Los eliminamos para que da igual si el usuario los copia o no.
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '').replace(' ', '')
EMAIL_TIMEOUT       = 20  # segundos

# Remitente por defecto (aparece en "De:" en el correo recibido)
DEFAULT_FROM_EMAIL = os.environ.get(
    'DEFAULT_FROM_EMAIL',
    f'DockerShield <{EMAIL_HOST_USER}>' if EMAIL_HOST_USER
    else 'DockerShield <no-reply@localhost>',
)

# Backend: SMTP si hay credenciales, consola si no
if EMAIL_HOST_USER and EMAIL_HOST_PASSWORD:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'


# URL pública del sitio (para construir links en correos)
SITE_URL = os.environ.get('SITE_URL', 'http://127.0.0.1:8000').rstrip('/')