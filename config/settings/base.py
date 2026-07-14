
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent



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
        pass  


_load_dotenv()



SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise Exception(
        "SECRET_KEY no encontrada. Añádela al archivo .env en la raíz del proyecto."
    )

DEBUG = False

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    if h.strip()
]


CSRF_TRUSTED_ORIGINS = []
for h in ALLOWED_HOSTS:
    if h in ('localhost', '127.0.0.1'):
        CSRF_TRUSTED_ORIGINS += [f'http://{h}:8000', f'http://{h}']
    elif h.startswith('.'):
        CSRF_TRUSTED_ORIGINS.append(f'https://*{h}')
    else:
        CSRF_TRUSTED_ORIGINS += [f'https://{h}', f'http://{h}']


SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

CSRF_FAILURE_VIEW = 'apps.core.views.csrf_failure_view'


MAIL_DOMAIN = os.environ.get('MAIL_DOMAIN', 'dockershield.lat').strip()


DEFAULT_FROM_EMAIL = f'DockerShield <noreply@{MAIL_DOMAIN}>'


SERVER_EMAIL = f'root@{MAIL_DOMAIN}'


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'apps.core',
    'apps.accounts',
    'apps.aliases',
    'apps.mail',
    'apps.sandbox',
    'apps.notifications',
]



SESSION_COOKIE_AGE = 60 * 60 * 24 * 365   
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'apps.core.middleware.SingleSessionMiddleware',
    'apps.core.middleware.NoCacheAuthMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]




ROOT_URLCONF       = 'config.urls'
WSGI_APPLICATION   = 'config.wsgi.application'
ASGI_APPLICATION   = 'config.asgi.application'




TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
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



DATABASES = {
    'default': {
        'ENGINE':   'django.db.backends.postgresql',
        'NAME':     os.environ.get('DB_NAME',     'db_email_seguro'),
        'USER':     os.environ.get('DB_USER',     'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST':     os.environ.get('DB_HOST',     'localhost'),
        'PORT':     os.environ.get('DB_PORT',     '5432'),
        'CONN_MAX_AGE': int(os.environ.get('CONN_MAX_AGE', 600)),
    }
}



CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-default-cache',
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

STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []


MEDIA_URL  = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


DATA_UPLOAD_MAX_MEMORY_SIZE = 30 * 1024 * 1024  


SITE_URL = os.environ.get('SITE_URL', 'http://127.0.0.1:8000').rstrip('/')
