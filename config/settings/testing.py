
from .base import *  


DEBUG = False

ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE':  'django.db.backends.sqlite3',
        'NAME':    ':memory:',
    }
}


PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]
CACHES = {
    'default': {
        'BACKEND':  'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'tests',
    }
}
