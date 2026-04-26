"""
Lógica de autenticación y autorización:
  - Decorator para vistas exclusivas de admin.
  - Rate limiting por IP para el login (anti fuerza bruta).

Las vistas usan estas funciones para no duplicar lógica de seguridad.
"""
from functools import wraps

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.shortcuts import redirect


# ─────────────────────────────────────────────────────────────────────
#  Rate limiting de login
# ─────────────────────────────────────────────────────────────────────

LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECS = 600   # 10 minutos


def login_is_locked(ip: str):
    """
    Devuelve (True, minutos_restantes) si la IP está bloqueada por
    demasiados intentos. Si no, (False, 0).
    """
    lock_key = f'login_lock:{ip}'
    if cache.get(lock_key):
        ttl = cache.ttl(lock_key) if hasattr(cache, 'ttl') else LOGIN_LOCK_SECS
        minutes = max(1, int(ttl / 60))
        return True, minutes
    return False, 0


def login_register_failure(ip: str) -> int:
    """
    Incrementa el contador de fallos para esta IP.
    Devuelve los intentos RESTANTES. Si llega a 0, bloquea 10 min.
    """
    fail_key = f'login_fails:{ip}'
    lock_key = f'login_lock:{ip}'

    fails = cache.get(fail_key, 0) + 1
    cache.set(fail_key, fails, LOGIN_LOCK_SECS)
    remaining = LOGIN_MAX_FAILS - fails

    if remaining <= 0:
        cache.set(lock_key, True, LOGIN_LOCK_SECS)
        cache.delete(fail_key)

    return remaining


def login_clear_failures(ip: str) -> None:
    """Al login exitoso, limpia contador y bloqueo."""
    cache.delete(f'login_fails:{ip}')
    cache.delete(f'login_lock:{ip}')


# ─────────────────────────────────────────────────────────────────────
#  Autenticación flexible (email O username)
# ─────────────────────────────────────────────────────────────────────

def authenticate_flexible(request, identifier: str, password: str):
    """
    Intenta autenticar primero por username; si falla y el identificador
    parece email, busca el user y autentica por su username real.
    Esto permite que funcione tanto el login normal como `createsuperuser`.
    """
    user = authenticate(request, username=identifier, password=password)
    if user:
        return user

    if '@' in identifier:
        real_user = User.objects.filter(email__iexact=identifier).first()
        if real_user:
            return authenticate(
                request, username=real_user.username, password=password,
            )
    return None


# ─────────────────────────────────────────────────────────────────────
#  Decorator para vistas solo-admin
# ─────────────────────────────────────────────────────────────────────

def admin_required(view_fn):
    """
    Protege una vista: solo usuarios con `is_staff=True` pueden acceder.
    Los no autenticados se redirigen a /, los usuarios normales reciben 403.
    """
    @wraps(view_fn)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not request.user.is_staff:
            return HttpResponseForbidden(
                "<h2 style='font-family:sans-serif;padding:40px;color:#e84040'>"
                "403 — Acceso restringido</h2>"
                "<p style='font-family:sans-serif;padding:0 40px;color:#666'>"
                "Esta sección es solo para administradores.</p>"
            )
        return view_fn(request, *args, **kwargs)
    return _wrapped
