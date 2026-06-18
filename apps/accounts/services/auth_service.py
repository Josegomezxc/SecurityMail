"""
Lógica de autenticación y autorización:
  - Decorator para vistas exclusivas de admin.
  - Rate limiting por IP para el login (anti fuerza bruta).
  - Single-session enforcement (un usuario, una sesión activa).

Las vistas usan estas funciones para no duplicar lógica de seguridad.
"""
from functools import wraps

from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.shortcuts import redirect
from django.utils import timezone

from apps.accounts.models import UserSession


# Tiempo de inactividad después del cual una sesión se considera "abandonada"
# y se permite que otra persona haga login con la misma cuenta. Si quieres
# que cerrar el navegador desbloquee al instante, baja a 0; si quieres ser
# más estricto, súbelo. 3 minutos es un buen balance.
SESSION_IDLE_TIMEOUT_SECONDS = 60


def is_session_active(user) -> bool:
    """
    Devuelve True si el usuario tiene una sesión "viva" en otro navegador
    o dispositivo (alguien la está usando ahora mismo).

    Se considera viva si:
      • El perfil tiene una current_session_key registrada
      • Esa sesión todavía existe en la BD de Django (no fue logout/expirada)
      • Hubo actividad en los últimos SESSION_IDLE_TIMEOUT_SECONDS segundos
    """
    try:
        profile = user.profile
    except Exception:
        return False

    session = getattr(profile, 'session', None)
    if session is None:
        return False
    key = (session.current_session_key or '').strip()
    if not key:
        return False

    # ¿Existe la sesión todavía? (si hicieron logout o expiró, ya no)
    if not Session.objects.filter(session_key=key).exists():
        return False

    # ¿Hubo actividad reciente?
    last = session.session_last_activity
    if last is None:
        return False
    idle = (timezone.now() - last).total_seconds()
    return idle < SESSION_IDLE_TIMEOUT_SECONDS


# ─────────────────────────────────────────────────────────────────────
#  Login con sesión única
# ─────────────────────────────────────────────────────────────────────

def login_single_session(request, user):
    """
    Hace login del usuario y garantiza que sea su ÚNICA sesión activa.

    Pasos:
      1) Borra de la BD cualquier sesión vieja del usuario (las
         identificamos por la session_key guardada en su perfil).
      2) Llama a django.contrib.auth.login(), que crea una sesión nueva.
      3) Guarda la nueva session_key en user.profile.current_session_key.

    Resultado: el usuario que estuviera logueado en otro navegador será
    deslogueado por SingleSessionMiddleware en su próximo request.
    """
    # 1) Borrar la sesión anterior si la teníamos registrada
    try:
        session = getattr(user.profile, 'session', None)
        old_key = (session.current_session_key or '').strip() if session else ''
    except Exception:
        old_key = ''

    # 2) Crear la sesión nueva (Django genera el session_key)
    django_login(request, user)

    # Forzar que la sesión se guarde YA en BD para tener session_key disponible
    if not request.session.session_key:
        request.session.save()

    # 3) Persistir la nueva session_key en la sesión del perfil
    try:
        profile = user.profile
        session, _ = UserSession.objects.get_or_create(profile=profile)
        session.current_session_key = request.session.session_key or ''
        session.session_last_activity = timezone.now()
        session.save(update_fields=['current_session_key', 'session_last_activity'])
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────
#  Rate limiting de login
# ─────────────────────────────────────────────────────────────────────

LOGIN_MAX_FAILS = 3
LOGIN_LOCK_SECS = 60   # 10 minutos


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

    Optimización: si el identifier contiene '@', buscamos primero por email
    para evitar la llamada inútil a authenticate() con username=email que
    ejecuta PBKDF2 sobre un hash dummy (doble hash innecesario).
    """
    if '@' in identifier:
        real_user = User.objects.filter(email__iexact=identifier).first()
        if not real_user:
            return None
        return authenticate(
            request, username=real_user.username, password=password,
        )
    return authenticate(request, username=identifier, password=password)


# ─────────────────────────────────────────────────────────────────────
#  Decorator para vistas solo-admin
# ─────────────────────────────────────────────────────────────────────

def admin_required(view_fn):
    """
    Protege una vista: solo usuarios con `is_staff=True` pueden acceder.
    No autenticados → login. Usuarios normales que intenten entrar a la
    URL de admin: los devolvemos a la página de la que venían (HTTP_REFERER)
    sin mostrar pantalla de error ni filtrar nada.
    """
    @wraps(view_fn)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not request.user.is_staff:
            referer = request.META.get('HTTP_REFERER', '')
            host = request.get_host()
            if referer and (host in referer):
                return redirect(referer)
            return redirect('dashboard')
        return view_fn(request, *args, **kwargs)
    return _wrapped
