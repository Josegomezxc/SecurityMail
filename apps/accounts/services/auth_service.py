
from functools import wraps

from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth.models import User
from django.core.cache import cache
from django.shortcuts import redirect
from django.utils import timezone

from apps.accounts.models import UserSession




def login_single_session(request, user):

    try:
        session = getattr(user.profile, 'session', None)
        old_key = (session.current_session_key or '').strip() if session else ''
    except Exception:
        old_key = ''


    django_login(request, user)


    if not request.session.session_key:
        request.session.save()

    
    try:
        profile = user.profile
        session, _ = UserSession.objects.get_or_create(profile=profile)
        session.current_session_key = request.session.session_key or ''
        session.session_last_activity = timezone.now()
        session.save(update_fields=['current_session_key', 'session_last_activity'])
    except Exception:
        pass



LOGIN_MAX_FAILS = 3
LOGIN_LOCK_SECS = 60   


def login_is_locked(ip: str):

    lock_key = f'login_lock:{ip}'
    if cache.get(lock_key):
        ttl = cache.ttl(lock_key) if hasattr(cache, 'ttl') else LOGIN_LOCK_SECS
        minutes = max(1, int(ttl / 60))
        return True, minutes
    return False, 0


def login_register_failure(ip: str) -> int:

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

    cache.delete(f'login_fails:{ip}')
    cache.delete(f'login_lock:{ip}')



def authenticate_flexible(request, identifier: str, password: str):

    if '@' in identifier:
        real_user = User.objects.filter(email__iexact=identifier).first()
        if not real_user:
            return None
        return authenticate(
            request, username=real_user.username, password=password,
        )
    return authenticate(request, username=identifier, password=password)




def admin_required(view_fn):

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
