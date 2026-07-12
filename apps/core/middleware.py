
from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect
from django.utils import timezone

from apps.accounts.models import UserSession


class SingleSessionMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, 'user', None)

        if user is not None and user.is_authenticated:
            try:
                profile = user.profile
            except Exception:
                profile = None

            if profile is not None:
                session = getattr(profile, 'session', None)
                stored_key = (session.current_session_key or '').strip() if session else ''
                current_key = request.session.session_key or ''

                if stored_key and current_key and stored_key != current_key:
                    logout(request)
                    messages.warning(
                        request,
                        'Tu sesión fue cerrada porque alguien más inició sesión '
                        'en esta cuenta desde otro dispositivo.',
                    )
                    return redirect('login')

              
                session = getattr(profile, 'session', None)
                if session is None:
                    session = UserSession.objects.create(profile=profile)
                session.session_last_activity = timezone.now()
                session.save(update_fields=['session_last_activity'])

        return self.get_response(request)


class NoCacheAuthMiddleware:


    SAFE_PREFIXES = ('/static/', '/media/', '/__debug__/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        path = request.path or ''
        if any(path.startswith(p) for p in self.SAFE_PREFIXES):
            return response

        ctype = (response.get('Content-Type') or '').lower()
        if 'text/html' not in ctype:
            return response
        if response.has_header('Cache-Control'):
            return response

        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        return response
