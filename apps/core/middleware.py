"""
Middleware del proyecto DockerShield.

SingleSessionMiddleware refuerza la regla "una sesión por usuario":
  1) Marca `session_last_activity` en cada request del usuario actual.
     Esto permite que la vista de login decida si una cuenta tiene
     sesión "viva" (no permite segundo login) o "abandonada" (sí permite).
  2) Como red de seguridad, si por alguna razón hay dos sesiones a la vez
     (race condition al loguearse simultáneamente), kickea la vieja.

NoCacheAuthMiddleware evita que el navegador conserve páginas autenticadas
en caché. Sin esto, tras logout o eliminar cuenta el botón "atrás" del
navegador puede mostrar la versión cacheada de la página privada (aunque
el usuario ya no tenga sesión). Con los headers que setea, el navegador
está obligado a re-pedir la página al servidor, que redirige al login.
"""
from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect
from django.utils import timezone

from apps.accounts.models import UserSession
from apps.accounts.services.auth_service import SESSION_IDLE_TIMEOUT_SECONDS


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

                # ── 1) Red de seguridad: si hay dos sesiones simultáneas,
                #       kickea a la sesión vieja (la que NO está registrada). ──
                if stored_key and current_key and stored_key != current_key:
                    logout(request)
                    messages.warning(
                        request,
                        'Tu sesión fue cerrada porque alguien más inició sesión '
                        'en esta cuenta desde otro dispositivo.',
                    )
                    return redirect('login')

                # ── 2) Auto-logout por inactividad ──
                if session and session.session_last_activity:
                    idle = (timezone.now() - session.session_last_activity).total_seconds()
                    if idle > SESSION_IDLE_TIMEOUT_SECONDS:
                        logout(request)
                        messages.info(
                            request,
                            'Tu sesión cerró por inactividad. Iniciá sesión de nuevo.',
                        )
                        return redirect('login')

                # ── 3) Marcar actividad: tu sesión está VIVA ──
                # Throttle a 10s para que el auto-logout sea preciso.
                now = timezone.now()
                session = getattr(profile, 'session', None)
                if session is None:
                    session = UserSession.objects.create(profile=profile)
                last = session.session_last_activity
                if last is None or (now - last).total_seconds() > 10:
                    session.session_last_activity = now
                    session.save(update_fields=['session_last_activity'])

        return self.get_response(request)


class NoCacheAuthMiddleware:
    """
    Setea headers anti-caché en respuestas HTML para que el botón "atrás"
    del navegador NUNCA muestre una página autenticada después de logout
    o eliminación de cuenta. El navegador se ve obligado a revalidar con
    el servidor, que redirige a /login/ si la sesión ya no existe.

    Reglas:
      - Solo HTML (Content-Type: text/html). Las APIs JSON, archivos
        estáticos, media y endpoints que setean su propio Cache-Control
        (ej. email_html_api) quedan intactos.
      - Si la respuesta ya trae un Cache-Control explícito, lo respetamos
        (no pisamos decisiones intencionales).
    """

    SAFE_PREFIXES = ('/static/', '/media/', '/__debug__/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Evitar prefijos que no necesitan/quieren no-cache
        path = request.path or ''
        if any(path.startswith(p) for p in self.SAFE_PREFIXES):
            return response

        # Solo HTML
        ctype = (response.get('Content-Type') or '').lower()
        if 'text/html' not in ctype:
            return response

        # Si la vista ya decidió un Cache-Control, no lo pisamos
        if response.has_header('Cache-Control'):
            return response

        response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        return response
