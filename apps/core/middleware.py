"""
Middleware del proyecto DockerShield.

SingleSessionMiddleware refuerza la regla "una sesión por usuario":
  1) Marca `session_last_activity` en cada request del usuario actual.
     Esto permite que la vista de login decida si una cuenta tiene
     sesión "viva" (no permite segundo login) o "abandonada" (sí permite).
  2) Como red de seguridad, si por alguna razón hay dos sesiones a la vez
     (race condition al loguearse simultáneamente), kickea la vieja.
"""
from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect
from django.utils import timezone


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
                stored_key = (profile.current_session_key or '').strip()
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

                # ── 2) Marcar actividad: tu sesión está VIVA ──
                # Throttle a 60s para no escribir BD en cada request.
                now = timezone.now()
                last = profile.session_last_activity
                if last is None or (now - last).total_seconds() > 60:
                    profile.session_last_activity = now
                    profile.save(update_fields=['session_last_activity'])

        return self.get_response(request)
