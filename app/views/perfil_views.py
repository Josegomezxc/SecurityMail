"""
Vistas del perfil del usuario:
  - Mostrar el perfil (nombre, email, rol, stats, avatar).
  - Editar el nombre de usuario.
  - Cambiar la contraseña.
  - Subir / quitar foto de perfil.
"""
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import redirect, render

from ..services.stats_service import profile_stats
from ..services.profile_service import (
    save_avatar, remove_avatar, get_user_initials, get_user_color,
)
from ..validators import clean_username


@login_required(login_url='login')
def perfil_view(request):
    """
    GET  → render con datos y stats del usuario.
    POST → dispatch por `form_type`:
         · 'info'     → cambio de nombre de usuario
         · 'password' → cambio de contraseña
         · 'avatar'   → subir nueva foto
         · 'avatar_remove' → quitar foto (volver a default)
    """
    if request.method == 'POST':
        form_type = request.POST.get('form_type', '')

        # ── Cambio de nombre de usuario ─────────────────────────────
        if form_type == 'info':
            new_username, err = clean_username(request.POST.get('name', ''))
            if err:
                messages.error(request, err)
            else:
                request.user.first_name = new_username[:150]
                request.user.last_name  = ''
                request.user.save(update_fields=['first_name', 'last_name'])
                messages.success(
                    request, 'Nombre de usuario actualizado correctamente.',
                )
            return redirect('perfil')

        # ── Cambio de contraseña ─────────────────────────────────────
        if form_type == 'password':
            password  = request.POST.get('password', '')
            password2 = request.POST.get('password2', '')

            if not password:
                messages.error(request, 'Ingresa una contraseña nueva.')
            elif password != password2:
                messages.error(request, 'Las contraseñas no coinciden.')
            elif len(password) < 8:
                messages.error(request, 'La contraseña debe tener mínimo 8 caracteres.')
            else:
                request.user.set_password(password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Contraseña actualizada correctamente.')
            return redirect('perfil')

        # ── Subir foto de perfil ─────────────────────────────────────
        if form_type == 'avatar':
            upload = request.FILES.get('avatar')
            if not upload:
                messages.error(request, 'No seleccionaste ninguna imagen.')
            else:
                ok, msg = save_avatar(request.user, upload)
                if ok:
                    messages.success(request, msg)
                else:
                    messages.error(request, msg)
            return redirect('perfil')

        # ── Quitar foto de perfil ────────────────────────────────────
        if form_type == 'avatar_remove':
            ok, msg = remove_avatar(request.user)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return redirect('perfil')

        # ── Toggle: reenviar correos seguros al correo real ──────────
        if form_type == 'forward_safe':
            from ..models import UserProfile
            profile, _ = UserProfile.objects.get_or_create(user=request.user)
            new_value = request.POST.get('enabled') == '1'
            profile.forward_safe_emails = new_value
            profile.save(update_fields=['forward_safe_emails'])
            if new_value:
                messages.success(
                    request,
                    f'Activado: los correos seguros se reenviarán a {request.user.email}.',
                )
            else:
                messages.success(
                    request,
                    'Desactivado: ya no recibirás copias en tu correo real.',
                )
            return redirect('perfil')

    ctx = profile_stats(request.user)
    # Datos para el avatar por defecto (cuando el usuario no sube foto)
    ctx['avatar_initials'] = get_user_initials(request.user)
    ctx['avatar_color']    = get_user_color(request.user)
    return render(request, 'perfil.html', ctx)
