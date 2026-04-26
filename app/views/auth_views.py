"""
Vistas de autenticación:
  - login / logout
  - registro
  - recuperar contraseña (placeholder)
  - cambiar contraseña
"""
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import redirect, render

from ..Forms import CambiarPasswordForm
from ..validators import (
    clean_username, clean_email, validate_password,
    clean_login_identifier, clean_login_password, get_client_ip,
)
from ..services.auth_service import (
    authenticate_flexible,
    login_is_locked, login_register_failure, login_clear_failures,
    LOGIN_MAX_FAILS,
)
from ..services.password_reset_service import (
    create_token, get_valid_token, send_reset_email, invalidate_other_tokens,
)


# ─────────────────────────────────────────────────────────────────────
#  LOGIN
# ─────────────────────────────────────────────────────────────────────

def login_view(request):
    """
    GET  → muestra la pantalla de bienvenida + formulario de login.
    POST → autentica al usuario por email O username, con rate limiting
           por IP para prevenir fuerza bruta.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    form_values = {'email': ''}

    if request.method == 'POST':
        identifier_raw = request.POST.get('email', '')
        password_raw   = request.POST.get('password', '')

        # Preservamos lo que escribió para no borrarle el campo si hay error
        form_values['email'] = (identifier_raw or '').strip()

        # ── Rate limiting: ¿esta IP está bloqueada? ──────────────────
        ip = get_client_ip(request)
        is_locked, minutes_left = login_is_locked(ip)
        if is_locked:
            messages.error(
                request,
                f'Demasiados intentos fallidos. Espera {minutes_left} minuto(s) '
                f'antes de volver a intentarlo.',
            )
            return render(request, 'login.html', {'form_values': form_values})

        # ── Validación de forma ─────────────────────────────────────
        identifier, ident_err = clean_login_identifier(identifier_raw)
        password,   pwd_err   = clean_login_password(password_raw)
        form_errors = [e for e in (ident_err, pwd_err) if e]

        if form_errors:
            for e in form_errors:
                messages.error(request, e)
            return render(request, 'login.html', {'form_values': form_values})

        # ── Autenticación ──────────────────────────────────────────
        user = authenticate_flexible(request, identifier, password)

        if user:
            login_clear_failures(ip)
            login(request, user)
            return redirect('dashboard')

        # ── Fallo: cuenta regresiva ─────────────────────────────────
        remaining = login_register_failure(ip)

        if remaining <= 0:
            messages.error(
                request,
                'Demasiados intentos fallidos. Acceso bloqueado por 10 minutos.',
            )
        elif remaining == 1:
            messages.error(
                request,
                'Correo o contraseña incorrectos. Te queda 1 intento antes del bloqueo.',
            )
        else:
            messages.error(
                request,
                f'Correo o contraseña incorrectos. Te quedan {remaining} intentos.',
            )

    return render(request, 'login.html', {'form_values': form_values})


# ─────────────────────────────────────────────────────────────────────
#  REGISTRO
# ─────────────────────────────────────────────────────────────────────

def registro_view(request):
    """Registro con validación estricta y preservación de valores al fallar."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    form_values  = {'name': '', 'email': ''}
    field_errors = {'name': '', 'email': '', 'password': [], 'password2': ''}

    if request.method == 'POST':
        # ── Normalización + validación de cada campo ────────────────
        username, name_err  = clean_username(request.POST.get('name', ''))
        email,    email_err = clean_email(request.POST.get('email', ''))

        password  = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        # Valores normalizados para devolverlos al template si hay error
        # (la contraseña NUNCA se devuelve, por seguridad)
        form_values['name']  = username
        form_values['email'] = email

        if name_err:
            field_errors['name'] = name_err
        if email_err:
            field_errors['email'] = email_err

        pwd_errors = validate_password(password, email=email, name=username)
        if pwd_errors:
            field_errors['password'] = pwd_errors

        if password and password != password2:
            field_errors['password2'] = 'Las dos contraseñas no coinciden.'

        # Unicidad del email (solo si lo anterior es válido)
        if (not field_errors['name'] and not field_errors['email']
                and not field_errors['password'] and not field_errors['password2']):
            if User.objects.filter(email__iexact=email).exists():
                field_errors['email'] = 'Ya existe una cuenta con ese correo.'

        has_errors = any((
            field_errors['name'], field_errors['email'],
            field_errors['password'], field_errors['password2'],
        ))

        if not has_errors:
            user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=username[:150],
                last_name='',
            )
            login(request, user)
            messages.success(
                request,
                f'¡Cuenta creada! Bienvenido a SecureMail Shield, {username}.',
            )
            return redirect('dashboard')

    return render(request, 'register.html', {
        'form_values':  form_values,
        'field_errors': field_errors,
    })


# ─────────────────────────────────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────────────────────────────────

def logout_view(request):
    logout(request)
    return redirect('login')


# ─────────────────────────────────────────────────────────────────────
#  RECUPERAR CONTRASEÑA — paso 1: pedir el correo y enviar el link
# ─────────────────────────────────────────────────────────────────────

def recuperar_view(request):
    """
    GET  → muestra el formulario.
    POST → valida el email, genera token y envía el correo.
           SIEMPRE responde con el mismo mensaje, exista o no el usuario
           (no revelamos qué emails están registrados).
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    form_values = {'email': ''}

    if request.method == 'POST':
        email_raw = request.POST.get('email', '')
        email_clean, email_err = clean_email(email_raw)
        form_values['email'] = email_clean

        if email_err:
            messages.error(request, email_err)
            return render(request, 'recuperar.html', {'form_values': form_values})

        # Buscar el usuario. Si no existe, igual respondemos "OK" para no
        # filtrar qué correos están registrados.
        try:
            user = User.objects.get(email__iexact=email_clean)
            token = create_token(user, ip=get_client_ip(request))
            if token is not None:
                send_reset_email(user, token)
                # Ignoramos errores de envío a propósito: no queremos revelar
                # fallos del proveedor al atacante. El log del server los captura.
        except User.DoesNotExist:
            pass

        return render(request, 'recuperar.html', {
            'form_values': {'email': ''},
            'submitted':   True,
            'sent_to':     email_clean,
        })

    return render(request, 'recuperar.html', {'form_values': form_values})


# ─────────────────────────────────────────────────────────────────────
#  RECUPERAR CONTRASEÑA — paso 2: nueva contraseña con token válido
# ─────────────────────────────────────────────────────────────────────

def reset_password_view(request, token):
    """
    GET  → valida el token y muestra el formulario de nueva contraseña.
    POST → valida otra vez + guarda la contraseña + marca el token usado.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    t = get_valid_token(token)
    if t is None:
        messages.error(
            request,
            'El enlace ha expirado o no es válido. Solicita uno nuevo.',
        )
        return redirect('recuperar')

    field_errors = {'password': [], 'password2': ''}

    if request.method == 'POST':
        password  = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        pwd_errors = validate_password(
            password,
            email=t.user.email,
            name=t.user.first_name or '',
        )
        if pwd_errors:
            field_errors['password'] = pwd_errors

        if password and password != password2:
            field_errors['password2'] = 'Las dos contraseñas no coinciden.'

        if not field_errors['password'] and not field_errors['password2']:
            # Todo OK → actualizamos la contraseña
            t.user.set_password(password)
            t.user.save(update_fields=['password'])
            t.mark_used()
            # Invalida otros tokens activos del mismo usuario
            invalidate_other_tokens(t.user, except_pk=t.pk)
            messages.success(
                request,
                'Contraseña actualizada correctamente. Inicia sesión con la nueva.',
            )
            return redirect('login')

    return render(request, 'reset_password.html', {
        'token':        token,
        'email':        t.user.email,
        'field_errors': field_errors,
    })


# ─────────────────────────────────────────────────────────────────────
#  CAMBIAR CONTRASEÑA (form propio con validación Django)
# ─────────────────────────────────────────────────────────────────────

@login_required
def cambiar_password(request):
    """
    Formulario dedicado para cambiar la contraseña.
    `update_session_auth_hash` mantiene la sesión activa tras el cambio.
    """
    form = CambiarPasswordForm(user=request.user)

    if request.method == "POST":
        form = CambiarPasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "¡Contraseña actualizada correctamente!")
            return redirect("cambiar_password")
        else:
            messages.error(request, "Revisa los errores del formulario.")

    return render(request, "cambiar_password.html", {"form": form})
