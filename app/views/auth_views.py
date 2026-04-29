"""
Vistas de autenticación:
  - login / logout
  - registro
  - recuperar contraseña (placeholder)
  - cambiar contraseña
"""
from django.contrib.auth import logout, update_session_auth_hash
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
    authenticate_flexible, login_single_session, is_session_active,
    login_is_locked, login_register_failure, login_clear_failures,
    SESSION_IDLE_TIMEOUT_SECONDS,
)
from ..services.password_reset_service import (
    create_token, get_valid_token, send_reset_email, invalidate_other_tokens,
)
from ..services.email_verification_service import (
    create_verification_code, get_valid_code_by_token, verify_code,
    can_resend, send_verification_email,
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

        # Si las credenciales son correctas pero la cuenta NO está verificada
        # (is_active=False), authenticate_flexible devuelve None. Lo detectamos
        # buscando al usuario por email/username para dar un mensaje útil
        # con link al reenvío de código.
        if user is None and identifier:
            from ..models import EmailVerificationCode
            candidate = (
                User.objects.filter(email__iexact=identifier).first()
                or User.objects.filter(username__iexact=identifier).first()
            )
            if (candidate
                    and not candidate.is_active
                    and candidate.check_password(password)):
                # Credenciales OK pero cuenta sin verificar → manda al verificar
                last_ev = (
                    EmailVerificationCode.objects
                    .filter(user=candidate)
                    .order_by('-created_at')
                    .first()
                )
                if last_ev is None or not last_ev.is_valid:
                    new_ev = create_verification_code(candidate)
                    if new_ev:
                        send_verification_email(candidate, new_ev)
                        last_ev = new_ev
                if last_ev is not None:
                    messages.warning(
                        request,
                        'Aún no has verificado tu correo. Te enviamos un nuevo '
                        'código si era necesario.',
                    )
                    return redirect('verificar_correo', token=last_ev.token)

        if user:
            # ── BLOQUEO: si la cuenta tiene sesión activa reciente, NO dejar entrar.
            # Esto evita que dos personas estén usando la misma cuenta a la vez.
            # Si la otra sesión queda inactiva más de SESSION_IDLE_TIMEOUT_SECONDS
            # (ej: cierran el navegador), el bloqueo se libera automáticamente.
            if is_session_active(user):
                mins = max(1, SESSION_IDLE_TIMEOUT_SECONDS // 60)
                messages.error(
                    request,
                    f'Esta cuenta ya está siendo usada en otro dispositivo. '
                    f'Cierra sesión allí o espera {mins} minuto(s) de inactividad '
                    f'para volver a entrar.',
                )
                return render(request, 'login.html', {'form_values': form_values})

            login_clear_failures(ip)
            login_single_session(request, user)
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

        # Unicidad del email (solo si lo anterior es válido).
        # Casos:
        #   • Correo NO existe                            → seguimos al registro
        #   • Correo existe + cuenta activa (is_active)   → "ya tienes cuenta"
        #     (esto cubre TANTO los verificados, COMO los superusers creados
        #      por createsuperuser, COMO usuarios legacy. Una cuenta activa
        #      JAMÁS se puede sobreescribir desde el formulario público —
        #      eso sería un agujero: cualquiera tomaría tu cuenta solo con
        #      conocer tu email.)
        #   • Correo existe + cuenta inactiva (registro abandonado a medias)
        #     → reusamos esa cuenta para no llenar la BD de basura
        existing_pending_user = None
        if (not field_errors['name'] and not field_errors['email']
                and not field_errors['password'] and not field_errors['password2']):
            existing = User.objects.filter(email__iexact=email).first()
            if existing:
                # Una cuenta es "reusable" SOLO si:
                #  - is_active = False  (nunca se activó)
                #  - email_verified = False  (nunca se verificó)
                # Cualquier otra combinación = cuenta legítima → bloqueamos.
                try:
                    is_verified = bool(existing.profile.email_verified)
                except Exception:
                    is_verified = False

                is_reusable = (not existing.is_active) and (not is_verified)

                if is_reusable:
                    existing_pending_user = existing
                else:
                    field_errors['email'] = 'Ya existe una cuenta con ese correo.'

        has_errors = any((
            field_errors['name'], field_errors['email'],
            field_errors['password'], field_errors['password2'],
        ))

        if not has_errors:
            if existing_pending_user is not None:
                # Reutilizamos la cuenta abandonada: actualizamos contraseña + nombre
                user = existing_pending_user
                user.first_name = username[:150]
                user.set_password(password)
                user.is_active = False
                user.save(update_fields=['first_name', 'password', 'is_active'])
            else:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=password,
                    first_name=username[:150],
                    last_name='',
                )
                # Cuenta inactiva hasta verificar el correo
                if user.is_active:
                    user.is_active = False
                    user.save(update_fields=['is_active'])

            # Generar código y enviar correo
            ev = create_verification_code(user)
            if ev is None:
                messages.error(
                    request,
                    'Has solicitado demasiados códigos en la última hora. '
                    'Espera unos minutos antes de intentarlo de nuevo.',
                )
                return render(request, 'register.html', {
                    'form_values':  form_values,
                    'field_errors': field_errors,
                })

            # ── Tracking: guardamos en la sesión del navegador todos los
            # user.id de cuentas que este navegador ha intentado registrar.
            # Cuando finalmente verifique exitosamente, borraremos las
            # otras (típicamente typos del mismo usuario corrigiéndose).
            pending = request.session.get('pending_registration_ids', [])
            if user.id not in pending:
                pending.append(user.id)
                request.session['pending_registration_ids'] = pending

            send_verification_email(user, ev)
            messages.info(
                request,
                f'Te enviamos un código de 6 dígitos a {user.email}. '
                f'Revisa tu bandeja (también la carpeta spam).',
            )
            return redirect('verificar_correo', token=ev.token)

    return render(request, 'register.html', {
        'form_values':  form_values,
        'field_errors': field_errors,
    })


# ─────────────────────────────────────────────────────────────────────
#  VERIFICAR CORREO (formulario del código de 6 dígitos)
# ─────────────────────────────────────────────────────────────────────

def verificar_correo_view(request, token):
    """
    GET  → muestra el formulario para ingresar el código.
    POST → valida el código. Si OK: activa cuenta + login + dashboard.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    ev = get_valid_code_by_token(token)
    if ev is None:
        # Token inexistente, ya usado o demasiados intentos
        messages.error(
            request,
            'Este enlace de verificación ya no es válido. '
            'Si todavía no has verificado tu correo, vuelve a registrarte.',
        )
        return redirect('registro')

    if request.method == 'POST':
        code_input = (request.POST.get('code', '') or '').strip()
        ok, err, user = verify_code(token, code_input)

        if ok:
            # Activar la cuenta
            user.is_active = True
            user.save(update_fields=['is_active'])
            try:
                profile = user.profile
                profile.email_verified = True
                profile.save(update_fields=['email_verified'])
            except Exception:
                pass

            # ── Limpieza de typos: borramos las OTRAS cuentas no-verificadas
            # que este mismo navegador intentó registrar (típicamente porque
            # el usuario escribió mal el correo, volvió a /registro/ y lo
            # corrigió). Solo borramos cuentas que sigan inactivas — nunca
            # tocamos cuentas activas/verificadas.
            pending_ids = request.session.get('pending_registration_ids', []) or []
            other_ids = [pid for pid in pending_ids if pid != user.id]
            if other_ids:
                User.objects.filter(
                    id__in=other_ids,
                    is_active=False,
                    profile__email_verified=False,
                ).delete()
            # Limpiamos el tracking — ya completó el registro
            request.session['pending_registration_ids'] = []

            # Login automático con sesión única
            login_single_session(request, user)
            messages.success(
                request,
                f'¡Listo! Tu correo está verificado. Bienvenido a DockerShield.',
            )
            return redirect('dashboard')

        # Mensaje según el tipo de error
        if err == 'expirado':
            messages.error(
                request,
                'Tu código expiró. Pide un código nuevo con el botón "Reenviar".',
            )
        elif err == 'demasiados':
            messages.error(
                request,
                'Demasiados intentos fallidos. Pide un código nuevo.',
            )
        elif err == 'incorrecto':
            messages.error(
                request,
                'El código es incorrecto. Revisa el correo y vuelve a intentar.',
            )
        else:
            messages.error(request, 'No se pudo verificar el código.')

    return render(request, 'verificar_correo.html', {
        'token':       token,
        'email':       ev.user.email,
        'expires_at':  ev.expires_at,
    })


# ─────────────────────────────────────────────────────────────────────
#  REENVIAR CÓDIGO DE VERIFICACIÓN
# ─────────────────────────────────────────────────────────────────────

def reenviar_codigo_view(request, token):
    """Genera un nuevo código (con cooldown) y manda otro correo."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    # Buscamos el usuario asociado al token (aunque el código en sí esté
    # expirado/usado, podemos generar uno nuevo para el mismo user).
    from ..models import EmailVerificationCode
    try:
        ev_old = EmailVerificationCode.objects.select_related('user').get(token=token)
    except EmailVerificationCode.DoesNotExist:
        messages.error(request, 'Enlace inválido. Vuelve a registrarte.')
        return redirect('registro')

    user = ev_old.user
    if user.is_active and getattr(user.profile, 'email_verified', False):
        # Ya está verificado
        messages.info(request, 'Tu correo ya estaba verificado. Inicia sesión.')
        return redirect('login')

    # Cooldown
    ok, secs = can_resend(user)
    if not ok:
        messages.error(
            request,
            f'Espera {secs} segundo(s) antes de pedir otro código.',
        )
        return redirect('verificar_correo', token=token)

    ev_new = create_verification_code(user)
    if ev_new is None:
        messages.error(
            request,
            'Has pedido demasiados códigos. Espera unos minutos.',
        )
        return redirect('verificar_correo', token=token)

    send_verification_email(user, ev_new)
    messages.success(request, 'Te enviamos un código nuevo. Revisa tu correo.')
    return redirect('verificar_correo', token=ev_new.token)


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
