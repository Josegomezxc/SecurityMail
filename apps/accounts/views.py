"""
Vistas del módulo accounts:
  - login / logout
  - registro + verificación de correo
  - recuperar / reset password
  - cambiar contraseña
  - perfil del usuario
  - eliminar cuenta (con confirmación de password)
"""
import os
import shutil
from django.conf import settings
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from apps.core.validators import (
    clean_username, clean_email, validate_password,
    clean_login_identifier, clean_login_password, get_client_ip,
)
from .forms import CambiarPasswordForm
from .services.auth_service import (
    authenticate_flexible, login_single_session, is_session_active,
    login_is_locked, login_register_failure, login_clear_failures,
    SESSION_IDLE_TIMEOUT_SECONDS,
)
from .services.login_lock_service import (
    check_user_lock_state, register_user_failure, clear_user_failures,
    STATE_TEMP_LOCKED, STATE_PERMANENT_LOCK,
)
from .services.password_reset_service import (
    create_token, get_valid_token, send_reset_email, invalidate_other_tokens,
)
from django.utils import timezone

from .services.email_verification_service import (
    create_verification_code, verify_deletion_code, can_resend,
)
from .services.pending_registration_service import (
    create_pending_registration, get_valid_pending_by_token,
    get_pending_by_token_any, verify_pending_code, can_resend_pending,
    send_pending_registration_email, cleanup_expired_pending_registrations,
)
from .services.profile_service import (
    save_avatar, remove_avatar, get_user_initials, get_user_color,
)
from .services.account_deletion_service import (
    send_account_deleted_email, send_deletion_code_email,
)
from apps.core.services.stats_service import profile_stats


# ═════════════════════════════════════════════════════════════════════
#  LOGIN
# ═════════════════════════════════════════════════════════════════════

def login_view(request):
    """
    GET  → muestra la pantalla de bienvenida + formulario de login.
    POST → autentica al usuario por email O username, con rate limiting
           por IP para prevenir fuerza bruta.

    Persistencia del modal de lock: cuando una cuenta queda temp/permanent
    locked, guardamos su id en `request.session['locked_user_id']`. En cada
    GET re-chequeamos el estado del usuario y, si sigue bloqueado, re-
    renderizamos el modal flotante. Así el usuario no puede "saltar" la
    espera recargando.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    form_values = {'email': ''}

    # ── GET: flash de "solicitud enviada" (dismissible) ─────────────
    # Cuando el usuario acaba de enviar una solicitud de recuperación
    # desde /cuenta/recuperar-bloqueada/<id>/, la vista guarda en session
    # `recovery_sent_flash = user_id` y redirige acá. Mostramos un card
    # con X para cerrar; al cerrar (JS) o al recargar, no aparece más.
    recovery_flash_uid = None
    if request.method == 'GET':
        recovery_flash_uid = request.session.pop('recovery_sent_flash', None)

    # ── GET: persistencia del modal de lock ──────────────────────────
    # Si la session recuerda un user_id lockeado, re-renderizamos el
    # overlay correspondiente. PERO si el usuario ya envió una solicitud
    # de recuperación (pending o resolved), apagamos el modal persistente:
    # ya está informado, dejamos que vea el login normal. La info sigue
    # siendo accesible vía /cuenta/recuperar-bloqueada/<id>/.
    locked_uid = request.session.get('locked_user_id')
    if locked_uid and request.method == 'GET':
        locked_user = User.objects.filter(pk=locked_uid).first()
        if locked_user is None:
            request.session.pop('locked_user_id', None)
        else:
            from .models import AccountRecoveryRequest
            has_any_recovery = AccountRecoveryRequest.objects.filter(
                user=locked_user,
            ).exists()
            if has_any_recovery:
                # Ya hay solicitud → no taparle el login.
                request.session.pop('locked_user_id', None)
            else:
                state, ctx = check_user_lock_state(locked_user)
                if state == STATE_PERMANENT_LOCK:
                    return render(request, 'accounts/login.html', {
                        'form_values':          form_values,
                        'permanent_lock':       True,
                        'lock_reason':          ctx.get('reason', ''),
                        'lock_user_id':         locked_user.id,
                        'lock_request_pending': ctx.get('pending_request', False),
                    })
                if state == STATE_TEMP_LOCKED:
                    return render(request, 'accounts/login.html', {
                        'form_values':       form_values,
                        'temp_lock':         True,
                        'temp_lock_seconds': ctx.get('remaining_seconds', 0),
                        'temp_lock_warning': True,
                    })
                # Estado ya OK — limpiamos la marca.
                request.session.pop('locked_user_id', None)

    # GET con flash de solicitud enviada (después de pasar el bloque de
    # lock para evitar conflicto si justo se acaba de bloquear).
    if recovery_flash_uid and request.method == 'GET':
        flash_user = User.objects.filter(pk=recovery_flash_uid).first()
        if flash_user is not None:
            return render(request, 'accounts/login.html', {
                'form_values':    form_values,
                'recovery_flash': True,
                'flash_email':    flash_user.email,
            })

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
            return render(request, 'accounts/login.html', {'form_values': form_values})

        # ── Validación de forma ─────────────────────────────────────
        identifier, ident_err = clean_login_identifier(identifier_raw)
        password,   pwd_err   = clean_login_password(password_raw)
        form_errors = [e for e in (ident_err, pwd_err) if e]

        if form_errors:
            for e in form_errors:
                messages.error(request, e)
            return render(request, 'accounts/login.html', {'form_values': form_values})

        # ── Autenticación ──────────────────────────────────────────
        user = authenticate_flexible(request, identifier, password)

        # Si la autenticación falla, intentamos diagnosticar la causa para
        # dar un mensaje útil (correo inexistente, cuenta deshabilitada, etc.)
        if user is None and identifier:
            candidate = (
                User.objects.filter(email__iexact=identifier).first()
                or User.objects.filter(username__iexact=identifier).first()
            )

            # ── Caso 1: el correo / usuario no existe en la BD ──
            if candidate is None:
                # Antes de avisar "correo inexistente", revisamos si hay un
                # registro pendiente de verificación (el dueño cerró el tab
                # antes de meter el código). Si lo hay, lo mandamos a esa
                # pantalla en vez de decirle que su correo no existe.
                from .models import PendingRegistration
                if '@' in identifier:
                    pr = (
                        PendingRegistration.objects
                        .filter(email__iexact=identifier, used_at__isnull=True)
                        .order_by('-created_at')
                        .first()
                    )
                    if pr is not None and pr.is_valid:
                        messages.warning(
                            request,
                            'Aún no has verificado tu correo. Ingresa el código '
                            'que te enviamos para completar el registro.',
                        )
                        return redirect('verificar_correo', token=pr.token)

                # Contamos el intento contra el rate limit (anti-enumeración).
                login_register_failure(ip)
                msg = ('Esta dirección de correo no existe. Intenta de nuevo '
                       'con una dirección diferente.') if '@' in identifier else (
                       'Este nombre de usuario no existe. Intenta con otro o '
                       'usa tu correo registrado.')
                messages.error(request, msg)
                return render(request, 'accounts/login.html', {'form_values': form_values})

            # ── Caso 2: cuenta marcada como eliminada (soft delete) ─────
            # Si profile.is_deleted = True, la cuenta fue cerrada a propósito.
            if (not candidate.is_active
                    and candidate.check_password(password)
                    and getattr(getattr(candidate, 'profile', None), 'is_deleted', False)):
                messages.error(
                    request,
                    'Esta cuenta fue eliminada. Si querés volver a usar DockerShield, '
                    'creá una cuenta nueva.',
                )
                return render(request, 'accounts/login.html', {'form_values': form_values})

            # ── Caso 3: cuenta bloqueada por intentos (permanent o temp) ─
            # Si el user existe pero está en lock, mostramos la card
            # apropiada SIN contar el intento (no penalizamos por mirar).
            lock_state, lock_ctx = check_user_lock_state(candidate)
            if lock_state == STATE_PERMANENT_LOCK:
                has_pending_req = lock_ctx.get('pending_request', False)
                # Si ya hay solicitud pendiente, el card es DISMISSIBLE y no
                # se persiste en session — el usuario ya está informado.
                # Si no hay solicitud aún, el card es persistente (el usuario
                # tiene que pasar por el flujo de recuperación).
                if not has_pending_req:
                    request.session['locked_user_id'] = candidate.id
                return render(request, 'accounts/login.html', {
                    'form_values':          form_values,
                    'permanent_lock':       True,
                    'lock_reason':          lock_ctx.get('reason', ''),
                    'lock_user_id':         candidate.id,
                    'lock_request_pending': has_pending_req,
                    'dismissible':          has_pending_req,
                })
            if lock_state == STATE_TEMP_LOCKED:
                # El user existe y está temp-locked. Si la contraseña
                # es correcta, NO lo dejamos entrar igual (respetamos el
                # tiempo de espera para defender contra brute force).
                request.session['locked_user_id'] = candidate.id
                return render(request, 'accounts/login.html', {
                    'form_values':       form_values,
                    'temp_lock':         True,
                    'temp_lock_seconds': lock_ctx.get('remaining_seconds', 0),
                    'temp_lock_warning': lock_ctx.get('warning_permanent', False),
                })

            # ── Caso 4: contraseña incorrecta → registrar fallo por user ─
            new_state, new_ctx = register_user_failure(candidate)
            login_register_failure(ip)  # también cuenta contra rate-limit IP

            if new_state == STATE_PERMANENT_LOCK:
                request.session['locked_user_id'] = candidate.id
                return render(request, 'accounts/login.html', {
                    'form_values':          form_values,
                    'permanent_lock':       True,
                    'lock_reason':          new_ctx.get('reason', ''),
                    'lock_user_id':         candidate.id,
                    'lock_request_pending': False,
                })
            if new_state == STATE_TEMP_LOCKED:
                request.session['locked_user_id'] = candidate.id
                return render(request, 'accounts/login.html', {
                    'form_values':       form_values,
                    'temp_lock':         True,
                    'temp_lock_seconds': new_ctx.get('remaining_seconds', 0),
                    'temp_lock_warning': True,  # próxima falla = permanente
                })
            # Sigue habiendo intentos — mensaje normal con contador.
            attempts_left = new_ctx.get('attempts_left', 0)
            if attempts_left == 1:
                messages.error(
                    request,
                    'Contraseña incorrecta. Te queda 1 intento antes del '
                    'bloqueo temporal de la cuenta.',
                )
            else:
                messages.error(
                    request,
                    f'Contraseña incorrecta. Te quedan {attempts_left} intentos.',
                )
            return render(request, 'accounts/login.html', {'form_values': form_values})

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
                return render(request, 'accounts/login.html', {'form_values': form_values})

            login_clear_failures(ip)
            clear_user_failures(user)
            login_single_session(request, user)

            # "Recordarme en este equipo": si está marcado, la sesión
            # persiste 30 días aunque cierre el navegador. Si no, expira
            # al cerrar el navegador (set_expiry(0)) — pisa el setting
            # global SESSION_COOKIE_AGE para esta sesión específica.
            remember = (request.POST.get('remember') or '').lower() in ('on', '1', 'true', 'yes')
            if remember:
                request.session.set_expiry(60 * 60 * 24 * 30)   # 30 días
                request.session['remember_me'] = True
            else:
                request.session.set_expiry(0)                   # cierre del navegador
                request.session['remember_me'] = False

            return redirect('dashboard')

    return render(request, 'accounts/login.html', {'form_values': form_values})


# ═════════════════════════════════════════════════════════════════════
#  SOLICITUD DE RECUPERACIÓN DE CUENTA BLOQUEADA
# ═════════════════════════════════════════════════════════════════════

def account_recovery_request_view(request, user_id):
    """
    Pantalla pública (no requiere login) donde el dueño de una cuenta
    bloqueada puede ver el estado de sus solicitudes de recuperación
    o crear una nueva.

    Comportamiento según estado actual:
      - Cuenta bloqueada + sin solicitudes              → form
      - Cuenta bloqueada + última solicitud pendiente   → card "esperá"
      - Cuenta bloqueada + última rechazada             → card de rechazo
        con la respuesta del admin + form para reintentar
      - Cuenta OK + tiene solicitudes en historial      → muestra la
        más reciente (aprobada / rechazada vieja) para que el usuario
        vea el resultado
      - Cuenta OK + sin solicitudes                     → redirect a login
    """
    from .models import AccountRecoveryRequest
    candidate = User.objects.filter(pk=user_id).first()
    if candidate is None:
        return redirect('login')

    state, _ctx = check_user_lock_state(candidate)
    is_locked = (state == STATE_PERMANENT_LOCK)

    # Última solicitud (cualquier estado) — la usamos para renderizar
    # historial de decisión incluso si la cuenta ya fue recuperada.
    last_req = (
        AccountRecoveryRequest.objects
        .filter(user=candidate)
        .order_by('-created_at')
        .first()
    )

    # Si no está bloqueado y no hay historial, no hay nada que mostrar.
    if not is_locked and last_req is None:
        return redirect('login')

    pending  = last_req if (last_req and last_req.status == 'pending')  else None
    resolved = last_req if (last_req and last_req.status != 'pending') else None

    # Si la cuenta volvió a bloquearse después de una aprobación anterior,
    # la resolución vieja ya no es relevante — mostramos el form para crear
    # una solicitud nueva en vez del cartel de "aprobada" con el mensaje
    # del admin.
    if is_locked and resolved and resolved.status == 'approved':
        resolved = None

    if request.method == 'POST':
        if not is_locked:
            messages.error(
                request,
                'Tu cuenta ya no está bloqueada — no hay nada que solicitar.',
            )
            return redirect('login')
        if pending is not None:
            messages.warning(
                request,
                'Ya tenés una solicitud pendiente. Esperá la respuesta del administrador.',
            )
            return redirect('account_recovery_request', user_id=candidate.id)

        reason = (request.POST.get('reason') or '').strip()[:2000]
        if len(reason) < 20:
            messages.error(
                request,
                'Explicá tu situación con al menos 20 caracteres para que el admin '
                'pueda evaluarla.',
            )
            return render(request, 'accounts/account_recovery_request.html', {
                'target_user': candidate,
                'is_locked':   is_locked,
                'pending':     None,
                'resolved':    resolved,
                'reason':      reason,
            })

        req = AccountRecoveryRequest.objects.create(
            user=candidate,
            reason=reason,
        )

        # Notificar a todos los admins (mismo patrón que alias_quota_request_create).
        try:
            from apps.notifications.models import Notification
            admins = User.objects.filter(is_staff=True, is_active=True)
            user_name = (candidate.get_full_name() or candidate.email
                         or candidate.username)
            admin_target = f'/admin-panel/solicitudes-cuenta/?open={req.id}'
            notif_objs = [
                Notification(
                    user=admin,
                    type='system',
                    title='Recuperación de cuenta bloqueada',
                    message=(f'{user_name} pide reactivar su cuenta bloqueada '
                             'permanentemente. Revisá en el panel.'),
                    status='pending',
                    read=False,
                    target_url=admin_target,
                )
                for admin in admins
            ]
            if notif_objs:
                Notification.objects.bulk_create(notif_objs)
        except Exception as e:
            print(f"[account_recovery_request] No se pudo notificar al admin: {e}")

        # Una vez enviada la solicitud, el usuario debe poder ver el login
        # normal (sin el modal flotante persistente). Limpiamos la marca
        # de "locked_user_id" en session y dejamos un flash dismissible
        # ("Solicitud enviada al admin") que se renderiza en /login/.
        request.session.pop('locked_user_id', None)
        request.session['recovery_sent_flash'] = candidate.id
        return redirect('login')

    return render(request, 'accounts/account_recovery_request.html', {
        'target_user': candidate,
        'is_locked':   is_locked,
        'pending':     pending,
        'resolved':    resolved,
    })


# ═════════════════════════════════════════════════════════════════════
#  REGISTRO
# ═════════════════════════════════════════════════════════════════════

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

        # Unicidad del email.
        if (not field_errors['name'] and not field_errors['email']
                and not field_errors['password'] and not field_errors['password2']):
            if User.objects.filter(email__iexact=email).exists():
                field_errors['email'] = 'Ya existe una cuenta con ese correo.'

        has_errors = any((
            field_errors['name'], field_errors['email'],
            field_errors['password'], field_errors['password2'],
        ))

        if not has_errors:
            # Creamos un PendingRegistration con los datos del form + código.
            # El User real se crea solo cuando se ingrese el código correcto.
            pr = create_pending_registration(
                email=email, first_name=username, password=password,
            )
            if pr is None:
                messages.error(
                    request,
                    'Has solicitado demasiados códigos en la última hora. '
                    'Espera unos minutos antes de intentarlo de nuevo.',
                )
                return render(request, 'accounts/register.html', {
                    'form_values':  form_values,
                    'field_errors': field_errors,
                })

            # ── Tracking de tokens pendientes en la sesión del navegador.
            # Si el usuario hace varios intentos (typos al escribir el email,
            # vuelve a /registro/, corrige), guardamos cada token. Cuando
            # finalmente verifique uno, invalidamos los otros pendientes.
            pending_tokens = request.session.get('pending_registration_tokens', [])
            if pr.token not in pending_tokens:
                pending_tokens.append(pr.token)
                request.session['pending_registration_tokens'] = pending_tokens

            # Enviar el correo en un hilo separado para no bloquear el request
            import threading
            threading.Thread(
                target=send_pending_registration_email,
                args=[pr], daemon=True,
            ).start()
            messages.info(
                request,
                f'Te enviamos un código de 6 dígitos a {pr.email}. '
                f'Revisa tu bandeja (también la carpeta spam).',
            )
            return redirect('verificar_correo', token=pr.token)

    return render(request, 'accounts/register.html', {
        'form_values':  form_values,
        'field_errors': field_errors,
    })


# ═════════════════════════════════════════════════════════════════════
#  VERIFICAR CORREO (formulario del código de 6 dígitos)
# ═════════════════════════════════════════════════════════════════════

def verificar_correo_view(request, token):
    """
    GET  → muestra el formulario para ingresar el código.
    POST → valida el código. Si OK: CREA el User real + login + dashboard.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    pr = get_valid_pending_by_token(token)
    if pr is None:
        # Token inexistente, ya usado o demasiados intentos
        messages.error(
            request,
            'Este enlace de verificación ya no es válido. '
            'Si todavía no has verificado tu correo, vuelve a registrarte.',
        )
        return redirect('registro')

    if request.method == 'POST':
        code_input = (request.POST.get('code', '') or '').strip()
        ok, err, user = verify_pending_code(token, code_input)

        if ok:
            # Limpiamos el tracking de tokens pendientes — ya completó.
            # Los otros pendings del mismo email fueron invalidados dentro
            # del service (`verify_pending_code`).
            request.session['pending_registration_tokens'] = []

            # Login automático con sesión única
            login_single_session(request, user)
            messages.success(
                request,
                '¡Listo! Tu correo está verificado. Bienvenido a DockerShield.',
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
        elif err == 'email_tomado':
            messages.error(
                request,
                'Ese correo fue registrado mientras verificabas. Inicia sesión.',
            )
            return redirect('login')
        else:
            messages.error(request, 'No se pudo verificar el código.')

    return render(request, 'accounts/verificar_correo.html', {
        'token':       token,
        'email':       pr.email,
        'expires_at':  pr.expires_at,
    })


# ═════════════════════════════════════════════════════════════════════
#  REENVIAR CÓDIGO DE VERIFICACIÓN
# ═════════════════════════════════════════════════════════════════════

def reenviar_codigo_view(request, token):
    """Genera un nuevo código (con cooldown) y manda otro correo."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    pr_old = get_pending_by_token_any(token)
    if pr_old is None:
        messages.error(request, 'Enlace inválido. Vuelve a registrarte.')
        return redirect('registro')

    # Si entre medias el correo se registró por otra vía (otra pestaña),
    # ya no tiene sentido reenviar — mandamos al login.
    if User.objects.filter(email__iexact=pr_old.email).exists():
        messages.info(request, 'Ese correo ya estaba verificado. Inicia sesión.')
        return redirect('login')

    # Cooldown desde el último pending de este email
    ok, secs = can_resend_pending(pr_old)
    if not ok:
        messages.error(
            request,
            f'Espera {secs} segundo(s) antes de pedir otro código.',
        )
        return redirect('verificar_correo', token=token)

    # Generamos un NUEVO pending (invalida el anterior dentro del service).
    # Reusamos los mismos datos (first_name + password ya hasheado) → no
    # podemos llamar create_pending_registration porque rehashea; en
    # cambio creamos directamente.
    from .models import PendingRegistration
    from .services.pending_registration_service import (
        _generate_code, TOKEN_BYTES, CODE_VALIDITY_MINUTES,
        MAX_PENDING_PER_HOUR,
    )
    from datetime import timedelta
    last_hour = timezone.now() - timedelta(hours=1)
    recent = PendingRegistration.objects.filter(
        email__iexact=pr_old.email, created_at__gte=last_hour,
    ).count()
    if recent >= MAX_PENDING_PER_HOUR:
        messages.error(
            request,
            'Has pedido demasiados códigos. Espera unos minutos.',
        )
        return redirect('verificar_correo', token=token)

    PendingRegistration.objects.filter(
        email__iexact=pr_old.email, used_at__isnull=True,
    ).update(used_at=timezone.now())

    import secrets
    pr_new = PendingRegistration.objects.create(
        email=pr_old.email,
        first_name=pr_old.first_name,
        password_hash=pr_old.password_hash,
        code=_generate_code(),
        token=secrets.token_urlsafe(TOKEN_BYTES),
        expires_at=timezone.now() + timedelta(minutes=CODE_VALIDITY_MINUTES),
    )

    # Mantenemos el tracking de tokens en la sesión
    pending_tokens = request.session.get('pending_registration_tokens', [])
    if pr_new.token not in pending_tokens:
        pending_tokens.append(pr_new.token)
        request.session['pending_registration_tokens'] = pending_tokens

    import threading
    threading.Thread(
        target=send_pending_registration_email,
        args=[pr_new], daemon=True,
    ).start()
    messages.success(request, 'Te enviamos un código nuevo. Revisa tu correo.')
    return redirect('verificar_correo', token=pr_new.token)


# ═════════════════════════════════════════════════════════════════════
#  LOGOUT
# ═════════════════════════════════════════════════════════════════════

def logout_view(request):
    logout(request)
    return redirect('login')


# ═════════════════════════════════════════════════════════════════════
#  RECUPERAR CONTRASEÑA — paso 1: pedir el correo y enviar el link
# ═════════════════════════════════════════════════════════════════════

def recuperar_view(request):
    """
    GET  → muestra el formulario.
    POST → valida el email, busca al usuario en BD y envía el correo
           si existe. Si no existe, muestra error.
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
            return render(request, 'accounts/recuperar.html', {'form_values': form_values})

        try:
            user = User.objects.get(email__iexact=email_clean)
        except User.DoesNotExist:
            messages.error(request, "No encontramos una cuenta registrada con ese correo.")
            return render(request, 'accounts/recuperar.html', {'form_values': form_values})

        token = create_token(user, ip=get_client_ip(request))
        if token is not None:
            send_reset_email(user, token)

        return render(request, 'accounts/recuperar.html', {
            'form_values': {'email': ''},
            'submitted':   True,
            'sent_to':     email_clean,
        })

    return render(request, 'accounts/recuperar.html', {'form_values': form_values})


# ═════════════════════════════════════════════════════════════════════
#  RECUPERAR CONTRASEÑA — paso 2: nueva contraseña con token válido
# ═════════════════════════════════════════════════════════════════════

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

    return render(request, 'accounts/reset_password.html', {
        'token':        token,
        'email':        t.user.email,
        'field_errors': field_errors,
    })


# ═════════════════════════════════════════════════════════════════════
#  CAMBIAR CONTRASEÑA (form propio con validación Django)
# ═════════════════════════════════════════════════════════════════════

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

    return render(request, "accounts/cambiar_password.html", {"form": form})


# ═════════════════════════════════════════════════════════════════════
#  PERFIL DEL USUARIO
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def perfil_view(request):
    """
    GET  → render con datos y stats del usuario.
    POST → dispatch por `form_type`:
         · 'info'     → cambio de nombre de usuario
         · 'password' → cambio de contraseña
         · 'avatar'   → subir nueva foto
         · 'avatar_remove' → quitar foto (volver a default)
         · 'forward_safe' → toggle de auto-forward de correos seguros
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
            from .models import UserProfile
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
    return render(request, 'accounts/perfil.html', ctx)


# ═════════════════════════════════════════════════════════════════════
#  ELIMINAR CUENTA — Flujo de 2 pasos con código por email + soft delete
#
#  Paso 1 (eliminar_cuenta_request):
#      Valida password + texto "ELIMINAR".
#      Genera código de 6 dígitos.
#      Envía el código al correo del usuario.
#      Devuelve {ok: true} para que el frontend pase al paso 2.
#
#  Paso 2 (eliminar_cuenta_confirmar):
#      Recibe el código de 6 dígitos.
#      Verifica contra el último código activo del usuario.
#      Marca profile.is_deleted = True (SOFT DELETE — no borra datos).
#      Cierra sesión y manda el correo "Tu cuenta fue eliminada".
#
#  Soft delete (vs hard delete que había antes):
#      - User.is_active = False
#      - UserProfile.is_deleted = True
#      - UserProfile.deleted_at = now
#      - Datos (alias, correos, análisis) quedan en BD para auditoría /
#        eventual recuperación.
#      - El middleware de auth + login bloquean cualquier intento de
#        entrar mientras is_deleted = True.
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
@require_POST
def eliminar_cuenta_request(request):
    """Paso 1: valida password+confirmación y envía el código por email."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _err(msg, status=400):
        if is_ajax:
            return JsonResponse({'ok': False, 'error': msg}, status=status)
        messages.error(request, msg)
        return redirect('perfil')

    if request.user.is_superuser or request.user.is_staff:
        return _err(
            'Las cuentas administrativas no se pueden eliminar desde aquí. '
            'Contacta a otro administrador.',
            status=403,
        )

    password = request.POST.get('password', '')
    if not password:
        return _err('Debes ingresar tu contraseña para confirmar.')
    if not request.user.check_password(password):
        return _err('La contraseña es incorrecta.', status=401)

    confirm = (request.POST.get('confirm_text') or '').strip().upper()
    if confirm != 'ELIMINAR':
        return _err('Debes escribir ELIMINAR para confirmar.')

    # Rate limit + cooldown
    can_send, wait_secs = can_resend(request.user, purpose='delete_account')
    if not can_send:
        return _err(
            f'Espera {wait_secs} segundos antes de pedir otro código.',
            status=429,
        )

    # Generar código de 10 minutos
    ev = create_verification_code(request.user, purpose='delete_account')
    if ev is None:
        return _err(
            'Demasiadas solicitudes en la última hora. Intenta más tarde.',
            status=429,
        )

    # Enviar el correo con el código (en thread para no bloquear)
    import threading
    display_name = (request.user.first_name or request.user.email or 'Usuario').strip()
    threading.Thread(
        target=send_deletion_code_email,
        kwargs=dict(
            to_email     = request.user.email,
            display_name = display_name,
            code         = ev.code,
            minutes      = 10,
        ),
        daemon=True,
    ).start()

    if is_ajax:
        return JsonResponse({
            'ok': True,
            'message': 'Código enviado a tu correo. Tenés 10 minutos para usarlo.',
        })
    messages.info(request, 'Te enviamos un código a tu correo para confirmar.')
    return redirect('perfil')


@login_required(login_url='login')
@require_POST
def eliminar_cuenta_confirmar(request):
    """Paso 2: valida el código y aplica el soft delete."""
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _err(msg, status=400, code_state=''):
        if is_ajax:
            payload = {'ok': False, 'error': msg}
            if code_state:
                payload['code_state'] = code_state
            return JsonResponse(payload, status=status)
        messages.error(request, msg)
        return redirect('perfil')

    if request.user.is_superuser or request.user.is_staff:
        return _err(
            'Las cuentas administrativas no se pueden eliminar desde aquí.',
            status=403,
        )

    code_input = (request.POST.get('code') or '').strip()
    if not code_input:
        return _err('Ingresa el código que te llegó al correo.')

    ok, err_kind = verify_deletion_code(request.user, code_input)
    if not ok:
        messages_map = {
            'no_encontrado': 'No hay código pendiente. Vuelve a iniciar el proceso.',
            'expirado':      'El código expiró. Vuelve a iniciar el proceso para recibir uno nuevo.',
            'demasiados':    'Demasiados intentos fallidos. Vuelve a iniciar el proceso.',
            'incorrecto':    'El código es incorrecto. Verifica que lo copiaste bien.',
        }
        return _err(messages_map.get(err_kind, 'Código inválido.'),
                    status=400, code_state=err_kind)

    # ── Hard delete físico ───────────────────────────────────────────
    user = request.user

    # Snapshot antes de eliminar
    snapshot_email   = user.email
    snapshot_display = (user.first_name or user.email or 'Usuario').strip()
    stats_snapshot   = profile_stats(user)
    deleted_at_str   = timezone.localtime().strftime('%d/%m/%Y · %H:%M')
    client_ip        = get_client_ip(request)

    # Enviar email de resumen ANTES de borrar (si falla, no se borra nada)
    ok, _ = send_account_deleted_email(
        to_email       = snapshot_email,
        display_name   = snapshot_display,
        alias_count    = stats_snapshot.get('alias_count', 0),
        total_emails   = stats_snapshot.get('total_emails', 0),
        threats_count  = stats_snapshot.get('threats_count', 0),
        deleted_at_str = deleted_at_str,
        ip             = client_ip,
    )
    if not ok:
        return _err('No se pudo enviar el correo de confirmación. Intenta de nuevo.')

    # Borrar archivos físicos
    try:
        profile = user.profile
        if profile.avatar and os.path.exists(profile.avatar.path):
            os.remove(profile.avatar.path)
    except Exception:
        pass

    att_dir = os.path.join(settings.MEDIA_ROOT, 'attachments', str(user.id))
    if os.path.exists(att_dir):
        shutil.rmtree(att_dir)

    # Hard-delete (cascade borra todo: UserProfile, Alias, EmailMessage,
    # Notification, Draft, SentEmail, UserSession, AccountLock, etc.)
    user_id = user.id
    user.delete()
    logout(request)

    if is_ajax:
        return JsonResponse({'ok': True, 'redirect': '/'})

    messages.success(request, 'Tu cuenta ha sido eliminada.')
    return redirect('login')


# Alias retro-compat: la URL antigua 'eliminar_cuenta' ahora apunta al
# paso 1 (request). El nombre se mantiene para no romper templates ni
# reverse() en el código viejo.
eliminar_cuenta = eliminar_cuenta_request
