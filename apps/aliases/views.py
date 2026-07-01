"""
Vistas CRUD de alias desechables:
  - Lista con búsqueda y filtros.
  - Crear nuevo alias.
  - Destruir (marcar inactivo).
  - Componer y enviar correo desde un alias.
  - Solicitar más cupo de alias al administrador.
  - Escaneo de adjuntos con DockerShield.
"""
import os
import re
import tempfile
import time

from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Alias, AliasQuotaRequest
from .services.alias_service import generate_alias_address, generate_creative_label
from .services.attachment_scanner import scan_attachment



# Cuántos alias ACTIVOS puede tener un usuario común al mismo tiempo.
# Los destruidos (is_active=False) no cuentan — quedan en la BD por
# seguridad (el address no se puede reutilizar gracias a unique=True)
# pero el usuario puede crear otros nuevos en su lugar.
# Los administradores (is_staff) NO tienen límite.
ALIAS_LIMIT_PER_USER = 5


def _user_is_unlimited(user) -> bool:
    """
    ¿El usuario puede crear alias sin tope? Es True si:
      - es admin (is_staff), o
      - el admin le concedió acceso ilimitado vía profile.alias_unlimited.
    """
    if user.is_staff:
        return True
    try:
        return bool(user.profile.alias_unlimited)
    except Exception:
        return False


def _user_alias_limit(user) -> int:
    """
    Cupo total de alias para `user` = base + ajuste del admin (puede ser
    negativo). Clamp a 0 mínimo para que un ajuste muy negativo no produzca
    valores negativos. Los usuarios ilimitados no tienen límite — se maneja
    antes de llamar a esto.
    """
    extra = 0
    try:
        extra = int(user.profile.alias_quota_extra or 0)
    except Exception:
        # Si por alguna razón el perfil no existe (raro), usamos el base.
        pass
    return max(0, ALIAS_LIMIT_PER_USER + extra)


ALIAS_BATCH = 6   # alias por "página" en el load-more


def _aliases_qs(user):
    """QuerySet base de alias del usuario con conteos anotados."""
    return (
        Alias.objects.filter(user=user).annotate(
            emails_total  = Count('emails'),
            threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
        ).order_by('-created_at')
    )


@login_required(login_url='login')
def alias_list_view(request):
    """
    Lista de alias con carga diferida. Render inicial: primeros ALIAS_BATCH.
    """
    full_qs = _aliases_qs(request.user)
    total   = full_qs.count()

    aliases  = list(full_qs[:ALIAS_BATCH])
    has_more = total > ALIAS_BATCH

    # ── Agregados sobre TODOS los alias (no solo los visibles) ──────────
    # Para los stats usamos `full_qs.aggregate` y filtros directos en BD
    # — son COUNT() baratos.
    from django.db.models import Sum
    active_count    = full_qs.filter(is_active=True).count()
    destroyed_count = total - active_count

    # Sumas globales (Count anotado por alias × Sum global)
    totals = full_qs.aggregate(
        emails  = Sum('emails_total'),
        threats = Sum('threats_total'),
    )
    total_emails  = totals['emails']  or 0
    total_threats = totals['threats'] or 0

    quota_used       = total
    is_unlimited     = _user_is_unlimited(request.user)
    alias_limit      = None if is_unlimited else _user_alias_limit(request.user)
    alias_remaining  = None if is_unlimited else max(0, alias_limit - quota_used)

    pending_request = None
    if not is_unlimited:
        pending_request = AliasQuotaRequest.objects.filter(
            user=request.user, status='pending',
        ).order_by('-created_at').first()

    return render(request, 'aliases/alias.html', {
        'aliases':         aliases,
        'active_count':    active_count,
        'destroyed_count': destroyed_count,
        'quota_used':      quota_used,
        'total_emails':    total_emails,
        'total_threats':   total_threats,
        'alias_limit':     alias_limit,
        'alias_remaining': alias_remaining,
        'is_unlimited':    is_unlimited,
        'pending_request': pending_request,
        'has_more':        has_more,
        'next_offset':     len(aliases),
        'batch_size':      ALIAS_BATCH,
    })


@login_required(login_url='login')
def alias_more_api(request):
    """Siguiente lote de alias como HTML parcial. Espera `?offset=N`."""
    try:
        offset = int(request.GET.get('offset') or 0)
    except ValueError:
        offset = 0
    offset = max(0, offset)

    qs = _aliases_qs(request.user)
    total = qs.count()
    batch = list(qs[offset:offset + ALIAS_BATCH])

    from django.template.loader import render_to_string
    html = render_to_string(
        'aliases/_alias_rows.html',
        {'aliases': batch, 'offset': offset},
        request=request,
    )

    new_offset = offset + len(batch)
    return JsonResponse({
        'ok':          True,
        'html':        html,
        'count':       len(batch),
        'next_offset': new_offset,
        'has_more':    new_offset < total,
    })


@login_required(login_url='login')
def alias_create_view(request):
    """
    Crea un nuevo alias con etiqueta y dirección 100% autogeneradas.

    El usuario NO escribe nada — el sistema genera una etiqueta creativa
    (adjetivo + sustantivo, ej: 'silver-tiger') y la convierte en una
    dirección única tipo 'silver-tiger_x7k2m@dockershield.lat'.

    Esto evita por completo cualquier riesgo de palabras vulgares,
    información personal o etiquetas ofensivas.
    """
    if request.method == 'POST':
        # Defensa anti doble-submit + anti abuso: chequea el límite SIEMPRE
        # en el backend (el JS del front solo es UX, no se debe confiar).
        # El cupo se cuenta sobre TODOS los alias creados (activos +
        # destruidos), no solo los activos — los slots se consumen al
        # crear y no se reciclan al destruir.
        if not _user_is_unlimited(request.user):
            quota_used = Alias.objects.filter(user=request.user).count()
            user_limit = _user_alias_limit(request.user)
            if quota_used >= user_limit:
                messages.error(
                    request,
                    f'Has consumido tu cupo de {user_limit} alias. '
                    f'Solicítale más al administrador para seguir creando.',
                )
                return redirect('alias_list')

        # Genera etiqueta creativa (silver-tiger, cosmic-falcon, etc.) y
        # dirección única. Si por mala suerte la dirección ya existe en
        # la BD (colisión muy improbable: ~36^6 = 2.000M combinaciones
        # por etiqueta), reintentamos hasta 5 veces.
        for _ in range(5):
            label   = generate_creative_label()
            address = generate_alias_address(label)
            if not Alias.objects.filter(address=address).exists():
                break
        else:
            messages.error(request, 'No se pudo generar un alias único. Inténtalo de nuevo.')
            return redirect('alias_list')

        Alias.objects.create(
            user=request.user,
            label=label,
            address=address,
        )
        messages.success(request, f'Alias creado: {address}')

    return redirect('alias_list')


@login_required(login_url='login')
def alias_destroy_view(request, pk):
    """Marca un alias como inactivo (soft delete)."""
    alias = get_object_or_404(Alias, pk=pk, user=request.user)
    if request.method == 'POST':
        alias.is_active   = False
        alias.destroyed_at = timezone.now()
        alias.save()
        messages.success(
            request, f'Alias {alias.address} destruido correctamente.',
        )
    return redirect('alias_list')


# ─────────────────────────────────────────────────────────────────────
#  COMPOSE: enviar correo desde un alias
# ─────────────────────────────────────────────────────────────────────

_EMAIL_RX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)

_HTML_DANGEROUS_TAG_RX = re.compile(
    r'<\s*/?\s*(script|iframe|object|embed|form|meta|link|style|base)\b[^>]*>',
    re.IGNORECASE | re.DOTALL,
)
_HTML_ON_ATTR_RX = re.compile(r'\son\w+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', re.IGNORECASE)
_HTML_JS_HREF_RX = re.compile(r'(href|src)\s*=\s*("javascript:[^"]*"|\'javascript:[^\']*\')', re.IGNORECASE)

MAX_TOTAL_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ATTACHMENTS            = 10
MAX_RECIPIENTS             = 50
ALLOWED_ATTACHMENT_NAME_RX = re.compile(r'[^A-Za-z0-9.\-_ ()áéíóúüñÁÉÍÓÚÜÑ]+')




def _parse_recipients(raw: str) -> list:
    """Acepta destinatarios separados por coma, punto y coma o espacios.
    Devuelve la lista deduplicada en minúsculas, en el orden original."""
    parts = re.split(r'[,;\s]+', (raw or '').strip().lower())
    seen, out = set(), []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _sanitize_html(html: str) -> str:
    if not html:
        return ''
    cleaned = _HTML_DANGEROUS_TAG_RX.sub('', html)
    cleaned = _HTML_ON_ATTR_RX.sub('', cleaned)
    cleaned = _HTML_JS_HREF_RX.sub(r'\1=""', cleaned)
    return cleaned


def _safe_filename(name: str) -> str:
    name = (name or 'archivo').strip()
    name = name.replace('\\', '/').split('/')[-1]
    name = ALLOWED_ATTACHMENT_NAME_RX.sub('_', name)
    return (name or 'archivo')[:120]


# ════════════════════════════════════════════════════════════════════════
#  NOTIFICACIÓN A ADMIN + BLOQUEO POR ABUSO (adjuntos maliciosos)
# ════════════════════════════════════════════════════════════════════════


def _notify_admin_attachment_abuse(user, filename, report, previous_data=None):
    """
    Notifica a todos los admins cuando un usuario es bloqueado por
    intentar adjuntar malware repetidamente. Incluye detalles de ambos intentos.
    """
    try:
        from apps.notifications.models import Notification
        from django.contrib.auth.models import User

        admins = User.objects.filter(is_staff=True, is_active=True)
        if not admins:
            return

        user_name = user.get_full_name() or user.email or user.username

        # Intento actual (2º)
        threat2 = report.get('threat_name', 'Desconocido')
        score2 = report.get('risk_score', 0)
        yara2 = len(report.get('yara_matches', []))
        risk2 = report.get('risk_level', 'unknown')

        title = 'Cuenta bloqueada por intento de adjuntar malware'

        msg = f'Usuario: {user_name} ({user.email})\n'
        msg += '═══════════════════════════════════════════\n'
        msg += 'RESUMEN DE LA CUENTA BLOQUEADA\n'
        msg += '═══════════════════════════════════════════\n\n'

        # Intento 1 (desde previous_data)
        if previous_data:
            msg += (
                f'◈ Intento 1 — {previous_data.get("timestamp", "—")}\n'
                f'  Archivo: {previous_data.get("filename", "—")}\n'
                f'  Amenaza: {previous_data.get("threat", "Desconocido")}\n'
                f'  Score: {previous_data.get("score", 0)} | '
                f'YARA: {previous_data.get("yara_count", 0)} | '
                f'Nivel: {previous_data.get("risk_level", "unknown")}\n'
                f'  Acción: Archivo rechazado, 1ª advertencia registrada.\n\n'
            )
        else:
            msg += '◈ Intento 1 — (sin datos previos)\n\n'

        # Intento 2 (actual)
        msg += (
            f'◈ Intento 2 — {timezone.now().isoformat()}\n'
            f'  Archivo: {filename}\n'
            f'  Amenaza: {threat2}\n'
            f'  Score: {score2} | YARA: {yara2} | Nivel: {risk2}\n'
            f'  Acción: Cuenta bloqueada permanentemente.\n'
            f'  Sesión cerrada.\n'
            f'  Redirigido al login.\n'
            f'  El usuario deberá contactar al administrador para recuperar el acceso.\n'
        )

        Notification.objects.bulk_create([
            Notification(
                user=admin, type='system', title=title,
                message=msg, status='pending', read=False,
            )
            for admin in admins
        ])
    except Exception as e:
        print(f'[_notify_admin_attachment_abuse] Error: {e}')


def _block_user_for_abuse(user):
    """
    Bloquea la cuenta de `user` por intento repetido de adjuntar malware:
      - Desactiva user.is_active
      - Marca permanent_lock en AccountLock para que login_view muestre
        el modal de "Solicitar recuperación" (sin contar intentos fallidos)
      - Cierra su sesión activa
    La notificación a admins la hace el caller.
    """
    user.is_active = False
    user.save(update_fields=['is_active'])
    try:
        from django.utils import timezone
        from apps.accounts.models import AccountLock
        lock, _ = AccountLock.objects.get_or_create(profile=user.profile)
        lock.permanent_lock_at = timezone.now()
        lock.permanent_lock_reason = (
            'Cuenta bloqueada automáticamente por intentar adjuntar '
            'archivos maliciosos a correos salientes. '
            'Contacta al administrador para recuperar el acceso.'
        )
        lock.save(update_fields=['permanent_lock_at', 'permanent_lock_reason'])
    except Exception:
        pass
    try:
        from django.contrib.sessions.models import Session
        session_key = user.profile.session.current_session_key
        if session_key:
            Session.objects.filter(session_key=session_key).delete()
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════════
#  ESCANEO DE ADJUNTOS CON DOCKERSHIELD
# ════════════════════════════════════════════════════════════════════════


@login_required(login_url='login')
@require_POST
def attachment_scan_api(request):
    """
    POST /alias/attachment-scan/
    Recibe un archivo vía multipart/form-data (`file`), lo pasa por el
    sandbox DockerShield y devuelve el veredicto.

    Si es malicioso (risk_level = critical|high):
      - 1ª vez:           {ok: false, error, attempts: 1}
      - 2ª vez o más:     {ok: false, error, blocked: true}
      El servidor además incrementa el contador y (en la 2ª) bloquea la
      cuenta y notifica al admin.

    Si es seguro o análisis falla: {ok: true, risk_level, risk_score}

    Si el archivo está protegido con contraseña:
      - Sin password: {ok: false, password_protected: true, filename, risk_score}
      - Con password: re-analiza con run_sandbox_with_password
    """
    if 'file' not in request.FILES:
        return JsonResponse({'ok': False, 'error': 'No se envió ningún archivo.'}, status=400)

    upload = request.FILES['file']
    if upload.size == 0:
        return JsonResponse({'ok': False, 'error': 'El archivo está vacío.'}, status=400)

    password = request.POST.get('password', '').strip()
    skip_malicious_counter = bool(password)
    session_key = None

    suffix = os.path.splitext(upload.name)[1] or '.bin'
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        for chunk in upload.chunks():
            tmp.write(chunk)
        tmp.close()

        if password:
            # ── Re-análisis con contraseña (desbloqueo) ──
            # Rate limit: 3 intentos / 10 min por filename
            session_key = f'unlock_attempts_compose_{upload.name}'
            now_ts = time.time()
            attempt_data = request.session.get(session_key)
            if isinstance(attempt_data, dict):
                attempts = attempt_data.get('count', 0)
                first_time = attempt_data.get('time', 0)
                if attempts >= 3 and (now_ts - first_time) < 600:
                    return JsonResponse({
                        'ok': False,
                        'error': 'Demasiados intentos. Esperá unos minutos.',
                    }, status=429)
                if (now_ts - first_time) >= 600:
                    attempts = 0
            else:
                attempts = 0

            from apps.sandbox.service import run_sandbox_with_password
            report = run_sandbox_with_password(tmp.name, password)

            if not report:
                return JsonResponse({'ok': False, 'error': 'Error al re-analizar el archivo.'}, status=500)

            # Normalizar risk_level como lo hace scan_attachment
            score = report.get('risk_score', 0)
            rl = report.get('risk_level')
            if score > 0 and rl in ('safe', 'unknown', None):
                if score >= 90:
                    report['risk_level'] = 'critical'
                elif score >= 70:
                    report['risk_level'] = 'high'
                elif score >= 40:
                    report['risk_level'] = 'medium'
                else:
                    report['risk_level'] = 'low'
            if report.get('risk_level') == 'malware':
                report['risk_level'] = 'critical'
            elif report.get('risk_level') == 'suspicious':
                report['risk_level'] = 'high'

            # Verificar si sigue protegido (contraseña incorrecta)
            still_protected = any(
                ev.get('type') == 'password_protected'
                for ev in (report.get('evidence') or [])
            )
            if still_protected:
                request.session[session_key] = {
                    'count': attempts + 1,
                    'time': now_ts if attempts == 0 else attempt_data['time'],
                }
                remaining = max(0, 3 - (attempts + 1))
                error_msg = 'Contraseña incorrecta.'
                if remaining > 0:
                    error_msg += f' Intentos restantes: {remaining}.'
                return JsonResponse({
                    'ok': False,
                    'password_protected': True,
                    'filename': upload.name,
                    'risk_score': report.get('risk_score', 50),
                    'error': error_msg,
                })

            # Continuar al veredicto normal
            risk_level = report.get('risk_level', 'unknown')

        else:
            # ── Escaneo normal (sin contraseña) ──
            report = scan_attachment(tmp.name)

            # Detectar si está protegido con contraseña
            is_password_protected = any(
                ev.get('type') == 'password_protected'
                for ev in (report.get('evidence') or [])
            )
            if is_password_protected:
                return JsonResponse({
                    'ok': False,
                    'password_protected': True,
                    'filename': upload.name,
                    'risk_score': report.get('risk_score', 50),
                })

            risk_level = report.get('risk_level', 'unknown')

        # ── Veredicto común ──
        is_malicious = risk_level in ('critical', 'high')
        is_warning = risk_level == 'warning'

        if is_warning:
            return JsonResponse({
                'ok': False,
                'error': f'El archivo "{upload.name}" contiene elementos sospechosos y no puede adjuntarse.',
                'warning': True,
                'risk_level': risk_level,
                'risk_score': report.get('risk_score'),
                'threat_name': report.get('threat_name'),
            })

        # Detectar si el sandbox no está disponible (Docker apagado)
        has_service_error = any(
            e.get('type') == 'service_error'
            for e in report.get('evidence', [])
        )
        if not is_malicious and has_service_error:
            return JsonResponse({
                'ok': False,
                'error': 'El contenedor DockerShield no está disponible. No se puede analizar el adjunto. Intenta de nuevo más tarde.',
                'sandbox_down': True,
            })

        result = {
            'ok': not is_malicious,
            'risk_level': risk_level,
            'risk_score': report.get('risk_score'),
            'threat_name': report.get('threat_name'),
        }

        if is_malicious:
            if skip_malicious_counter:
                result['error'] = (
                    report.get('threat_name')
                    or 'El archivo contiene malware y no puede adjuntarse.'
                )
            else:
                profile = request.user.profile
                profile.malicious_attachment_attempts += 1
                profile.save(update_fields=['malicious_attachment_attempts'])

                result['attempts'] = profile.malicious_attachment_attempts

                if profile.malicious_attachment_attempts >= 2:
                    _block_user_for_abuse(request.user)
                    result['blocked'] = True
                    result['error'] = (
                        'Has intentado adjuntar un archivo malicioso repetidamente. '
                        'Tu cuenta ha sido bloqueada por seguridad.'
                    )
                    _notify_admin_attachment_abuse(
                        request.user, upload.name, report,
                        previous_data=profile.malicious_attempt_data,
                    )
                    profile.malicious_attempt_data = {}
                    profile.save(update_fields=['malicious_attempt_data'])
                else:
                    result['error'] = (
                        report.get('threat_name')
                        or 'Archivo potencialmente malicioso detectado por DockerShield.'
                    )
                    profile.malicious_attempt_data = {
                        'filename': upload.name,
                        'threat': report.get('threat_name', 'Desconocido'),
                        'score': report.get('risk_score', 0),
                        'yara_count': len(report.get('yara_matches', [])),
                        'risk_level': risk_level,
                        'timestamp': timezone.now().isoformat(),
                    }
                    profile.save(update_fields=['malicious_attempt_data'])

        # Resetear intentos de desbloqueo si hubo password y no hay bloqueo
        if session_key and session_key in request.session:
            del request.session[session_key]

        return JsonResponse(result)
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


@login_required(login_url='login')
@require_POST
def alias_compose_view(request, pk):
    """Envía un correo desde un alias activo del usuario."""
    alias = get_object_or_404(Alias, pk=pk, user=request.user)

    if not alias.is_active:
        return JsonResponse({
            'ok': False,
            'error': 'Este alias está destruido. Crea uno nuevo para enviar correos.',
        }, status=400)

    raw_to        = (request.POST.get('to', '') or '').strip()
    subject       = (request.POST.get('subject', '') or '').strip()
    message_html  = (request.POST.get('message_html', '') or '').strip()
    scheduled_at  = (request.POST.get('scheduled_at', '') or '').strip()
    plain_text = re.sub(r'<[^>]+>', '', message_html).strip()

    recipients = _parse_recipients(raw_to)
    alias_addr_lower = alias.address.lower()

    errors = {}
    if not recipients:
        errors['to'] = 'Ingresa el correo del destinatario.'
    elif len(recipients) > MAX_RECIPIENTS:
        errors['to'] = f'Máximo {MAX_RECIPIENTS} destinatarios por correo.'
    else:
        invalid = [r for r in recipients if len(r) > 254 or not _EMAIL_RX.match(r)]
        if invalid:
            shown = ', '.join(invalid[:3])
            errors['to'] = f'Correo(s) no válido(s): {shown}'
        elif alias_addr_lower in recipients:
            errors['to'] = 'No puedes enviarte un correo a ti mismo desde este alias.'

    if not subject:
        subject = '(sin asunto)'
    elif len(subject) > 200:
        errors['subject'] = 'El asunto no puede superar 200 caracteres.'

    if not plain_text:
        errors['message'] = 'El mensaje no puede estar vacío.'
    elif len(message_html) > 200000:
        errors['message'] = 'El mensaje supera el tamaño máximo.'

    uploaded_files = request.FILES.getlist('attachments')
    if len(uploaded_files) > MAX_ATTACHMENTS:
        errors['attachments'] = f'Máximo {MAX_ATTACHMENTS} adjuntos por correo.'

    total_bytes = sum(f.size for f in uploaded_files)
    if total_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
        size_mb = MAX_TOTAL_ATTACHMENT_BYTES // (1024 * 1024)
        errors['attachments'] = f'Tamaño total de adjuntos supera {size_mb} MB.'

    send_at_ts = None
    if scheduled_at:
        from datetime import datetime, timedelta
        try:
            dt = datetime.fromisoformat(scheduled_at)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            now = timezone.now()
            # El frontend envía la hora con segundos en cero (granularidad
            # de minutos). Si compararamos contra now + 60s podríamos
            # rechazar el minuto inmediatamente siguiente cuando solo faltan
            # ~30 segundos para cambiar de minuto. Comparamos contra el
            # INICIO DEL PRÓXIMO MINUTO: now.replace(second=0) + 1min.
            next_minute = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
            if dt < next_minute:
                errors['scheduled_at'] = 'La hora ya pasó. Elige al menos 1 minuto en el futuro.'
            elif dt > now + timedelta(hours=72):
                errors['scheduled_at'] = 'No se puede programar más de 72 horas en el futuro.'
            else:
                send_at_ts = int(dt.timestamp())
        except (ValueError, TypeError):
            errors['scheduled_at'] = 'Formato de fecha inválido.'

    if errors:
        return JsonResponse({'ok': False, 'errors': errors}, status=400)

    safe_html = _sanitize_html(message_html)
    body_html = (
        '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,'
        'Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6;'
        'color:#1a1a1a;max-width:640px;margin:0 auto;padding:18px">'
        + safe_html
        + '<hr style="border:none;border-top:1px solid #e5e7eb;margin:22px 0 10px">'
        + '<div style="font-size:11px;color:#9ca3af;font-family:monospace">'
        + 'Enviado desde un alias seguro de DockerShield · ' + alias.address
        + '</div></div>'
    )

    import base64
    resend_attachments = []
    for upload in uploaded_files:
        try:
            content = upload.read()
            resend_attachments.append({
                'filename': _safe_filename(upload.name),
                'content':  base64.b64encode(content).decode('ascii'),
                'type':     upload.content_type or 'application/octet-stream',
            })
        except Exception as e:
            print(f'[compose] no se pudo leer adjunto {upload.name}: {e}')

    from apps.mail.webhook import _send_via_resend
    from_addr = f'"{alias.label}" <{alias.address}>'
    ok = _send_via_resend(
        from_addr   = from_addr,
        to_email    = recipients if len(recipients) > 1 else recipients[0],
        subject     = subject,
        html_body   = body_html,
        attachments = resend_attachments or None,
        send_at     = send_at_ts,
    )

    if not ok:
        return JsonResponse({
            'ok': False,
            'error': 'No se pudo enviar el correo. Intenta de nuevo en unos segundos.',
        }, status=500)

    # Guardar histórico en "Enviados". Si esto falla, no afecta al envío
    # ya completado — solo perdemos el registro local, no el correo real.
    sent_payload = None
    try:
        from apps.mail.models import SentEmail
        from datetime import datetime as _dt
        scheduled_dt = None
        if send_at_ts:
            scheduled_dt = _dt.fromtimestamp(send_at_ts)
            if scheduled_dt.tzinfo is None:
                scheduled_dt = timezone.make_aware(
                    scheduled_dt, timezone.get_current_timezone(),
                )
        # Metadata de adjuntos para mostrarla en la vista del correo enviado.
        # No guardamos el `content` (base64 del archivo) — ya se envió al
        # destinatario y conservarlo inflaría la BD. Solo nombre/tamaño/tipo.
        attachments_meta = []
        for att, upload in zip(resend_attachments, uploaded_files):
            attachments_meta.append({
                'filename': att.get('filename', ''),
                'type':     att.get('type', ''),
                'size':     getattr(upload, 'size', 0),
            })
        sent_obj = SentEmail.objects.create(
            alias=alias,
            to_email=', '.join(recipients)[:2500],
            subject=subject,
            body_html=body_html,
            scheduled_at=scheduled_dt,
            attachments_count=len(resend_attachments),
            attachments_meta=attachments_meta,
        )
        # Payload completo para que el frontend pueda insertar la fila
        # al instante en /enviados/ sin recargar la página.
        sent_payload = {
            'id':                 sent_obj.id,
            'to':                 sent_obj.to_email,
            'subject':            sent_obj.subject,
            'body_html':          sent_obj.body_html,
            'alias':              alias.address,
            'alias_id':           alias.id,
            'alias_label':        alias.label,
            'alias_active':       alias.is_active,
            'sent_at':            sent_obj.sent_at.strftime('%d/%m/%Y %H:%M'),
            'sent_at_iso':        sent_obj.sent_at.isoformat(),
            'scheduled_at':       sent_obj.scheduled_at.strftime('%d/%m/%Y %H:%M') if sent_obj.scheduled_at else '',
            'scheduled_at_short': sent_obj.scheduled_at.strftime('%d/%m %H:%M') if sent_obj.scheduled_at else '',
            'attachments_count':  sent_obj.attachments_count,
            'attachments_meta':   sent_obj.attachments_meta or [],
        }
    except Exception as e:
        print(f'[compose] no se pudo guardar SentEmail: {e}')

    if send_at_ts:
        from datetime import datetime
        when_local = datetime.fromtimestamp(send_at_ts).strftime('%d %b · %H:%M')
        msg = f'Programado para {when_local}'
    elif len(recipients) == 1:
        msg = f'Correo enviado a {recipients[0]}'
    else:
        msg = f'Correo enviado a {len(recipients)} destinatarios'

    return JsonResponse({
        'ok':               True,
        'message':          msg,
        'from':             alias.address,
        'attachments_sent': len(resend_attachments),
        'scheduled':        bool(send_at_ts),
        'scheduled_ts':     send_at_ts,
        'sent':             sent_payload,
    })


# ════════════════════════════════════════════════════════════════════════
#  SOLICITUD DE MÁS CUPO DE ALIAS (usuario → admin)
# ════════════════════════════════════════════════════════════════════════

# Cuántos alias EXTRA puede pedir un usuario en una solicitud. Limitamos
# para que no pidan algo absurdo (ej. +1000); el admin igual modera.
ALIAS_REQUEST_MAX_AMOUNT = 10


@login_required(login_url='login')
@require_POST
def alias_quota_request_create(request):
    """
    POST endpoint donde el usuario crea una solicitud de más cupo de alias.
    Acepta:
        amount  (1 a 10) — cuántos alias extra pide
        reason  (texto, opcional)
    Devuelve JSON: { ok, message, request_id }
    Si ya hay una solicitud `pending` para este usuario, devuelve ok=false.
    """
    # Los admins no piden (no tienen límite). Defensa por si igual lo intentan.
    if request.user.is_staff:
        return JsonResponse({'ok': False, 'error': 'admin_no_quota'}, status=400)

    # Bloquear duplicados: si ya tiene una pending, no aceptamos otra.
    if AliasQuotaRequest.objects.filter(user=request.user, status='pending').exists():
        return JsonResponse({
            'ok': False,
            'error': 'already_pending',
            'message': 'Ya tienes una solicitud pendiente. Espera la respuesta del admin.',
        }, status=400)

    # Parsear amount con tope.
    try:
        amount = int(request.POST.get('amount', '1'))
    except (TypeError, ValueError):
        amount = 0
    if amount < 1 or amount > ALIAS_REQUEST_MAX_AMOUNT:
        return JsonResponse({
            'ok': False,
            'error': 'invalid_amount',
            'message': f'Pide entre 1 y {ALIAS_REQUEST_MAX_AMOUNT} alias adicionales.',
        }, status=400)

    reason = (request.POST.get('reason') or '').strip()[:2000]

    req = AliasQuotaRequest.objects.create(
        user=request.user,
        requested_amount=amount,
        reason=reason,
    )

    # Notificar a TODOS los admins (is_staff=True) — antes solo se subía
    # el badge del sidebar y el admin no veía toast hasta entrar al
    # módulo de solicitudes. Ahora le aparece la notificación en cualquier
    # página del admin via el sistema de toasts persistentes.
    try:
        from apps.notifications.models import Notification
        from django.contrib.auth.models import User
        admins = User.objects.filter(is_staff=True, is_active=True)
        user_name = (request.user.get_full_name() or request.user.email
                     or request.user.username)
        # target_url: que el click del toast/bell abra directo el panel de
        # solicitudes con esta solicitud destacada (modal). Sin esto el toast
        # apuntaba al detalle de la notif y para el admin eso no es útil — el
        # admin quiere VER la solicitud, no leer el mensaje de notif.
        admin_target = f'/admin-panel/solicitudes/?open={req.id}'
        notif_objs = [
            Notification(
                user=admin,
                type='system',
                title='Nueva solicitud de cupo',
                message=f'{user_name} pide +{amount} alias adicionales. Revisa en el panel de solicitudes.',
                status='pending',
                read=False,
                target_url=admin_target,
            )
            for admin in admins
        ]
        if notif_objs:
            Notification.objects.bulk_create(notif_objs)
    except Exception as e:
        # No bloqueamos la creación de la solicitud si la notificación falla.
        print(f"[alias_quota_request] No se pudo notificar al admin: {e}")

    return JsonResponse({
        'ok':         True,
        'message':    'Solicitud enviada. El administrador la revisará en breve.',
        'request_id': req.id,
        'amount':     amount,
    })
