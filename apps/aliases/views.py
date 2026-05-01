"""
Vistas CRUD de alias desechables:
  - Lista con búsqueda y filtros.
  - Crear nuevo alias.
  - Destruir (marcar inactivo).
  - Componer y enviar correo desde un alias.
"""
import re

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Alias
from .services.alias_service import generate_alias_address, generate_creative_label


# Cuántos alias ACTIVOS puede tener un usuario común al mismo tiempo.
# Los destruidos (is_active=False) no cuentan — quedan en la BD por
# seguridad (el address no se puede reutilizar gracias a unique=True)
# pero el usuario puede crear otros nuevos en su lugar.
# Los administradores (is_staff) NO tienen límite.
ALIAS_LIMIT_PER_USER = 5


@login_required(login_url='login')
def alias_list_view(request):
    """
    Lista todos los alias del usuario con sus contadores anotados
    (correos totales, amenazas) para la UI.
    """
    # Ojo: los nombres de anotaciones NO pueden empezar con "_"
    # porque Django templates rechaza variables con underscore inicial.
    aliases = Alias.objects.filter(user=request.user).annotate(
        emails_total  = Count('emails'),
        threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
    ).order_by('-created_at')

    active_count    = sum(1 for a in aliases if a.is_active)
    destroyed_count = sum(1 for a in aliases if not a.is_active)
    total_emails    = sum(a.emails_total for a in aliases)
    total_threats   = sum(a.threats_total for a in aliases)

    # Para la UI: cuántos alias puede crear todavía + límite total
    is_unlimited     = request.user.is_staff
    alias_limit      = None if is_unlimited else ALIAS_LIMIT_PER_USER
    alias_remaining  = None if is_unlimited else max(0, ALIAS_LIMIT_PER_USER - active_count)

    return render(request, 'alias.html', {
        'aliases':         aliases,
        'active_count':    active_count,
        'destroyed_count': destroyed_count,
        'total_emails':    total_emails,
        'total_threats':   total_threats,
        'alias_limit':     alias_limit,
        'alias_remaining': alias_remaining,
        'is_unlimited':    is_unlimited,
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
        if not request.user.is_staff:
            active_count = Alias.objects.filter(
                user=request.user, is_active=True,
            ).count()
            if active_count >= ALIAS_LIMIT_PER_USER:
                messages.error(
                    request,
                    f'Has alcanzado el límite de {ALIAS_LIMIT_PER_USER} alias '
                    f'activos. Destruye alguno antes de crear uno nuevo.',
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

# Validador básico de email (suficiente para UX; SendGrid valida del lado real)
_EMAIL_RX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


# Etiquetas y atributos peligrosos que removemos del HTML enviado por
# el editor visual antes de mandarlo. Es una sanitización mínima — los
# clientes de correo serios también filtran scripts, pero conviene no
# permitir vectores triviales (script, iframe, on*=).
_HTML_DANGEROUS_TAG_RX = re.compile(
    r'<\s*/?\s*(script|iframe|object|embed|form|meta|link|style|base)\b[^>]*>',
    re.IGNORECASE | re.DOTALL,
)
_HTML_ON_ATTR_RX     = re.compile(r'\son\w+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)', re.IGNORECASE)
_HTML_JS_HREF_RX     = re.compile(r'(href|src)\s*=\s*("javascript:[^"]*"|\'javascript:[^\']*\')', re.IGNORECASE)

# Límites del envío
MAX_TOTAL_ATTACHMENT_BYTES = 25 * 1024 * 1024   # 25 MB total
MAX_ATTACHMENTS            = 10
ALLOWED_ATTACHMENT_NAME_RX = re.compile(r'[^A-Za-z0-9._\- ()áéíóúüñÁÉÍÓÚÜÑ]+')


def _sanitize_html(html: str) -> str:
    """
    Limpieza mínima del HTML que viene del editor:
      - Quita <script>, <iframe>, <object>, <embed>, <form>, <meta>, <link>, <style>, <base>.
      - Quita atributos on* (onclick, onerror, etc.).
      - Quita href="javascript:..." y src="javascript:...".
    No es un sanitizador completo (eso requeriría Bleach), pero bloquea
    los vectores comunes de XSS al enviar correo a otros.
    """
    if not html:
        return ''
    cleaned = _HTML_DANGEROUS_TAG_RX.sub('', html)
    cleaned = _HTML_ON_ATTR_RX.sub('', cleaned)
    cleaned = _HTML_JS_HREF_RX.sub(r'\1=""', cleaned)
    return cleaned


def _safe_filename(name: str) -> str:
    """Limpia el nombre de archivo del adjunto (anti path traversal + chars raros)."""
    name = (name or 'archivo').strip()
    name = name.replace('\\', '/').split('/')[-1]            # quita rutas
    name = ALLOWED_ATTACHMENT_NAME_RX.sub('_', name)         # solo chars seguros
    return (name or 'archivo')[:120]


@login_required(login_url='login')
@require_POST
def alias_compose_view(request, pk):
    """
    Envía un correo desde un alias activo del usuario.

    POST multipart/form-data:
        to:           destinatario (email)
        subject:      asunto
        message_html: cuerpo HTML del editor (rico) — sanitizado en backend
        attachments: archivos múltiples (input type="file" multiple)

    Solo el dueño del alias puede enviar desde él, y solo si está activo.
    """
    alias = get_object_or_404(Alias, pk=pk, user=request.user)

    if not alias.is_active:
        return JsonResponse({
            'ok': False,
            'error': 'Este alias está destruido. Crea uno nuevo para enviar correos.',
        }, status=400)

    to            = (request.POST.get('to', '') or '').strip().lower()
    subject       = (request.POST.get('subject', '') or '').strip()
    message_html  = (request.POST.get('message_html', '') or '').strip()
    scheduled_at  = (request.POST.get('scheduled_at', '') or '').strip()
    # Versión texto plano del mensaje (la mandamos como respaldo y se
    # usa para validaciones de "no vacío", ya que el editor produce
    # `<p><br></p>` aunque el usuario no escriba nada).
    import re as _re
    plain_text = _re.sub(r'<[^>]+>', '', message_html).strip()

    # ── Validaciones ──────────────────────────────────────────────────
    errors = {}
    if not to:
        errors['to'] = 'Ingresa el correo del destinatario.'
    elif len(to) > 254:
        errors['to'] = 'El correo del destinatario es demasiado largo.'
    elif not _EMAIL_RX.match(to):
        errors['to'] = 'El correo del destinatario no es válido.'

    # Asunto opcional: si está vacío usamos un placeholder discreto
    if not subject:
        subject = '(sin asunto)'
    elif len(subject) > 200:
        errors['subject'] = 'El asunto no puede superar 200 caracteres.'

    if not plain_text:
        errors['message'] = 'El mensaje no puede estar vacío.'
    elif len(message_html) > 200000:
        errors['message'] = 'El mensaje supera el tamaño máximo.'

    # Anti auto-envío: no permitimos mandar a la propia dirección del alias
    if to and to == alias.address.lower():
        errors['to'] = 'No puedes enviarte un correo a ti mismo desde este alias.'

    # ── Validar adjuntos ──────────────────────────────────────────────
    uploaded_files = request.FILES.getlist('attachments')
    if len(uploaded_files) > MAX_ATTACHMENTS:
        errors['attachments'] = f'Máximo {MAX_ATTACHMENTS} adjuntos por correo.'

    total_bytes = sum(f.size for f in uploaded_files)
    if total_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
        size_mb = MAX_TOTAL_ATTACHMENT_BYTES // (1024 * 1024)
        errors['attachments'] = f'Tamaño total de adjuntos supera {size_mb} MB.'

    # ── Validar fecha programada (opcional) ──────────────────────────
    # Acepta ISO 8601 (datetime-local del browser produce 'YYYY-MM-DDTHH:MM').
    # SendGrid acepta `send_at` hasta ~72 h en el futuro; por encima de
    # eso devuelve 400. Validamos en backend para dar mensaje útil.
    send_at_ts = None
    if scheduled_at:
        from datetime import datetime, timedelta
        try:
            # datetime-local del navegador no incluye zona horaria;
            # asumimos hora LOCAL del servidor (TIME_ZONE de settings).
            dt = datetime.fromisoformat(scheduled_at)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            now = timezone.now()
            # Mín: 60 s en el futuro. Permite programar mismo día (ej. 17:40 → 17:41).
            if dt <= now + timedelta(seconds=60):
                errors['scheduled_at'] = 'La hora ya pasó. Elige al menos 1 minuto en el futuro.'
            elif dt > now + timedelta(hours=72):
                errors['scheduled_at'] = 'No se puede programar más de 72 horas en el futuro.'
            else:
                send_at_ts = int(dt.timestamp())
        except (ValueError, TypeError):
            errors['scheduled_at'] = 'Formato de fecha inválido.'

    if errors:
        return JsonResponse({'ok': False, 'errors': errors}, status=400)

    # ── Construir HTML final (saneamos + envolvemos con marca) ────────
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

    # ── Codificar adjuntos en base64 (formato que pide SendGrid) ─────
    import base64
    sendgrid_attachments = []
    for upload in uploaded_files:
        try:
            content = upload.read()
            sendgrid_attachments.append({
                'filename': _safe_filename(upload.name),
                'content':  base64.b64encode(content).decode('ascii'),
                'type':     upload.content_type or 'application/octet-stream',
            })
        except Exception as e:
            print(f'[compose] no se pudo leer adjunto {upload.name}: {e}')

    # ── Enviar vía SendGrid ──────────────────────────────────────────
    from apps.mail.webhook import _send_via_sendgrid
    from_addr = f'"{alias.label}" <{alias.address}>'
    ok = _send_via_sendgrid(
        from_addr   = from_addr,
        to_email    = to,
        subject     = subject,
        html_body   = body_html,
        attachments = sendgrid_attachments or None,
        send_at     = send_at_ts,
    )

    if not ok:
        return JsonResponse({
            'ok': False,
            'error': 'No se pudo enviar el correo. Intenta de nuevo en unos segundos.',
        }, status=500)

    if send_at_ts:
        # Mensaje del toast en el cliente cuando es envío programado
        from datetime import datetime
        when_local = datetime.fromtimestamp(send_at_ts).strftime('%d %b · %H:%M')
        msg = f'Programado para {when_local}'
    else:
        msg = f'Correo enviado a {to}'

    return JsonResponse({
        'ok':               True,
        'message':          msg,
        'from':             alias.address,
        'attachments_sent': len(sendgrid_attachments),
        'scheduled':        bool(send_at_ts),
        'scheduled_ts':     send_at_ts,
    })
