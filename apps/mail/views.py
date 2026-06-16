"""
Vistas del módulo mail:
  - Dashboard principal (render server-side).
  - Bandeja de entrada (render + marcado de leído, vaciar).

Toda la lógica de scoring/sandbox vive en apps.sandbox y apps.mail.webhook.
"""
import re
from datetime import timedelta
from urllib.parse import urlencode

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.aliases.models import Alias
from apps.sandbox.models import SandboxAnalysis
from apps.core.services.stats_service import dashboard_stats
from .models import EmailMessage, SentEmail, Draft


# Items por página en todas las listas. Subir/bajar global desde aquí.
PAGE_SIZE = 6


def _qs_params(request, exclude=('page',)):
    """
    Devuelve los query params actuales como string para preservarlos al
    paginar (excepto los que se quieran sobreescribir, típicamente `page`).
    Ej: si la URL es ?q=hola&filter=unread&page=2 → "q=hola&filter=unread"
    """
    params = {k: v for k, v in request.GET.items() if k not in exclude and v}
    return urlencode(params)


# ═════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def dashboard_view(request):
    """Dashboard principal — métricas + listas recientes."""
    stats = dashboard_stats(request.user)

    aliases         = Alias.objects.filter(user=request.user, is_active=True)[:5]
    # 20 correos = 5 páginas de 4 en la tabla "Actividad reciente".
    # La paginación se hace en el cliente (todas las filas en DOM).
    recent_emails   = list(
        EmailMessage.objects.select_related('alias').filter(
            alias__user=request.user, deleted_at__isnull=True,
        ).order_by('-received_at')[:20]
    )
    # Pre-computamos un timestamp compacto para la columna "Hora" — Django
    # `timesince` devuelve "4 minutos, 30 segundos" y queda feo cuando lo
    # truncamos en el template. Acá decidimos la unidad correcta y la
    # abreviamos en 4-5 chars.
    _now = timezone.now()
    for em in recent_emails:
        delta = _now - em.received_at
        secs = int(delta.total_seconds())
        if   secs < 45:        em.time_short = 'ahora'
        elif secs < 3600:      em.time_short = f'{max(1, secs // 60)} min'
        elif secs < 86400:     em.time_short = f'{secs // 3600} h'
        elif secs < 86400 * 7: em.time_short = f'{secs // 86400} d'
        else:                  em.time_short = f'{secs // (86400*7)} sem'
    recent_analyses = list(
        SandboxAnalysis.objects.select_related('email').filter(
            email__alias__user=request.user
        ).order_by('-analyzed_at')[:3]
    )
    for an in recent_analyses:
        delta = _now - an.analyzed_at
        secs = int(delta.total_seconds())
        if   secs < 45:        an.time_short = 'ahora'
        elif secs < 3600:      an.time_short = f'{max(1, secs // 60)} min'
        elif secs < 86400:     an.time_short = f'{secs // 3600} h'
        elif secs < 86400 * 7: an.time_short = f'{secs // 86400} d'
        else:                  an.time_short = f'{secs // (86400*7)} sem'
    recent_threats  = EmailMessage.objects.select_related('alias').filter(
                          alias__user=request.user, risk_score__gte=61,
                          deleted_at__isnull=True,
                      ).order_by('-received_at')[:3]

    return render(request, 'mail/dashboard.html', {
        'aliases':         aliases,
        'recent_emails':   recent_emails,
        'recent_analyses': recent_analyses,
        'recent_threats':  recent_threats,
        **stats,
    })


# ═════════════════════════════════════════════════════════════════════
#  INBOX
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def inbox_view(request):
    """
    Bandeja de entrada paginada (server-side).

    Query params soportados:
      ?q=<texto>     búsqueda en remitente / asunto / preview
      ?filter=<f>    all | unread | attachment | danger | safe
      ?page=<n>      número de página (PAGE_SIZE items)

    El filtrado y la búsqueda se hacen en BD para que el paginado tenga
    sentido: solo se traen 25 filas por request, no la bandeja entera.
    """
    base_qs = EmailMessage.objects.filter(
        alias__user=request.user, deleted_at__isnull=True,
    )

    # Contadores por categoría (se calculan UNA vez sobre el base_qs y se
    # muestran en los tabs). Son SELECT COUNT — baratos, pero los podemos
    # convertir a aggregate único si la tabla crece mucho.
    counts = {
        'all':        base_qs.count(),
        'unread':     base_qs.filter(read=False).count(),
        'attachment': base_qs.filter(attachment__has_attachment=True).count(),
        'danger':     base_qs.filter(risk_score__gte=61).count(),
        'safe':       base_qs.filter(risk_score__gt=0, risk_score__lte=30).count(),
    }

    qs = base_qs

    # ── Filtro por categoría ───────────────────────────────────────────
    filter_ = (request.GET.get('filter') or 'all').strip().lower()
    if filter_ == 'unread':
        qs = qs.filter(read=False)
    elif filter_ == 'attachment':
        qs = qs.filter(attachment__has_attachment=True)
    elif filter_ == 'danger':
        qs = qs.filter(risk_score__gte=61)
    elif filter_ == 'safe':
        qs = qs.filter(risk_score__gt=0, risk_score__lte=30)
    else:
        filter_ = 'all'

    # ── Búsqueda libre ─────────────────────────────────────────────────
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(from_email__icontains=q) |
            Q(subject__icontains=q) |
            Q(body__icontains=q)
        )

    qs = qs.select_related('alias').order_by('-received_at')

    # ── Paginación ─────────────────────────────────────────────────────
    paginator = Paginator(qs, PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    # Pre-computa un timestamp compacto ("3 d", "53 min", "2 h"…) para la
    # columna "Recibido". `timesince` devuelve cosas largas como "3 días,
    # 4 horas" que quedan feas en una celda.
    _now = timezone.now()
    for em in page_obj.object_list:
        delta = _now - em.received_at
        secs = int(delta.total_seconds())
        if   secs < 45:        em.time_short = 'ahora'
        elif secs < 3600:      em.time_short = f'{max(1, secs // 60)} min'
        elif secs < 86400:     em.time_short = f'{secs // 3600} h'
        elif secs < 86400 * 7: em.time_short = f'{secs // 86400} d'
        else:                  em.time_short = f'{secs // (86400*7)} sem'

    return render(request, 'mail/inbox.html', {
        'page_obj':   page_obj,
        'emails':     page_obj.object_list,    # compat con código que itera flat
        'counts':     counts,
        'q':          q,
        'filter':     filter_,
        'qs_params':  _qs_params(request),
    })


@login_required(login_url='login')
@require_POST
def mark_email_read_api(request, pk):
    """
    Marca un correo como leído. Solo el dueño del alias puede hacerlo.
    También marca como leídas las notificaciones asociadas a ese correo —
    si el usuario ya abrió el correo y vio el análisis, no tiene sentido
    seguir recordándoselo en la campana / lista de notificaciones.

    Devuelve {ok, unread_count, notif_unread_count} para que el cliente
    actualice los dos badges (correos no leídos + bell).
    """
    try:
        em = EmailMessage.objects.select_related('alias').get(
            pk=pk, alias__user=request.user,
        )
    except EmailMessage.DoesNotExist:
        return JsonResponse({"ok": False, "error": "not_found"}, status=404)

    if not em.read:
        em.read = True
        em.save(update_fields=['read'])

    # Marcar leídas las notificaciones de ese correo. No tocamos el `status`
    # (una forward_request sigue 'pending' hasta que el usuario decida
    # reenviar/descartar) — solo el flag `read`, que es lo que cuenta el
    # badge de la campana.
    from apps.notifications.models import Notification
    Notification.objects.filter(
        user=request.user, related_email=em, read=False,
    ).update(read=True)

    unread_count = EmailMessage.objects.filter(
        alias__user=request.user, read=False,
    ).count()
    notif_unread_count = Notification.objects.filter(
        user=request.user, read=False,
    ).count()

    return JsonResponse({
        "ok": True,
        "unread_count": unread_count,
        "notif_unread_count": notif_unread_count,
    })


@login_required(login_url='login')
def email_html_api(request, pk):
    """
    Devuelve el body_html de un correo (texto/html plano).

    Solo accesible por el dueño del alias. Se usa en la bandeja para
    cargar el HTML bajo demanda dentro del iframe sandbox — así no
    embebemos megabytes de HTML en cada render del inbox.
    """
    try:
        em = EmailMessage.objects.select_related('alias').only(
            'body_html', 'alias__user_id',
        ).get(pk=pk, alias__user=request.user)
    except EmailMessage.DoesNotExist:
        return HttpResponseNotFound("not_found")

    # text/html sirve directo al iframe srcdoc; cache 1 día porque el body
    # es inmutable una vez guardado.
    resp = HttpResponse(em.body_html or '', content_type='text/html; charset=utf-8')
    resp['Cache-Control'] = 'private, max-age=86400'
    return resp


@login_required(login_url='login')
@require_POST
def inbox_clear_api(request):
    """
    Vacía correos del usuario según el filtro:
      - read    → solo los leídos
      - threats → solo amenazas (risk_score >= 61)
      - safe    → solo seguros (risk_score <= 30)
      - all     → TODOS los correos del usuario
    """
    scope = request.POST.get('scope', 'read')
    # Solo aplicamos sobre correos VIVOS (no los que ya están en papelera).
    qs = EmailMessage.objects.filter(alias__user=request.user, deleted_at__isnull=True)

    if scope == 'read':
        qs = qs.filter(read=True)
    elif scope == 'threats':
        qs = qs.filter(risk_score__gte=61)
    elif scope == 'safe':
        qs = qs.filter(risk_score__lte=30)
    elif scope == 'all':
        pass    # qs queda con TODOS los vivos
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_scope'}, status=400)

    # En vez de borrado físico, mandamos a papelera (soft delete).
    moved = qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'deleted': moved, 'trashed': True})


# ═════════════════════════════════════════════════════════════════════
#  ENVIADOS
# ═════════════════════════════════════════════════════════════════════

SENT_BATCH = 6   # cuántos correos por "página" en el load-more


def _sent_qs(user):
    """QuerySet base de enviados (excluye papelera, select_related al alias)."""
    return (
        SentEmail.objects
            .filter(alias__user=user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-sent_at')
    )


def _prepare_sent_for_render(emails):
    """Anota cada SentEmail con metadata pre-serializada para el template."""
    import json as _json
    for em in emails:
        em.attachments_meta_json = _json.dumps(em.attachments_meta or [])


def _group_sent_by_date(emails):
    """Agrupa la lista de enviados en Hoy / Ayer / Esta semana / Anteriores."""
    today    = timezone.now().date()
    yday     = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)

    groups = [
        {"label": "Hoy",          "emails": []},
        {"label": "Ayer",         "emails": []},
        {"label": "Esta semana",  "emails": []},
        {"label": "Anteriores",   "emails": []},
    ]
    for em in emails:
        d = em.sent_at.date()
        if d == today:        groups[0]["emails"].append(em)
        elif d == yday:       groups[1]["emails"].append(em)
        elif d > week_ago:    groups[2]["emails"].append(em)
        else:                 groups[3]["emails"].append(em)

    return [g for g in groups if g["emails"]]


@login_required(login_url='login')
def sent_view(request):
    """
    Lista de enviados.

    Render inicial muestra solo los SENT_BATCH primeros. El front pide
    los siguientes lotes vía `sent_more_api` (botón "Cargar más"). Así
    no cargamos los miles de correos del usuario en cada visita.

    Filtros y búsqueda se mantienen client-side sobre lo que está
    cargado en el DOM. Si el usuario filtra y ve pocos resultados, basta
    con que pulse "Cargar más" para que entren nuevos batches.
    """
    full_qs = _sent_qs(request.user)
    total_sent = full_qs.count()

    sent_emails = list(full_qs[:SENT_BATCH])
    has_more    = total_sent > SENT_BATCH

    _prepare_sent_for_render(sent_emails)
    groups = _group_sent_by_date(sent_emails)

    # Aliases activos para el compose
    active_aliases = Alias.objects.filter(
        user=request.user, is_active=True,
    ).order_by('-created_at')

    # Contadores para los filtros del sidebar (sobre TODOS los enviados)
    attach_count    = full_qs.filter(attachments_count__gt=0).count()
    scheduled_count = full_qs.filter(scheduled_at__isnull=False).count()

    return render(request, 'mail/sent.html', {
        'sent_emails':     sent_emails,
        'sent_groups':     groups,
        'total_sent':      total_sent,
        'has_more':        has_more,
        'next_offset':     len(sent_emails),
        'batch_size':      SENT_BATCH,
        'active_aliases':  active_aliases,
        'attach_count':    attach_count,
        'scheduled_count': scheduled_count,
    })


@login_required(login_url='login')
def sent_more_api(request):
    """
    Devuelve el siguiente lote de enviados como HTML parcial listo para
    appendear. Espera `?offset=<n>` (cuántos ya están en pantalla).

    Respuesta JSON:
      { ok, html, count, next_offset, has_more }
    """
    try:
        offset = int(request.GET.get('offset') or 0)
    except ValueError:
        offset = 0
    offset = max(0, offset)

    qs = _sent_qs(request.user)
    total = qs.count()
    batch = list(qs[offset:offset + SENT_BATCH])

    _prepare_sent_for_render(batch)

    from django.template.loader import render_to_string
    html = render_to_string('mail/_sent_rows.html', {'sent_emails': batch}, request=request)

    new_offset = offset + len(batch)
    return JsonResponse({
        'ok':          True,
        'html':        html,
        'count':       len(batch),
        'next_offset': new_offset,
        'has_more':    new_offset < total,
    })


@login_required(login_url='login')
@require_POST
def sent_empty_api(request):
    """Manda TODOS los enviados activos del usuario a la papelera."""
    qs = SentEmail.objects.filter(alias__user=request.user, deleted_at__isnull=True)
    count = qs.count()
    qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'moved': count})


_CONTACT_EMAIL_RX = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


@login_required(login_url='login')
def compose_contacts_api(request):
    """Autocompletado de destinatarios al escribir en el campo "Para".

    Fuente: destinatarios previos del usuario (SentEmail.to_email, que ahora
    puede ser comma-separated) + remitentes que han escrito a sus alias
    (EmailMessage.from_email, extrayendo el correo del "Nombre <correo>").

    Devuelve hasta 8 sugerencias ordenadas por uso reciente, filtradas por
    `q` (substring case-insensitive en el email o en el nombre).
    """
    q = (request.GET.get('q', '') or '').strip().lower()

    # Email → {label, last_seen}. Nos quedamos con el label más informativo
    # y el timestamp más reciente para ordenar.
    contacts: dict = {}

    def _bump(email: str, label: str, when):
        email = (email or '').strip().lower()
        if not email or '@' not in email:
            return
        cur = contacts.get(email)
        if cur is None or when > cur['last_seen']:
            contacts[email] = {
                'email':     email,
                'label':     label or (cur['label'] if cur else ''),
                'last_seen': when,
            }
        elif label and not cur['label']:
            cur['label'] = label

    # 1. Destinatarios de correos enviados (los más relevantes)
    for s in (SentEmail.objects
              .filter(alias__user=request.user)
              .order_by('-sent_at')
              .values_list('to_email', 'sent_at')[:500]):
        to_field, when = s
        for addr in (to_field or '').split(','):
            _bump(addr.strip(), '', when)

    # 2. Remitentes de correos recibidos en los alias del usuario
    for em in (EmailMessage.objects
               .filter(alias__user=request.user)
               .order_by('-received_at')
               .values_list('from_email', 'received_at')[:500]):
        raw, when = em
        if not raw:
            continue
        # Soporta "Nombre <correo>" y correo pelado
        m = _CONTACT_EMAIL_RX.search(raw)
        if not m:
            continue
        email = m.group(0).lower()
        # Display name = lo que viene antes del < (si existe)
        label = ''
        if '<' in raw:
            label = raw.split('<', 1)[0].strip().strip('"').strip()
        _bump(email, label, when)

    # Filtrar por query
    items = list(contacts.values())
    if q:
        items = [c for c in items
                 if q in c['email'] or q in (c['label'] or '').lower()]

    items.sort(key=lambda c: c['last_seen'], reverse=True)

    return JsonResponse({
        'ok': True,
        'results': [
            {'email': c['email'], 'label': c['label']}
            for c in items[:8]
        ],
    })


# ═════════════════════════════════════════════════════════════════════
#  PAPELERA — soft delete + auto-cleanup tras 30 días
# ═════════════════════════════════════════════════════════════════════

# Días que un correo permanece en la papelera antes de ser borrado de
# forma permanente — mismo comportamiento que Gmail.
TRASH_RETENTION_DAYS = 30


def _cleanup_expired_trash(user):
    """Borra de forma permanente los items del usuario que llevan más de
    TRASH_RETENTION_DAYS días en la papelera. Llamado lazy en cada visita
    a la vista de papelera — no necesita cron job."""
    cutoff = timezone.now() - timedelta(days=TRASH_RETENTION_DAYS)
    EmailMessage.objects.filter(
        alias__user=user, deleted_at__lt=cutoff,
    ).delete()
    SentEmail.objects.filter(
        alias__user=user, deleted_at__lt=cutoff,
    ).delete()
    Draft.objects.filter(
        user=user, deleted_at__lt=cutoff,
    ).delete()


@login_required(login_url='login')
@require_POST
def email_trash_api(request, pk):
    """Mueve un correo recibido a la papelera (soft delete)."""
    try:
        em = EmailMessage.objects.select_related('alias').get(
            pk=pk, alias__user=request.user, deleted_at__isnull=True,
        )
    except EmailMessage.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    em.deleted_at = timezone.now()
    em.save(update_fields=['deleted_at'])
    return JsonResponse({'ok': True})


@login_required(login_url='login')
@require_POST
def sent_trash_api(request, pk):
    """Mueve un correo enviado a la papelera."""
    try:
        em = SentEmail.objects.select_related('alias').get(
            pk=pk, alias__user=request.user, deleted_at__isnull=True,
        )
    except SentEmail.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    em.deleted_at = timezone.now()
    em.save(update_fields=['deleted_at'])
    return JsonResponse({'ok': True})


def _trash_lookup(kind, pk, user):
    """Devuelve el queryset filtrado al ítem de papelera correspondiente.
    Maneja inbound/outbound (correos por alias) y draft (asociado al user)."""
    if kind == 'inbound':
        return EmailMessage.objects.filter(
            pk=pk, alias__user=user, deleted_at__isnull=False,
        )
    if kind == 'outbound':
        return SentEmail.objects.filter(
            pk=pk, alias__user=user, deleted_at__isnull=False,
        )
    if kind == 'draft':
        return Draft.objects.filter(
            pk=pk, user=user, deleted_at__isnull=False,
        )
    return None


@login_required(login_url='login')
@require_POST
def trash_restore_api(request):
    """Restaura un item de la papelera. POST con {kind: 'inbound'|'outbound'|'draft', pk}."""
    kind = request.POST.get('kind', '')
    try:
        pk = int(request.POST.get('pk', '0'))
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_pk'}, status=400)

    qs = _trash_lookup(kind, pk, request.user)
    if qs is None:
        return JsonResponse({'ok': False, 'error': 'invalid_kind'}, status=400)

    obj = qs.first()
    if not obj:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    obj.deleted_at = None
    obj.save(update_fields=['deleted_at'])
    return JsonResponse({'ok': True})


@login_required(login_url='login')
@require_POST
def trash_delete_api(request):
    """Borra permanentemente un item de la papelera. POST con {kind, pk}."""
    kind = request.POST.get('kind', '')
    try:
        pk = int(request.POST.get('pk', '0'))
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_pk'}, status=400)

    qs = _trash_lookup(kind, pk, request.user)
    if qs is None:
        return JsonResponse({'ok': False, 'error': 'invalid_kind'}, status=400)

    deleted, _ = qs.delete()
    if deleted == 0:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)
    return JsonResponse({'ok': True})


@login_required(login_url='login')
@require_POST
def trash_empty_api(request):
    """Vacía completamente la papelera del usuario (recibidos, enviados y borradores)."""
    inbound_n  = EmailMessage.objects.filter(
        alias__user=request.user, deleted_at__isnull=False,
    ).count()
    outbound_n = SentEmail.objects.filter(
        alias__user=request.user, deleted_at__isnull=False,
    ).count()
    drafts_n   = Draft.objects.filter(
        user=request.user, deleted_at__isnull=False,
    ).count()
    EmailMessage.objects.filter(
        alias__user=request.user, deleted_at__isnull=False,
    ).delete()
    SentEmail.objects.filter(
        alias__user=request.user, deleted_at__isnull=False,
    ).delete()
    Draft.objects.filter(
        user=request.user, deleted_at__isnull=False,
    ).delete()
    return JsonResponse({
        'ok':       True,
        'deleted':  inbound_n + outbound_n + drafts_n,
        'inbound':  inbound_n,
        'outbound': outbound_n,
        'drafts':   drafts_n,
    })


TRASH_BATCH = 6   # ítems por lote en "Ver más" de papelera


def _trash_items(user):
    """
    Devuelve la lista mixta (recibidos + enviados + borradores) en
    papelera, anotada con `kind` y `expires_at` y ordenada por
    deleted_at descendente.
    """
    inbound = list(
        EmailMessage.objects
            .filter(alias__user=user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )
    outbound = list(
        SentEmail.objects
            .filter(alias__user=user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )
    drafts = list(
        Draft.objects
            .filter(user=user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )
    retention_delta = timedelta(days=TRASH_RETENTION_DAYS)
    for em in inbound:
        em.expires_at = em.deleted_at + retention_delta
        em.kind = 'inbound'
    for em in outbound:
        em.expires_at = em.deleted_at + retention_delta
        em.kind = 'outbound'
    for d in drafts:
        d.expires_at = d.deleted_at + retention_delta
        d.kind = 'draft'

    return (
        sorted(inbound + outbound + drafts,
               key=lambda it: it.deleted_at, reverse=True),
        inbound, outbound, drafts,
    )


@login_required(login_url='login')
def trash_view(request):
    """Lista la papelera. Carga diferida: primer lote en server-side,
    siguientes vía `trash_more_api`."""
    _cleanup_expired_trash(request.user)

    all_trash, inbound, outbound, drafts = _trash_items(request.user)
    total = len(all_trash)
    page  = all_trash[:TRASH_BATCH]
    has_more = total > TRASH_BATCH

    return render(request, 'mail/trash.html', {
        'all_trash':        page,
        'inbound_trash':    inbound,     # se usa solo para contadores
        'outbound_trash':   outbound,
        'drafts_trash':     drafts,
        'total_trash':      total,
        'retention_days':   TRASH_RETENTION_DAYS,
        'has_more':         has_more,
        'next_offset':      len(page),
        'batch_size':       TRASH_BATCH,
    })


@login_required(login_url='login')
def trash_more_api(request):
    """Siguiente lote de items de papelera como HTML parcial.
    Espera `?offset=N`."""
    try:
        offset = int(request.GET.get('offset') or 0)
    except ValueError:
        offset = 0
    offset = max(0, offset)

    all_trash, _, _, _ = _trash_items(request.user)
    total = len(all_trash)
    batch = all_trash[offset:offset + TRASH_BATCH]

    from django.template.loader import render_to_string
    html = render_to_string('mail/_trash_rows.html', {'all_trash': batch}, request=request)

    new_offset = offset + len(batch)
    return JsonResponse({
        'ok':          True,
        'html':        html,
        'count':       len(batch),
        'next_offset': new_offset,
        'has_more':    new_offset < total,
    })


# ═════════════════════════════════════════════════════════════════════
#  BORRADORES
# ═════════════════════════════════════════════════════════════════════

def _draft_has_content(to, body_html):
    """Un borrador se guarda SOLO si el usuario llenó AMBOS campos:
    destinatario (`to`) Y cuerpo con texto real. Si abre el compose y lo
    cierra sin escribir nada, o solo pone el asunto, no se guarda nada
    en borradores. Evita los "borradores fantasma" del refactor anterior."""
    if not (to or '').strip():
        return False
    plain = re.sub(r'<[^>]+>', '', body_html or '').strip()
    return bool(plain)


@login_required(login_url='login')
@require_POST
def draft_save_api(request):
    """Crea o actualiza un borrador.

    POST:
        draft_id    (opcional) → si viene, actualiza; si no, crea
        alias_id    (opcional)
        to          (opcional)
        subject     (opcional)
        message_html(opcional)
        scheduled_at(opcional, ISO)

    Devuelve: {ok, draft_id, updated_at}
    """
    raw_id = (request.POST.get('draft_id') or '').strip()
    alias_id = (request.POST.get('alias_id') or '').strip()
    to            = (request.POST.get('to', '') or '').strip()
    subject       = (request.POST.get('subject', '') or '').strip()
    message_html  = (request.POST.get('message_html', '') or '').strip()
    scheduled_raw = (request.POST.get('scheduled_at', '') or '').strip()

    # Si no hay nada que valga la pena guardar (requiere destinatario +
    # cuerpo con texto real), no creamos el borrador.
    if not _draft_has_content(to, message_html):
        return JsonResponse({'ok': True, 'draft_id': None, 'empty': True})

    # Resolver alias (debe pertenecer al usuario)
    alias = None
    if alias_id.isdigit():
        alias = Alias.objects.filter(id=int(alias_id), user=request.user).first()

    # Parse scheduled_at si llegó
    scheduled_dt = None
    if scheduled_raw:
        try:
            from datetime import datetime as _dt
            dt = _dt.fromisoformat(scheduled_raw)
            if dt.tzinfo is None:
                dt = timezone.make_aware(dt, timezone.get_current_timezone())
            scheduled_dt = dt
        except (ValueError, TypeError):
            scheduled_dt = None

    # Update si nos dieron un id válido y el borrador es nuestro
    draft = None
    if raw_id.isdigit():
        draft = Draft.objects.filter(id=int(raw_id), user=request.user).first()

    # Deduplicación: si NO nos dieron draft_id (borrador "nuevo") pero ya
    # existe uno con el MISMO alias + destinatario + asunto, lo reusamos.
    # Esto evita que cerrar/reabrir el compose y escribir lo mismo cree
    # 3 entradas duplicadas en /borradores/ — Gmail funciona igual.
    if not draft:
        existing_qs = Draft.objects.filter(
            user=request.user,
            alias=alias,
            to_email=to[:255],
            subject=subject[:255],
        )
        draft = existing_qs.order_by('-updated_at').first()

    if draft:
        draft.alias        = alias
        draft.to_email     = to[:255]
        draft.subject      = subject[:255]
        draft.body_html    = message_html
        draft.scheduled_at = scheduled_dt
        draft.save()
    else:
        draft = Draft.objects.create(
            user=request.user,
            alias=alias,
            to_email=to[:255],
            subject=subject[:255],
            body_html=message_html,
            scheduled_at=scheduled_dt,
        )

    return JsonResponse({
        'ok': True,
        'draft_id':   draft.id,
        'updated_at': draft.updated_at.isoformat(),
    })


@login_required(login_url='login')
def draft_get_api(request, pk):
    """Devuelve un borrador para que el compose modal lo cargue."""
    try:
        d = Draft.objects.select_related('alias').get(pk=pk, user=request.user)
    except Draft.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    return JsonResponse({
        'ok': True,
        'draft': {
            'id':            d.id,
            'alias_id':      d.alias.id if d.alias else None,
            'alias_address': d.alias.address if d.alias else '',
            'alias_label':   d.alias.label if d.alias else '',
            'alias_active':  bool(d.alias and d.alias.is_active),
            'to':            d.to_email,
            'subject':       d.subject,
            'body_html':     d.body_html,
            'scheduled_at':  d.scheduled_at.isoformat() if d.scheduled_at else '',
        },
    })


@login_required(login_url='login')
@require_POST
def draft_delete_api(request, pk):
    """Borra un borrador. Distingue dos casos:
       - hard=1 → eliminación permanente (lo usan los flujos internos:
         envío exitoso del compose).
       - default → soft delete: lo manda a la papelera (estilo Gmail).
    """
    hard = request.POST.get('hard') == '1'
    qs = Draft.objects.filter(pk=pk, user=request.user)
    if hard:
        deleted, _ = qs.delete()
        return JsonResponse({'ok': True, 'deleted': deleted, 'hard': True})

    # Soft delete: lo movemos a papelera
    qs = qs.filter(deleted_at__isnull=True)
    obj = qs.first()
    if not obj:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)
    obj.deleted_at = timezone.now()
    obj.save(update_fields=['deleted_at'])
    return JsonResponse({'ok': True, 'trashed': True})


@login_required(login_url='login')
@require_POST
def drafts_empty_api(request):
    """Manda TODOS los borradores activos del usuario a la papelera."""
    qs = Draft.objects.filter(user=request.user, deleted_at__isnull=True)
    count = qs.count()
    qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'moved': count})


DRAFTS_BATCH = 6   # cuántos borradores por "página" en el load-more


def _drafts_qs(user):
    """QuerySet base de borradores activos (no en papelera)."""
    return (
        Draft.objects
            .filter(user=user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-updated_at')
    )


@login_required(login_url='login')
def drafts_view(request):
    """
    Lista de borradores con carga diferida.
    Render inicial: solo los DRAFTS_BATCH primeros. El front pide los
    siguientes lotes vía `drafts_more_api`.
    """
    full_qs = _drafts_qs(request.user)
    total   = full_qs.count()

    drafts   = list(full_qs[:DRAFTS_BATCH])
    has_more = total > DRAFTS_BATCH

    # Contadores GLOBALES (no solo del lote visible)
    no_recipient_count = full_qs.filter(to_email='').count()
    scheduled_count    = full_qs.filter(scheduled_at__isnull=False).count()

    return render(request, 'mail/drafts.html', {
        'drafts':              drafts,
        'total_drafts':        total,
        'no_recipient_count':  no_recipient_count,
        'scheduled_count':     scheduled_count,
        'has_more':            has_more,
        'next_offset':         len(drafts),
        'batch_size':          DRAFTS_BATCH,
    })


@login_required(login_url='login')
def drafts_more_api(request):
    """Siguiente lote de borradores como HTML parcial. Espera `?offset=N`."""
    try:
        offset = int(request.GET.get('offset') or 0)
    except ValueError:
        offset = 0
    offset = max(0, offset)

    qs = _drafts_qs(request.user)
    total = qs.count()
    batch = list(qs[offset:offset + DRAFTS_BATCH])

    from django.template.loader import render_to_string
    html = render_to_string('mail/_drafts_rows.html', {'drafts': batch}, request=request)

    new_offset = offset + len(batch)
    return JsonResponse({
        'ok':          True,
        'html':        html,
        'count':       len(batch),
        'next_offset': new_offset,
        'has_more':    new_offset < total,
    })
