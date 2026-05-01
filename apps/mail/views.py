"""
Vistas del módulo mail:
  - Dashboard principal (HTML + endpoint live).
  - Bandeja de entrada (HTML + APIs de polling, marcado de leído, vaciar).

Toda la lógica de scoring/sandbox vive en apps.sandbox y apps.mail.webhook.
"""
import re
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.aliases.models import Alias
from apps.sandbox.models import SandboxAnalysis
from apps.core.services.stats_service import dashboard_stats, timesince_short
from .models import EmailMessage, SentEmail, Draft


# ═════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def dashboard_view(request):
    """Dashboard principal — métricas + listas recientes."""
    stats = dashboard_stats(request.user)

    aliases         = Alias.objects.filter(user=request.user, is_active=True)[:5]
    recent_emails   = EmailMessage.objects.filter(
                          alias__user=request.user, deleted_at__isnull=True,
                      ).order_by('-received_at')[:8]
    recent_analyses = SandboxAnalysis.objects.filter(
                          email__alias__user=request.user
                      ).order_by('-analyzed_at')[:3]
    recent_threats  = EmailMessage.objects.filter(
                          alias__user=request.user, risk_score__gte=61,
                          deleted_at__isnull=True,
                      ).order_by('-received_at')[:3]

    return render(request, 'dashboard.html', {
        'aliases':         aliases,
        'recent_emails':   recent_emails,
        'recent_analyses': recent_analyses,
        'recent_threats':  recent_threats,
        **stats,
    })


@login_required(login_url='login')
def dashboard_live_api(request):
    """
    JSON consumido por el polling del dashboard (cada 15 s).
    Devuelve stats + listas compactas de los últimos correos, alias,
    análisis y amenazas del usuario.
    """
    stats = dashboard_stats(request.user)

    emails = EmailMessage.objects.filter(
        alias__user=request.user,
    ).select_related('alias').order_by('-received_at')[:8]

    aliases = Alias.objects.filter(user=request.user, is_active=True)[:5]

    analyses = SandboxAnalysis.objects.filter(
        email__alias__user=request.user,
    ).order_by('-analyzed_at')[:3]

    threats = EmailMessage.objects.filter(
        alias__user=request.user, risk_score__gte=61,
    ).select_related('alias').order_by('-received_at')[:3]

    data = dict(stats)
    data["emails"] = [{
        "id":         em.id,
        "from":       em.from_email,
        "subject":    em.subject,
        "alias":      em.alias.address,
        "risk_score": em.risk_score or 0,
        "time_human": timesince_short(em.received_at),
    } for em in emails]
    data["aliases"] = [{
        "id":          a.id,
        "address":     a.address,
        "label":       a.label,
        "email_count": a.email_count,
        "is_active":   a.is_active,
    } for a in aliases]
    data["analyses"] = [{
        "id":         a.pk,
        "filename":   a.filename,
        "risk_score": a.risk_score or 0,
    } for a in analyses]
    data["threats"] = [{
        "id":          em.id,
        "from":        em.from_email,
        "subject":     em.subject,
        "alias":       em.alias.address,
        "risk_score":  em.risk_score or 0,
        "time_human":  timesince_short(em.received_at),
        "analysis_id": (
            em.analysis.pk
            if hasattr(em, 'analysis') and getattr(em, 'analysis', None)
            else None
        ),
    } for em in threats]

    return JsonResponse(data)


# ═════════════════════════════════════════════════════════════════════
#  INBOX
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def inbox_view(request):
    """Bandeja de entrada con correos agrupados por fecha relativa.
       Excluye correos en papelera (deleted_at != null)."""
    emails = list(
        EmailMessage.objects
            .filter(alias__user=request.user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-received_at')
    )

    now      = timezone.now()
    today    = now.date()
    yday     = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)

    groups = [
        {"label": "Hoy",          "emails": []},
        {"label": "Ayer",         "emails": []},
        {"label": "Esta semana",  "emails": []},
        {"label": "Anteriores",   "emails": []},
    ]
    for em in emails:
        d = em.received_at.date()
        if d == today:
            groups[0]["emails"].append(em)
        elif d == yday:
            groups[1]["emails"].append(em)
        elif d > week_ago:
            groups[2]["emails"].append(em)
        else:
            groups[3]["emails"].append(em)

    groups = [g for g in groups if g["emails"]]   # quita vacíos

    return render(request, 'inbox.html', {
        'emails':       emails,          # compat para iteración flat
        'email_groups': groups,
    })


@login_required(login_url='login')
@require_POST
def mark_email_read_api(request, pk):
    """
    Marca un correo como leído. Solo el dueño del alias puede hacerlo.
    Devuelve {ok, unread_count} para que el cliente actualice contadores.
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

    unread_count = EmailMessage.objects.filter(
        alias__user=request.user, read=False,
    ).count()

    return JsonResponse({"ok": True, "unread_count": unread_count})


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
def inbox_new_api(request):
    """
    Endpoint consultado por el polling de la bandeja.
    Devuelve solo los correos con id > after (los más nuevos).
    """
    try:
        after = int(request.GET.get('after', '0'))
    except (TypeError, ValueError):
        after = 0

    qs = (
        EmailMessage.objects
            .filter(alias__user=request.user, id__gt=after, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-received_at')[:50]
    )

    def _row(em):
        analysis_id = None
        try:
            analysis_id = em.analysis.pk
        except SandboxAnalysis.DoesNotExist:
            pass
        return {
            "id":              em.id,
            "from_email":      em.from_email,
            "subject":         em.subject or "",
            "body":            (em.body or "")[:200],
            "alias":           em.alias.address,
            "alias_id":        em.alias.id,
            "alias_label":     em.alias.label,
            "alias_active":    em.alias.is_active,
            "received_at_iso": em.received_at.isoformat(),
            "received_human":  timesince_short(em.received_at),
            "read":            em.read,
            "has_attachment":  em.has_attachment,
            "attachment_name": em.attachment_name or "",
            "risk_score":      em.risk_score or 0,
            "analysis_id":     analysis_id,
        }

    return JsonResponse({
        "emails":  [_row(em) for em in qs],
        "has_new": qs.exists(),
    })


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

@login_required(login_url='login')
def sent_view(request):
    """Lista los correos enviados por el usuario, agrupados por fecha.
       Excluye correos en papelera."""
    sent_emails = list(
        SentEmail.objects
            .filter(alias__user=request.user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-sent_at')
    )

    now      = timezone.now()
    today    = now.date()
    yday     = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)

    groups = [
        {"label": "Hoy",          "emails": []},
        {"label": "Ayer",         "emails": []},
        {"label": "Esta semana",  "emails": []},
        {"label": "Anteriores",   "emails": []},
    ]
    for em in sent_emails:
        d = em.sent_at.date()
        if d == today:
            groups[0]["emails"].append(em)
        elif d == yday:
            groups[1]["emails"].append(em)
        elif d > week_ago:
            groups[2]["emails"].append(em)
        else:
            groups[3]["emails"].append(em)

    groups = [g for g in groups if g["emails"]]

    # Aliases activos para el botón "Nuevo correo" — el compose modal
    # necesita aliasId/address/label para arrancar.
    active_aliases = Alias.objects.filter(user=request.user, is_active=True).order_by('-created_at')

    # Contadores para los filtros del sidebar de la lista
    attach_count    = sum(1 for em in sent_emails if em.attachments_count and em.attachments_count > 0)
    scheduled_count = sum(1 for em in sent_emails if em.scheduled_at is not None)

    # Pre-serializamos la metadata de adjuntos a JSON string para inyectarla
    # en un atributo data-* y consumirla desde JavaScript.
    import json as _json
    for em in sent_emails:
        em.attachments_meta_json = _json.dumps(em.attachments_meta or [])

    return render(request, 'sent.html', {
        'sent_emails':       sent_emails,
        'sent_groups':       groups,
        'total_sent':        len(sent_emails),
        'active_aliases':    active_aliases,
        'attach_count':      attach_count,
        'scheduled_count':   scheduled_count,
    })


@login_required(login_url='login')
@require_POST
def sent_empty_api(request):
    """Manda TODOS los enviados activos del usuario a la papelera."""
    qs = SentEmail.objects.filter(alias__user=request.user, deleted_at__isnull=True)
    count = qs.count()
    qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'moved': count})


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


@login_required(login_url='login')
def trash_view(request):
    """Lista todos los items en papelera (recibidos + enviados + borradores).
    Hace cleanup lazy de los que ya pasaron TRASH_RETENTION_DAYS."""
    _cleanup_expired_trash(request.user)

    inbound = list(
        EmailMessage.objects
            .filter(alias__user=request.user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )
    outbound = list(
        SentEmail.objects
            .filter(alias__user=request.user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )
    drafts = list(
        Draft.objects
            .filter(user=request.user, deleted_at__isnull=False)
            .select_related('alias')
            .order_by('-deleted_at')
    )

    # Anotamos la fecha de expiración (deleted_at + 30 días) en cada
    # objeto para que la plantilla pueda usar {{ em.expires_at|timeuntil }}
    # y mostrar "se borra en X días". Sin esto, deleted_at es una fecha
    # pasada y timeuntil siempre devuelve "0 minutos".
    retention_delta = timedelta(days=TRASH_RETENTION_DAYS)
    for em in inbound:
        em.expires_at = em.deleted_at + retention_delta
    for em in outbound:
        em.expires_at = em.deleted_at + retention_delta
    for d in drafts:
        d.expires_at = d.deleted_at + retention_delta

    return render(request, 'trash.html', {
        'inbound_trash':    inbound,
        'outbound_trash':   outbound,
        'drafts_trash':     drafts,
        'total_trash':      len(inbound) + len(outbound) + len(drafts),
        'retention_days':   TRASH_RETENTION_DAYS,
    })


# ═════════════════════════════════════════════════════════════════════
#  BORRADORES
# ═════════════════════════════════════════════════════════════════════

def _draft_has_content(to, subject, body_html):
    """Un borrador es 'no vacío' si tiene destinatario, asunto, o cuerpo
    con texto real (excluyendo el firmón <p><br></p> que el editor pone
    por defecto)."""
    if to.strip() or subject.strip():
        return True
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

    # Si no hay nada que valga la pena guardar, no creamos el borrador.
    if not _draft_has_content(to, subject, message_html):
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


@login_required(login_url='login')
def drafts_view(request):
    """Lista todos los borradores ACTIVOS del usuario (no en papelera)."""
    drafts = list(
        Draft.objects
            .filter(user=request.user, deleted_at__isnull=True)
            .select_related('alias').order_by('-updated_at')
    )
    # Contadores para los filtros
    no_recipient = sum(1 for d in drafts if not d.to_email.strip())
    scheduled    = sum(1 for d in drafts if d.scheduled_at is not None)
    return render(request, 'drafts.html', {
        'drafts':              drafts,
        'total_drafts':        len(drafts),
        'no_recipient_count':  no_recipient,
        'scheduled_count':     scheduled,
    })
