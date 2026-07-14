
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
from apps.core.services.stats_service import activity_data_for_user, dashboard_stats
from apps.core.url_signer import decode_id, encode_id
from .models import EmailMessage, SentEmail, Draft


PAGE_SIZE = 6


def _qs_params(request, exclude=('page',)):
    """
    Devuelve los query params actuales como string para preservarlos al
    paginar (excepto los que se quieran sobreescribir, típicamente `page`).
    Ej: si la URL es ?q=hola&filter=unread&page=2 → "q=hola&filter=unread"
    """
    params = {k: v for k, v in request.GET.items() if k not in exclude and v}
    return urlencode(params)





@login_required(login_url='login')
def dashboard_view(request):
    """Dashboard principal — métricas + listas recientes."""
    period = request.GET.get('period', 'semanal')
    ref = request.GET.get('ref')
    stats = dashboard_stats(request.user, period=period, ref_str=ref)

    aliases         = Alias.objects.filter(user=request.user, is_active=True)[:5]

    recent_emails   = list(
        EmailMessage.objects.select_related('alias').filter(
            alias__user=request.user, deleted_at__isnull=True,
        ).order_by('-received_at')[:20]
    )

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
        'period':          period,
        **stats,
    })




@login_required(login_url='login')
def inbox_view(request):

    base_qs = EmailMessage.objects.filter(
        alias__user=request.user, deleted_at__isnull=True,
    )

    counts = {
        'all':        base_qs.count(),
        'unread':     base_qs.filter(read=False).count(),
        'attachment': base_qs.filter(attachment__has_attachment=True).count(),
        'danger':     base_qs.filter(risk_score__gte=61).count(),
        'safe':       base_qs.filter(risk_score__gt=0, risk_score__lte=30).count(),
    }

    qs = base_qs


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


    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(from_email__icontains=q) |
            Q(subject__icontains=q) |
            Q(body__icontains=q)
        )

    qs = qs.select_related('alias').order_by('-received_at')

    
    paginator = Paginator(qs, PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))


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
        'emails':     page_obj.object_list,  
        'counts':     counts,
        'q':          q,
        'filter':     filter_,
        'qs_params':  _qs_params(request),
    })


@login_required(login_url='login')
@require_POST
def mark_email_read_api(request, pk):

    try:
        em = EmailMessage.objects.select_related('alias').get(
            pk=pk, alias__user=request.user,
        )
    except EmailMessage.DoesNotExist:
        return JsonResponse({"ok": False, "error": "not_found"}, status=404)

    if not em.read:
        em.read = True
        em.save(update_fields=['read'])


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

    try:
        em = EmailMessage.objects.select_related('alias').only(
            'body_html', 'alias__user_id',
        ).get(pk=pk, alias__user=request.user)
    except EmailMessage.DoesNotExist:
        return HttpResponseNotFound("not_found")

    
    resp = HttpResponse(em.body_html or '', content_type='text/html; charset=utf-8')
    resp['Cache-Control'] = 'private, max-age=86400'
    return resp


@login_required(login_url='login')
@require_POST
def inbox_clear_api(request):

    scope = request.POST.get('scope', 'read')
    qs = EmailMessage.objects.filter(alias__user=request.user, deleted_at__isnull=True)

    if scope == 'read':
        qs = qs.filter(read=True)
    elif scope == 'threats':
        qs = qs.filter(risk_score__gte=61)
    elif scope == 'safe':
        qs = qs.filter(risk_score__lte=30)
    elif scope == 'all':
        pass
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_scope'}, status=400)


    moved = qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'deleted': moved, 'trashed': True})




SENT_BATCH = 6   


def _sent_qs(user):
    return (
        SentEmail.objects
            .filter(alias__user=user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-sent_at')
    )


def _prepare_sent_for_render(emails):
    import json as _json
    for em in emails:
        em.attachments_meta_json = _json.dumps(em.attachments_meta or [])


def _group_sent_by_date(emails):

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

    full_qs = _sent_qs(request.user)
    total_sent = full_qs.count()

    sent_emails = list(full_qs[:SENT_BATCH])
    has_more    = total_sent > SENT_BATCH

    _prepare_sent_for_render(sent_emails)
    groups = _group_sent_by_date(sent_emails)


    active_aliases = Alias.objects.filter(
        user=request.user, is_active=True,
    ).order_by('-created_at')
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

    qs = SentEmail.objects.filter(alias__user=request.user, deleted_at__isnull=True)
    count = qs.count()
    qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'moved': count})


_CONTACT_EMAIL_RX = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


@login_required(login_url='login')
def compose_contacts_api(request):

    q = ((request.POST.get('q') or request.GET.get('q', '')) or '').strip().lower()

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

    for s in (SentEmail.objects
              .filter(alias__user=request.user)
              .order_by('-sent_at')
              .values_list('to_email', 'sent_at')[:500]):
        to_field, when = s
        for addr in (to_field or '').split(','):
            _bump(addr.strip(), '', when)


    for em in (EmailMessage.objects
               .filter(alias__user=request.user)
               .order_by('-received_at')
               .values_list('from_email', 'received_at')[:500]):
        raw, when = em
        if not raw:
            continue
        m = _CONTACT_EMAIL_RX.search(raw)
        if not m:
            continue
        email = m.group(0).lower()
        label = ''
        if '<' in raw:
            label = raw.split('<', 1)[0].strip().strip('"').strip()
        _bump(email, label, when)

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




TRASH_RETENTION_DAYS = 30


def _cleanup_expired_trash(user):
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


TRASH_BATCH = 6   


def _trash_items(user):
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
    _cleanup_expired_trash(request.user)

    all_trash, inbound, outbound, drafts = _trash_items(request.user)
    total = len(all_trash)
    page  = all_trash[:TRASH_BATCH]
    has_more = total > TRASH_BATCH

    return render(request, 'mail/trash.html', {
        'all_trash':        page,
        'inbound_trash':    inbound,     
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



def _draft_has_content(to, body_html):
    if not (to or '').strip():
        return False
    plain = re.sub(r'<[^>]+>', '', body_html or '').strip()
    return bool(plain)


@login_required(login_url='login')
@require_POST
def draft_save_api(request):

    raw_id = (request.POST.get('draft_id') or '').strip()
    alias_id = (request.POST.get('alias_id') or '').strip()
    to            = (request.POST.get('to', '') or '').strip()
    subject       = (request.POST.get('subject', '') or '').strip()
    message_html  = (request.POST.get('message_html', '') or '').strip()
    scheduled_raw = (request.POST.get('scheduled_at', '') or '').strip()

    if not _draft_has_content(to, message_html):
        return JsonResponse({'ok': True, 'draft_id': None, 'empty': True})
    alias = None
    try:
        alias_pk = decode_id(alias_id)
    except Exception:
        alias_pk = int(alias_id) if alias_id.isdigit() else None
    if alias_pk is not None:
        alias = Alias.objects.filter(id=alias_pk, user=request.user).first()

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

    draft = None
    try:
        draft_pk = decode_id(raw_id)
    except Exception:
        draft_pk = int(raw_id) if raw_id.isdigit() else None
    if draft_pk is not None:
        draft = Draft.objects.filter(id=draft_pk, user=request.user).first()

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
        'draft_id':   encode_id(draft.id),
        'updated_at': draft.updated_at.isoformat(),
    })


@login_required(login_url='login')
def draft_get_api(request, pk):
    try:
        d = Draft.objects.select_related('alias').get(pk=pk, user=request.user)
    except Draft.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'not_found'}, status=404)

    alias = d.alias
    return JsonResponse({
        'ok': True,
        'draft': {
            'id':            encode_id(d.id),
            'alias_id':      encode_id(alias.id) if alias else None,
            'alias_address': alias.address if alias else '',
            'alias_label':   alias.label if alias else '',
            'alias_active':  bool(alias and alias.is_active),
            'to':            d.to_email,
            'subject':       d.subject,
            'body_html':     d.body_html,
            'scheduled_at':  d.scheduled_at.isoformat() if d.scheduled_at else '',
        },
    })


@login_required(login_url='login')
@require_POST
def draft_delete_api(request, pk):
    hard = request.POST.get('hard') == '1'
    qs = Draft.objects.filter(pk=pk, user=request.user)
    if hard:
        deleted, _ = qs.delete()
        return JsonResponse({'ok': True, 'deleted': deleted, 'hard': True})

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
    qs = Draft.objects.filter(user=request.user, deleted_at__isnull=True)
    count = qs.count()
    qs.update(deleted_at=timezone.now())
    return JsonResponse({'ok': True, 'moved': count})


DRAFTS_BATCH = 6   


def _drafts_qs(user):
    return (
        Draft.objects
            .filter(user=user, deleted_at__isnull=True)
            .select_related('alias')
            .order_by('-updated_at')
    )


@login_required(login_url='login')
def drafts_view(request):
    full_qs = _drafts_qs(request.user)
    total   = full_qs.count()

    drafts   = list(full_qs[:DRAFTS_BATCH])
    has_more = total > DRAFTS_BATCH


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


@login_required(login_url='login')
def dashboard_activity_api(request):
    period = request.GET.get('period', 'semanal')
    if period not in ('diario', 'semanal', 'mensual', 'anual'):
        period = 'semanal'
    data, label = activity_data_for_user(request.user, period)
    return JsonResponse({'activity_data': data, 'range_label': label})
