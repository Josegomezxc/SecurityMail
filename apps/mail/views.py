"""
Vistas del módulo mail:
  - Dashboard principal (HTML + endpoint live).
  - Bandeja de entrada (HTML + APIs de polling, marcado de leído, vaciar).

Toda la lógica de scoring/sandbox vive en apps.sandbox y apps.mail.webhook.
"""
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.aliases.models import Alias
from apps.sandbox.models import SandboxAnalysis
from apps.core.services.stats_service import dashboard_stats, timesince_short
from .models import EmailMessage


# ═════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ═════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def dashboard_view(request):
    """Dashboard principal — métricas + listas recientes."""
    stats = dashboard_stats(request.user)

    aliases         = Alias.objects.filter(user=request.user, is_active=True)[:5]
    recent_emails   = EmailMessage.objects.filter(
                          alias__user=request.user
                      ).order_by('-received_at')[:8]
    recent_analyses = SandboxAnalysis.objects.filter(
                          email__alias__user=request.user
                      ).order_by('-analyzed_at')[:3]
    recent_threats  = EmailMessage.objects.filter(
                          alias__user=request.user, risk_score__gte=61
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
    """Bandeja de entrada con correos agrupados por fecha relativa."""
    emails = list(
        EmailMessage.objects
            .filter(alias__user=request.user)
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
            .filter(alias__user=request.user, id__gt=after)
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
    qs = EmailMessage.objects.filter(alias__user=request.user)

    if scope == 'read':
        qs = qs.filter(read=True)
    elif scope == 'threats':
        qs = qs.filter(risk_score__gte=61)
    elif scope == 'safe':
        qs = qs.filter(risk_score__lte=30)
    elif scope == 'all':
        pass    # qs queda con TODOS
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_scope'}, status=400)

    deleted = qs.count()
    qs.delete()
    return JsonResponse({'ok': True, 'deleted': deleted})
