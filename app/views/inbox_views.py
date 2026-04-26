"""
Vistas de la bandeja de entrada:
  - Render HTML agrupado por fecha.
  - API JSON para polling de correos nuevos.
  - API POST para marcar un correo como leído.
"""
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_POST

from ..models import EmailMessage, SandboxAnalysis
from ..services.stats_service import timesince_short


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
