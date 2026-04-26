"""
Vistas del dashboard principal del usuario:
  - Render HTML del dashboard.
  - API JSON de "en vivo" para el polling del frontend.
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render

from ..models import Alias, EmailMessage, SandboxAnalysis
from ..services.stats_service import dashboard_stats, timesince_short


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
