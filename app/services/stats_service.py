"""
Cálculos estadísticos reutilizables.

Usado por dashboard (GET + polling JSON), perfil, y panel de admin.
Mantiene las consultas centralizadas para no duplicar lógica.
"""
from datetime import timedelta

from django.utils import timezone

from ..models import Alias, EmailMessage, SandboxAnalysis


# ─────────────────────────────────────────────────────────────────────
#  Stats del usuario logueado (usado por el dashboard normal)
# ─────────────────────────────────────────────────────────────────────

def dashboard_stats(user) -> dict:
    """
    Devuelve todas las métricas que el dashboard del usuario necesita:
    contadores principales, tendencia 24h y tasa de bloqueo.
    """
    now       = timezone.now()
    cutoff_1d = now - timedelta(days=1)
    cutoff_2d = now - timedelta(days=2)

    emails_qs  = EmailMessage.objects.filter(alias__user=user)
    sandbox_qs = SandboxAnalysis.objects.filter(email__alias__user=user)

    total_emails  = emails_qs.count()
    threats_count = emails_qs.filter(risk_score__gte=61).count()
    safe_count    = sandbox_qs.filter(risk_score__lte=30).count()
    alias_count   = Alias.objects.filter(user=user, is_active=True).count()
    unread_count  = emails_qs.filter(read=False).count()

    today_emails  = emails_qs.filter(received_at__gte=cutoff_1d).count()
    yday_emails   = emails_qs.filter(received_at__gte=cutoff_2d,
                                     received_at__lt=cutoff_1d).count()
    today_threats = emails_qs.filter(received_at__gte=cutoff_1d,
                                     risk_score__gte=61).count()

    block_rate = 0
    if total_emails > 0:
        block_rate = round((threats_count / total_emails) * 100)

    return {
        "alias_count":   alias_count,
        "total_emails":  total_emails,
        "threats_count": threats_count,
        "safe_count":    safe_count,
        "unread_count":  unread_count,
        "today_emails":  today_emails,
        "yday_emails":   yday_emails,
        "today_threats": today_threats,
        "block_rate":    block_rate,
    }


# ─────────────────────────────────────────────────────────────────────
#  Stats globales del sistema (panel de administración)
# ─────────────────────────────────────────────────────────────────────

def admin_global_stats() -> dict:
    """Métricas agregadas de TODO el sistema para el panel admin."""
    from django.contrib.auth.models import User

    now       = timezone.now()
    cutoff_1d = now - timedelta(days=1)
    cutoff_7d = now - timedelta(days=7)

    return {
        "users_total":     User.objects.count(),
        "users_staff":     User.objects.filter(is_staff=True).count(),
        "aliases_total":   Alias.objects.count(),
        "aliases_active":  Alias.objects.filter(is_active=True).count(),
        "emails_total":    EmailMessage.objects.count(),
        "emails_24h":      EmailMessage.objects.filter(received_at__gte=cutoff_1d).count(),
        "emails_7d":       EmailMessage.objects.filter(received_at__gte=cutoff_7d).count(),
        "threats_total":   EmailMessage.objects.filter(risk_score__gte=61).count(),
        "threats_24h":     EmailMessage.objects.filter(
                                received_at__gte=cutoff_1d, risk_score__gte=61).count(),
        "sandbox_total":   SandboxAnalysis.objects.count(),
        "sandbox_blocked": SandboxAnalysis.objects.filter(risk_score__gte=81).count(),
    }


# ─────────────────────────────────────────────────────────────────────
#  Stats del perfil (conteos básicos por usuario)
# ─────────────────────────────────────────────────────────────────────

def profile_stats(user) -> dict:
    """Contadores mostrados en la tarjeta del perfil."""
    return {
        "alias_count":   Alias.objects.filter(user=user, is_active=True).count(),
        "total_emails":  EmailMessage.objects.filter(alias__user=user).count(),
        "threats_count": SandboxAnalysis.objects.filter(
                            email__alias__user=user, risk_score__gte=61).count(),
    }


# ─────────────────────────────────────────────────────────────────────
#  Utilidades de formato
# ─────────────────────────────────────────────────────────────────────

def timesince_short(dt) -> str:
    """
    Devuelve 'hace N min/h/d/sem' en formato compacto para el frontend.
    Usado en las respuestas JSON del polling.
    """
    from django.utils.timesince import timesince
    s = timesince(dt).split(',')[0]
    return (s
            .replace('hours', 'h').replace('hour', 'h')
            .replace('minutes', 'min').replace('minute', 'min')
            .replace('days', 'd').replace('day', 'd')
            .replace('weeks', 'sem').replace('week', 'sem'))
