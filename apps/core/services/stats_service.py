"""
Cálculos estadísticos reutilizables.

Usado por dashboard (GET + polling JSON), perfil, y panel de admin.
Mantiene las consultas centralizadas para no duplicar lógica.
"""
from datetime import timedelta

from django.utils import timezone

from apps.aliases.models import Alias
from apps.mail.models import EmailMessage
from apps.sandbox.models import SandboxAnalysis


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

    received_qs   = EmailMessage.objects.all()
    emails_total  = received_qs.count()

    # ── Distribución de correos por nivel de riesgo ──
    safe_count    = received_qs.filter(risk_score__lte=30).count()
    susp_count    = received_qs.filter(
                        risk_score__gt=30, risk_score__lt=61).count()
    threats_total = received_qs.filter(risk_score__gte=61).count()

    # Porcentajes (evita divisiones por 0)
    if emails_total > 0:
        safe_pct    = round(safe_count    / emails_total * 100)
        susp_pct    = round(susp_count    / emails_total * 100)
        threats_pct = round(threats_total / emails_total * 100)
    else:
        safe_pct = susp_pct = threats_pct = 0

    aliases_total  = Alias.objects.count()
    aliases_active = Alias.objects.filter(is_active=True).count()
    aliases_active_pct = round(aliases_active / aliases_total * 100) if aliases_total else 0

    users_total = User.objects.count()
    users_staff = User.objects.filter(is_staff=True).count()
    users_active = User.objects.filter(is_active=True).count()

    # ── Actividad: correos por día en los últimos 7 días ──
    activity_7d = []
    max_in_day  = 0
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0,  minute=0, second=0, microsecond=0)
        day_end   = (now - timedelta(days=i)).replace(hour=23, minute=59, second=59, microsecond=999999)
        count = received_qs.filter(
            received_at__gte=day_start, received_at__lte=day_end,
        ).count()
        max_in_day = max(max_in_day, count)
        activity_7d.append({
            'date':  day_start,
            'label': day_start.strftime('%a %d').lower(),
            'count': count,
        })
    # Calculamos el % de altura de la barra para el gráfico
    for d in activity_7d:
        d['bar_pct'] = round(d['count'] / max_in_day * 100) if max_in_day else 0

    # ── Top 5 dominios atacantes (de dónde vienen las amenazas) ──
    # Extraemos el dominio del campo from_email de los correos con
    # score >= 61. Lo hacemos en Python porque sqlite/postgres no tienen
    # SUBSTRING_INDEX nativo igual.
    threat_emails = received_qs.filter(
        risk_score__gte=61,
    ).values_list('from_email', flat=True)
    domain_counts = {}
    for addr in threat_emails:
        if not addr:
            continue
        # Extrae solo el dominio: 'foo@bar.com' -> 'bar.com'
        if '@' in addr:
            domain = addr.split('@')[-1].strip().lower().rstrip('>').strip()
        else:
            domain = addr.strip().lower()
        if not domain:
            continue
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    top_attacker_domains = [
        {'domain': d, 'count': c}
        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:5]
    ]

    # ── Tendencia: comparación 7 días actuales vs 7 días anteriores ──
    cutoff_14d = now - timedelta(days=14)
    emails_prev_7d = received_qs.filter(
        received_at__gte=cutoff_14d, received_at__lt=cutoff_7d,
    ).count()
    threats_7d = received_qs.filter(
        received_at__gte=cutoff_7d, risk_score__gte=61,
    ).count()
    threats_prev_7d = received_qs.filter(
        received_at__gte=cutoff_14d, received_at__lt=cutoff_7d,
        risk_score__gte=61,
    ).count()

    def _trend_pct(current, previous):
        if previous == 0:
            return 100 if current > 0 else 0
        return round((current - previous) / previous * 100)

    emails_trend  = _trend_pct(received_qs.filter(received_at__gte=cutoff_7d).count(), emails_prev_7d)
    threats_trend = _trend_pct(threats_7d, threats_prev_7d)

    return {
        "users_total":     users_total,
        "users_staff":     users_staff,
        "users_active":    users_active,
        "aliases_total":   aliases_total,
        "aliases_active":  aliases_active,
        "aliases_active_pct": aliases_active_pct,
        "emails_total":    emails_total,
        "emails_24h":      received_qs.filter(received_at__gte=cutoff_1d).count(),
        "emails_7d":       received_qs.filter(received_at__gte=cutoff_7d).count(),
        "threats_total":   threats_total,
        "threats_24h":     received_qs.filter(
                                received_at__gte=cutoff_1d, risk_score__gte=61).count(),
        "threats_7d":      threats_7d,
        "sandbox_total":   SandboxAnalysis.objects.count(),
        "sandbox_blocked": SandboxAnalysis.objects.filter(risk_score__gte=81).count(),
        # Distribución
        "safe_count":      safe_count,
        "susp_count":      susp_count,
        "safe_pct":        safe_pct,
        "susp_pct":        susp_pct,
        "threats_pct":     threats_pct,
        # Actividad
        "activity_7d":     activity_7d,
        "max_in_day":      max_in_day,
        # Top dominios atacantes
        "top_attacker_domains": top_attacker_domains,
        # Tendencias
        "emails_trend":    emails_trend,
        "threats_trend":   threats_trend,
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
