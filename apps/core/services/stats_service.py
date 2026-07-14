
import calendar
from datetime import datetime, timedelta

from django.db.models import Count, Q
from django.db.models.functions import TruncDate, TruncHour, TruncMonth, TruncYear
from django.utils import timezone

from apps.aliases.models import Alias
from apps.mail.models import EmailMessage
from apps.sandbox.models import SandboxAnalysis


def _build_activity(user, period, ref_date):

    today = timezone.now().date()
    _filter = {} if user is None else {'alias__user': user}

    if period == 'diario':
        start = timezone.make_aware(datetime.combine(ref_date, datetime.min.time()))
        end = start + timedelta(days=1)
        qs = (EmailMessage.objects
              .filter(**_filter, received_at__gte=start, received_at__lt=end)
              .annotate(bucket=TruncHour('received_at'))
              .values('bucket')
              .annotate(count=Count('id')))
        bucket_map = {row['bucket'].hour: row['count'] for row in qs}
        data = [{'label': f'{h:02d}:00', 'count': bucket_map.get(h, 0)} for h in range(24)]
        label = ref_date.strftime('%d/%m/%Y')

    elif period == 'semanal':
        monday = ref_date - timedelta(days=ref_date.weekday())
        start = timezone.make_aware(datetime.combine(monday, datetime.min.time()))
        end = start + timedelta(days=7)
        qs = (EmailMessage.objects
              .filter(**_filter, received_at__gte=start, received_at__lt=end)
              .annotate(bucket=TruncDate('received_at'))
              .values('bucket')
              .annotate(count=Count('id')))
        bucket_map = {row['bucket']: row['count'] for row in qs}
        weekdays = ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom']
        data = []
        for i in range(7):
            day = monday + timedelta(days=i)
            data.append({'label': f"{weekdays[i]} {day.day}", 'count': bucket_map.get(day, 0)})
        label = f"Semana del {monday.strftime('%d/%m')}"

    elif period == 'mensual':
        first = ref_date.replace(day=1)
        start = timezone.make_aware(datetime.combine(first, datetime.min.time()))
        if ref_date.month == 12:
            end = timezone.make_aware(datetime.combine(first.replace(year=first.year + 1, month=1), datetime.min.time()))
        else:
            end = timezone.make_aware(datetime.combine(first.replace(month=first.month + 1), datetime.min.time()))
        qs = (EmailMessage.objects
              .filter(**_filter, received_at__gte=start, received_at__lt=end)
              .annotate(bucket=TruncDate('received_at'))
              .values('bucket')
              .annotate(count=Count('id')))
        bucket_map = {}
        for row in qs:
            bucket_map[row['bucket'].day] = row['count']
        last_day = calendar.monthrange(ref_date.year, ref_date.month)[1]
        data = [{'label': f'{d:02d}/{ref_date.month:02d}', 'count': bucket_map.get(d, 0)} for d in range(1, last_day + 1)]
        label = ref_date.strftime('%B %Y').capitalize()

    elif period == 'anual':
        today = timezone.now().date()
        first_year = today.year - 4
        start = timezone.make_aware(datetime(first_year, 1, 1))
        end = timezone.make_aware(datetime(today.year + 1, 1, 1))
        qs = (EmailMessage.objects
              .filter(**_filter, received_at__gte=start, received_at__lt=end)
              .annotate(bucket=TruncYear('received_at'))
              .values('bucket')
              .annotate(count=Count('id')))
        bucket_map = {row['bucket'].year: row['count'] for row in qs}
        data = [{'label': str(y), 'count': bucket_map.get(y, 0)} for y in range(first_year, today.year + 1)]
        label = f"{first_year}–{today.year}"

    else:
        return _build_activity(user, 'diario', today)

    return data, label


def activity_data_for_user(user, period='diario'):
    today = timezone.now().date()
    return _build_activity(user, period, today)


def dashboard_stats(user, period='diario', ref_str=None) -> dict:

    now       = timezone.now()
    today     = now.date()
    cutoff_1d = now - timedelta(days=1)
    cutoff_2d = now - timedelta(days=2)

    if ref_str:
        try:
            ref_date = datetime.strptime(ref_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            ref_date = today
    else:
        ref_date = today
    if ref_date > today:
        ref_date = today

    agg = EmailMessage.objects.filter(alias__user=user).aggregate(
        total_emails=Count('id'),
        threats_count=Count('id', filter=Q(risk_score__gte=61)),
        susp_count=Count('id', filter=Q(risk_score__gt=30, risk_score__lt=61)),
        safe_emails=Count('id', filter=Q(risk_score__lte=30)),
        unread_count=Count('id', filter=Q(read=False)),
        today_emails=Count('id', filter=Q(received_at__gte=cutoff_1d)),
        yday_emails=Count('id', filter=Q(
            received_at__gte=cutoff_2d, received_at__lt=cutoff_1d,
        )),
        today_threats=Count('id', filter=Q(
            received_at__gte=cutoff_1d, risk_score__gte=61,
        )),
    )

    activity_data, range_label = _build_activity(user, period, ref_date)

    safe_count = SandboxAnalysis.objects.filter(
        email__alias__user=user, risk_score__lte=30,
    ).count()

    alias_count = Alias.objects.filter(user=user, is_active=True).count()

    total_emails  = agg['total_emails']
    threats_count = agg['threats_count']
    susp_count    = agg['susp_count']
    safe_emails   = agg['safe_emails']
    unread_count  = agg['unread_count']
    today_emails  = agg['today_emails']
    yday_emails   = agg['yday_emails']
    today_threats = agg['today_threats']

    block_rate = round(threats_count / total_emails * 100) if total_emails > 0 else 0

    risk_distribution = {
        'safe':    safe_emails,
        'susp':    susp_count,
        'threats': threats_count,
    }

    emails_trend = _trend_pct(today_emails, yday_emails)

    return {
        "alias_count":       alias_count,
        "total_emails":      total_emails,
        "threats_count":     threats_count,
        "safe_count":        safe_count,
        "unread_count":      unread_count,
        "today_emails":      today_emails,
        "yday_emails":       yday_emails,
        "today_threats":     today_threats,
        "block_rate":        block_rate,
        "activity_data":     activity_data,
        "range_label":       range_label,
        "risk_distribution": risk_distribution,
        "emails_trend":      emails_trend,
    }


def _trend_pct(current: int, previous: int) -> int:
    """% de cambio current vs previous. Maneja división por cero."""
    if previous == 0:
        return 100 if current > 0 else 0
    return round((current - previous) / previous * 100)


def admin_global_stats() -> dict:

    from django.contrib.auth.models import User

    now       = timezone.now()
    cutoff_1d = now - timedelta(days=1)
    cutoff_7d = now - timedelta(days=7)

    received_qs   = EmailMessage.objects.all()
    emails_total  = received_qs.count()

    safe_count    = received_qs.filter(risk_score__lte=30).count()
    susp_count    = received_qs.filter(
                        risk_score__gt=30, risk_score__lt=61).count()
    threats_total = received_qs.filter(risk_score__gte=61).count()

    
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

    for d in activity_7d:
        d['bar_pct'] = round(d['count'] / max_in_day * 100) if max_in_day else 0

    threat_emails = received_qs.filter(
        risk_score__gte=61,
    ).values_list('from_email', flat=True)
    domain_counts = {}
    for addr in threat_emails:
        if not addr:
            continue

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


    users_active_regular = max(0, users_active - users_staff)
    users_inactive       = max(0, users_total  - users_active)

    return {
        "users_total":          users_total,
        "users_staff":          users_staff,
        "users_active":         users_active,
        "users_active_regular": users_active_regular,
        "users_inactive":       users_inactive,
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

        "safe_count":      safe_count,
        "susp_count":      susp_count,
        "safe_pct":        safe_pct,
        "susp_pct":        susp_pct,
        "threats_pct":     threats_pct,

        "activity_7d":     activity_7d,
        "max_in_day":      max_in_day,

        "top_attacker_domains": top_attacker_domains,
        "emails_trend":    emails_trend,
        "threats_trend":   threats_trend,
    }



def profile_stats(user) -> dict:

    return {
        "alias_count":   Alias.objects.filter(user=user, is_active=True).count(),
        "total_emails":  EmailMessage.objects.filter(alias__user=user).count(),
        "threats_count": SandboxAnalysis.objects.filter(
                            email__alias__user=user, risk_score__gte=61).count(),
    }


