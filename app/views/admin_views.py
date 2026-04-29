"""
Vistas del panel de administración (solo `is_staff=True`).

Incluye:
  - Dashboard global (stats del sistema completo).
  - Lista de usuarios con stats por usuario.
  - Detalle de un usuario.
  - Promover/degradar a admin.
"""
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from django.utils import timezone

from ..models import Alias, EmailMessage
from ..services.auth_service import admin_required
from ..services.stats_service import admin_global_stats


@admin_required
def admin_dashboard_view(request):
    """Panel global — estadísticas agregadas del sistema entero."""
    stats = admin_global_stats()

    top_users = (
        User.objects
            .annotate(emails_count=Count('aliases__emails'))
            .filter(emails_count__gt=0)
            .order_by('-emails_count')[:5]
    )

    recent_threats = (
        EmailMessage.objects
            .filter(risk_score__gte=61)
            .select_related('alias', 'alias__user')
            .order_by('-received_at')[:6]
    )

    return render(request, 'admin_dashboard.html', {
        **stats,
        'top_users':      top_users,
        'recent_threats': recent_threats,
    })


@admin_required
def admin_users_view(request):
    """Lista de todos los usuarios con contadores anotados."""
    users = (
        User.objects
            .annotate(
                aliases_count = Count('aliases', distinct=True),
                emails_count  = Count('aliases__emails', distinct=True),
                threats_count = Count(
                    'aliases__emails',
                    filter=Q(aliases__emails__risk_score__gte=61),
                    distinct=True,
                ),
            )
            .order_by('-date_joined')
    )
    return render(request, 'admin_users.html', {'users': users})


@admin_required
@require_POST
def admin_toggle_staff(request, pk):
    """Promueve o degrada a administrador a un usuario específico."""
    target = get_object_or_404(User, pk=pk)

    if target == request.user:
        messages.error(request, "No puedes modificar tu propio rol.")
    else:
        target.is_staff = not target.is_staff
        target.save(update_fields=['is_staff'])
        role = "administrador" if target.is_staff else "usuario normal"
        messages.success(request, f"{target.email} ahora es {role}.")

    return redirect('admin_users')


@admin_required
@require_POST
def admin_toggle_alias(request, pk):
    """
    Permite al admin DESACTIVAR (o reactivar) un alias de cualquier usuario.

    Útil cuando un alias se está usando para spam o el dueño lo abandonó.
    No borra el alias — solo lo marca como inactivo (la dirección queda
    bloqueada en BD para que jamás pueda regenerarse).
    """
    alias = get_object_or_404(Alias, pk=pk)
    target_id = alias.user_id

    if alias.is_active:
        alias.is_active = False
        alias.destroyed_at = timezone.now()
        alias.save(update_fields=['is_active', 'destroyed_at'])
        messages.success(
            request,
            f'Alias {alias.address} desactivado por administrador.',
        )
    else:
        alias.is_active = True
        alias.destroyed_at = None
        alias.save(update_fields=['is_active', 'destroyed_at'])
        messages.success(
            request,
            f'Alias {alias.address} reactivado por administrador.',
        )

    return redirect('admin_user_detail', pk=target_id)


@admin_required
def admin_threats_view(request):
    """
    Vista global de TODAS las amenazas detectadas en el sistema.
    Soporta búsqueda y filtros por nivel de score.
    """
    qs = EmailMessage.objects.filter(risk_score__gte=61).select_related(
        'alias', 'alias__user', 'analysis',
    ).order_by('-received_at')

    # Filtro por nivel
    level = (request.GET.get('level') or '').strip()
    if level == 'critical':
        qs = qs.filter(risk_score__gte=81)
    elif level == 'high':
        qs = qs.filter(risk_score__gte=61, risk_score__lt=81)

    # Búsqueda
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(from_email__icontains=q) |
            Q(subject__icontains=q) |
            Q(alias__address__icontains=q) |
            Q(alias__user__email__icontains=q)
        )

    # Stats del header (sin aplicar filtros, totales reales)
    from datetime import timedelta
    base = EmailMessage.objects.filter(risk_score__gte=61)
    total_threats   = base.count()
    critical_count  = base.filter(risk_score__gte=81).count()
    high_count      = total_threats - critical_count
    today_count     = base.filter(
        received_at__gte=timezone.now() - timedelta(days=1),
    ).count()

    return render(request, 'admin_threats.html', {
        'threats':         qs[:200],   # tope de 200 para no reventar el render
        'total_threats':   total_threats,
        'critical_count':  critical_count,
        'high_count':      high_count,
        'today_count':     today_count,
        'shown_count':     min(qs.count(), 200),
        'current_level':   level or 'all',
        'current_q':       q,
    })


@admin_required
def admin_aliases_view(request):
    """
    Vista global de TODOS los alias del sistema. Permite al admin ver
    todo lo registrado, con búsqueda y filtros por estado.
    """
    qs = Alias.objects.select_related('user').annotate(
        emails_total  = Count('emails'),
        threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
    ).order_by('-created_at')

    # Filtro por estado
    state = (request.GET.get('state') or '').strip()
    if state == 'active':
        qs = qs.filter(is_active=True)
    elif state == 'destroyed':
        qs = qs.filter(is_active=False)
    elif state == 'with_threats':
        qs = qs.filter(threats_total__gt=0)

    # Búsqueda
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(address__icontains=q) |
            Q(label__icontains=q) |
            Q(user__email__icontains=q)
        )

    # Stats del header (totales sin filtros)
    base = Alias.objects.all()
    total_count       = base.count()
    active_count      = base.filter(is_active=True).count()
    destroyed_count   = total_count - active_count
    with_threats_qs   = Alias.objects.annotate(
        threats_total=Count('emails', filter=Q(emails__risk_score__gte=61)),
    ).filter(threats_total__gt=0)
    with_threats_count = with_threats_qs.count()

    return render(request, 'admin_aliases.html', {
        'aliases':            qs[:300],
        'total_count':        total_count,
        'active_count':       active_count,
        'destroyed_count':    destroyed_count,
        'with_threats_count': with_threats_count,
        'shown_count':        min(qs.count(), 300),
        'current_state':      state or 'all',
        'current_q':          q,
    })


@admin_required
def admin_user_detail_view(request, pk):
    """Detalle de un usuario: sus aliases, correos recientes y amenazas."""
    target = get_object_or_404(User, pk=pk)

    aliases = (
        Alias.objects.filter(user=target)
            .annotate(
                emails_total  = Count('emails'),
                threats_total = Count('emails', filter=Q(emails__risk_score__gte=61)),
            )
            .order_by('-created_at')
    )

    recent_emails = (
        EmailMessage.objects
            .filter(alias__user=target)
            .select_related('alias')
            .order_by('-received_at')[:15]
    )

    return render(request, 'admin_user_detail.html', {
        'target':        target,
        'aliases':       aliases,
        'recent_emails': recent_emails,
        'emails_total':  EmailMessage.objects.filter(alias__user=target).count(),
        'threats_total': EmailMessage.objects.filter(
                              alias__user=target, risk_score__gte=61).count(),
    })
