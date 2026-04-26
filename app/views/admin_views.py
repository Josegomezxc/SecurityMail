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
