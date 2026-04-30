"""
Vistas y APIs del sistema de notificaciones (panel de campana).

  - notification_list_view  → página completa con todas las notificaciones
  - notification_detail_view → detalle de una notificación + acciones
  - notification_unread_api  → JSON para el polling del badge
  - notification_mark_read_api → marca una como leída
  - notification_forward_api  → aprueba reenvío (forward_request)
  - notification_discard_api  → descarta (forward_request)
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Notification


# ─────────────────────────────────────────────────────────────────────
#  Render: lista completa
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def notification_list_view(request):
    """Página con todas las notificaciones del usuario."""
    notifs = Notification.objects.filter(user=request.user).select_related(
        'related_email', 'related_email__alias',
    )
    # Counts por categoría para los pills de filtro
    # "Reenviadas" cubre tanto auto-forwarded (type=forwarded) como aprobadas
    # manualmente desde una forward_request (status=approved).
    from django.db.models import Q
    counts = {
        'all':       notifs.count(),
        'unread':    notifs.filter(read=False).count(),
        'pending':   notifs.filter(status='pending').count(),
        'forwarded': notifs.filter(Q(type='forwarded') | Q(status='approved')).count(),
        'discarded': notifs.filter(status='discarded').count(),
    }
    return render(request, 'notifications.html', {
        'notifications': notifs,
        'pending_count': counts['pending'],
        'counts':        counts,
    })


# ─────────────────────────────────────────────────────────────────────
#  Render: detalle de una notificación
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def notification_detail_view(request, pk):
    """Detalle de una notificación. Si es de un correo, muestra preview completo."""
    notif = get_object_or_404(
        Notification.objects.select_related('related_email', 'related_email__alias'),
        pk=pk, user=request.user,
    )
    # Marcar como leída automáticamente al abrirla
    if not notif.read:
        notif.read = True
        notif.save(update_fields=['read'])
    return render(request, 'notification_detail.html', {
        'notif': notif,
        'email': notif.related_email,
    })


# ─────────────────────────────────────────────────────────────────────
#  API: contador + últimas (para polling del bell)
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def notification_unread_api(request):
    """JSON con contador y últimas N notificaciones para el dropdown."""
    qs = Notification.objects.filter(user=request.user).select_related(
        'related_email__alias',
    )
    unread_count  = qs.filter(read=False).count()
    pending_count = qs.filter(type='forward_request', status='pending').count()
    recent = list(qs[:8])

    def _row(n):
        # Score del correo asociado, para que el frontend pinte el toast
        # del color correcto (verde=seguro, amarillo=sospechoso, rojo=amenaza).
        risk = None
        if n.related_email_id:
            try:
                risk = int(n.related_email.risk_score or 0)
            except Exception:
                risk = None
        return {
            'id':         n.id,
            'type':       n.type,
            'title':      n.title,
            'message':    n.message,
            'read':       n.read,
            'status':     n.status,
            'is_actionable': n.is_actionable,
            'risk_score': risk,
            'time_iso':   n.created_at.isoformat(),
            'time_human': _time_short(n.created_at),
            'url':        f'/notificaciones/{n.id}/',
        }

    return JsonResponse({
        'unread_count':  unread_count,
        'pending_count': pending_count,
        'total':         qs.count(),
        'recent':        [_row(n) for n in recent],
    })


def _time_short(dt):
    """'hace 3m', 'hace 2h', 'ayer', '5/6'"""
    delta = timezone.now() - dt
    s = int(delta.total_seconds())
    if s < 60:    return 'ahora'
    if s < 3600:  return f'hace {s // 60} min'
    if s < 86400: return f'hace {s // 3600} h'
    if s < 86400 * 2: return 'ayer'
    if s < 86400 * 7: return f'hace {s // 86400} d'
    return dt.strftime('%d/%m')


# ─────────────────────────────────────────────────────────────────────
#  Acciones (POST)
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
@require_POST
def notification_mark_read_api(request, pk):
    """Marca una notificación como leída."""
    n = get_object_or_404(Notification, pk=pk, user=request.user)
    if not n.read:
        n.read = True
        n.save(update_fields=['read'])
    return JsonResponse({'ok': True, 'read': True})


@login_required(login_url='login')
@require_POST
def notification_mark_all_read_api(request):
    """Marca TODAS las notificaciones como leídas."""
    Notification.objects.filter(user=request.user, read=False).update(read=True)
    return JsonResponse({'ok': True})


@login_required(login_url='login')
@require_POST
def notification_forward_api(request, pk):
    """Aprueba el reenvío de un correo seguro al correo real del usuario."""
    n = get_object_or_404(
        Notification.objects.select_related('related_email__alias__user'),
        pk=pk, user=request.user,
    )
    if n.type != 'forward_request' or n.status != 'pending':
        return JsonResponse({'ok': False, 'error': 'no_actionable'}, status=400)
    if not n.related_email:
        return JsonResponse({'ok': False, 'error': 'no_email'}, status=400)

    # force=True salta el check de opt-in (el usuario está aprobando MANUALMENTE
    # desde el panel de notificaciones, así que su voluntad ya está clara).
    from apps.mail.webhook import send_safe_email_forward
    send_safe_email_forward(n.related_email, force=True)

    n.status = 'approved'
    n.actioned_at = timezone.now()
    n.read = True
    n.save(update_fields=['status', 'actioned_at', 'read'])
    return JsonResponse({'ok': True, 'status': 'approved'})


@login_required(login_url='login')
@require_POST
def notification_clear_api(request):
    """
    Vacía notificaciones del usuario según el filtro:
      - all       → todas (excepto pendientes que requieren acción)
      - read      → solo las leídas
      - discarded → solo las descartadas
      - all_force → TODAS sin excepción (incluye pendientes — uso con confirmación fuerte)
    """
    scope = request.POST.get('scope', 'read')
    qs = Notification.objects.filter(user=request.user)

    if scope == 'read':
        qs = qs.filter(read=True)
    elif scope == 'discarded':
        qs = qs.filter(status='discarded')
    elif scope == 'all':
        # Todas EXCEPTO pendientes (para no perder acciones requeridas)
        qs = qs.exclude(type='forward_request', status='pending')
    elif scope == 'all_force':
        pass   # qs queda con TODAS
    else:
        return JsonResponse({'ok': False, 'error': 'invalid_scope'}, status=400)

    deleted = qs.count()
    qs.delete()
    return JsonResponse({'ok': True, 'deleted': deleted})


@login_required(login_url='login')
@require_POST
def notification_discard_api(request, pk):
    """Descarta la solicitud de reenvío (no se manda nada, pero el correo sigue en /bandeja/)."""
    n = get_object_or_404(Notification, pk=pk, user=request.user)
    if n.type != 'forward_request' or n.status != 'pending':
        return JsonResponse({'ok': False, 'error': 'no_actionable'}, status=400)
    n.status = 'discarded'
    n.actioned_at = timezone.now()
    n.read = True
    n.save(update_fields=['status', 'actioned_at', 'read'])
    return JsonResponse({'ok': True, 'status': 'discarded'})
