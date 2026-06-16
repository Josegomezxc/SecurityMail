"""
Vistas y APIs del sistema de notificaciones (panel de campana).

  - notification_list_view  → página completa con todas las notificaciones
  - notification_detail_view → detalle de una notificación + acciones
  - notification_unread_api  → JSON para refrescar el badge bajo demanda
  - notification_mark_read_api → marca una como leída
  - notification_forward_api  → aprueba reenvío (forward_request)
  - notification_discard_api  → descarta (forward_request)
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Notification


# ─────────────────────────────────────────────────────────────────────
#  Render: lista completa
# ─────────────────────────────────────────────────────────────────────

NOTIF_BATCH = 6   # notificaciones por "página" en el load-more


def _notifs_qs(user):
    """QuerySet base de notificaciones del usuario."""
    return Notification.objects.filter(user=user).select_related(
        'related_email', 'related_email__alias',
    )


@login_required(login_url='login')
def notification_list_view(request):
    """Página con notificaciones — carga diferida."""
    from django.db.models import Q
    full_qs = _notifs_qs(request.user)

    counts = {
        'all':       full_qs.count(),
        'unread':    full_qs.filter(read=False).count(),
        'pending':   full_qs.filter(status='pending').count(),
        'forwarded': full_qs.filter(Q(type='forwarded') | Q(status='approved')).count(),
        'discarded': full_qs.filter(status='discarded').count(),
    }

    notifs   = list(full_qs[:NOTIF_BATCH])
    has_more = counts['all'] > NOTIF_BATCH

    return render(request, 'notifications/notifications.html', {
        'notifications': notifs,
        'pending_count': counts['pending'],
        'counts':        counts,
        'has_more':      has_more,
        'next_offset':   len(notifs),
        'batch_size':    NOTIF_BATCH,
    })


@login_required(login_url='login')
def notification_more_api(request):
    """Siguiente lote de notificaciones como HTML parcial. Espera `?offset=N`."""
    try:
        offset = int(request.GET.get('offset') or 0)
    except ValueError:
        offset = 0
    offset = max(0, offset)

    qs = _notifs_qs(request.user)
    total = qs.count()
    batch = list(qs[offset:offset + NOTIF_BATCH])

    from django.template.loader import render_to_string
    html = render_to_string(
        'notifications/_notif_rows.html',
        {'notifications': batch},
        request=request,
    )

    new_offset = offset + len(batch)
    return JsonResponse({
        'ok':          True,
        'html':        html,
        'count':       len(batch),
        'next_offset': new_offset,
        'has_more':    new_offset < total,
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
    return render(request, 'notifications/notification_detail.html', {
        'notif': notif,
        'email': notif.related_email,
    })


# ─────────────────────────────────────────────────────────────────────
#  API: contador + últimas (para refrescar el dropdown del bell)
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def notification_unread_api(request):
    """JSON con contador y últimas N notificaciones para el dropdown."""
    qs = Notification.objects.filter(user=request.user).select_related(
        'related_email__alias',
    )
    unread_count  = qs.filter(read=False).count()
    pending_count = qs.filter(type='forward_request', status='pending').count()
    # Pendientes que además están sin leer — el sidebar lo usa para decidir
    # si pintar el badge en amarillo (urgencia) o en violeta (informativo).
    unread_pending_count = qs.filter(
        type='forward_request', status='pending', read=False,
    ).count()
    # IDs de las que están sin leer ahora mismo. La página /notificaciones/
    # los usa para sincronizar el estado visual de las filas en vivo (ej.
    # quitar la clase `unread` de las que ya leyó el usuario en otra
    # pestaña / al abrir el correo). Capamos a 500 para no inflar el JSON.
    unread_ids = list(qs.filter(read=False).values_list('id', flat=True)[:500])
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
        # Deep-link: si la notificación trae `target_url`, ese gana.
        # Si no, devolvemos la URL FIRMADA del detalle (el converter `sid`
        # exige token, no entero — un /notificaciones/94/ crudo cae a 404).
        link = n.target_url or reverse('notification_detail', kwargs={'pk': n.id})
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
            'url':        link,
        }

    # Marker server-side del último toast mostrado para este usuario.
    # Lo usa el JS del bell para evitar que el mismo toast se muestre en
    # OTRO dispositivo cuando el usuario ya lo vio en uno (ej. celular → PC).
    try:
        last_toast_id = request.user.profile.last_toast_notif_id or 0
    except Exception:
        last_toast_id = 0

    return JsonResponse({
        'unread_count':         unread_count,
        'pending_count':        pending_count,
        'unread_pending_count': unread_pending_count,
        'unread_ids':           unread_ids,
        'last_toast_id':        last_toast_id,
        'total':                qs.count(),
        'recent':               [_row(n) for n in recent],
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
def notification_mark_toast_shown_api(request):
    """
    Actualiza el marker server-side del último ID de notificación cuyo toast
    ya se mostró al usuario. Sincroniza la "vista" entre dispositivos:
    si el usuario ya vio el toast en su celular, no se vuelve a disparar
    cuando abre la app en su PC con la misma cuenta.

    POST body: last_id=<int>
    Sólo avanza el marker (nunca lo retrocede), por si llegan llamadas
    desordenadas desde 2 tabs abiertas en paralelo.
    """
    try:
        last_id = int(request.POST.get('last_id', 0))
    except (TypeError, ValueError):
        return JsonResponse({'ok': False, 'error': 'invalid_last_id'}, status=400)

    try:
        profile = request.user.profile
    except Exception:
        return JsonResponse({'ok': False, 'error': 'no_profile'}, status=400)

    if last_id > (profile.last_toast_notif_id or 0):
        profile.last_toast_notif_id = last_id
        profile.save(update_fields=['last_toast_notif_id'])

    return JsonResponse({'ok': True, 'last_toast_id': profile.last_toast_notif_id})


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

    # Disparamos el reenvío en un thread para no bloquear la respuesta HTTP.
    # Si falla, el error se loguea internamente en send_safe_email_forward.
    import threading
    from apps.mail.webhook import send_safe_email_forward
    threading.Thread(
        target=send_safe_email_forward,
        kwargs={'email': n.related_email, 'force': True},
        daemon=True,
    ).start()

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
