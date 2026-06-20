"""
Vistas del panel de administración (solo `is_staff=True`).

Vive en `apps.core` porque cruza dominios (usuarios + alias + correos
+ amenazas) — no pertenece exclusivamente a una sola app.

Incluye:
  - Dashboard global (stats del sistema completo).
  - Lista de usuarios con stats por usuario.
  - Detalle de un usuario.
  - Promover/degradar a admin.
  - Vista global de amenazas y alias.
"""
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from django.utils import timezone

from apps.aliases.models import Alias, AliasQuotaRequest
from apps.aliases.views import ALIAS_LIMIT_PER_USER, _user_alias_limit, _user_is_unlimited
from apps.mail.models import EmailMessage
from apps.notifications.models import Notification
from apps.accounts.services.auth_service import admin_required
from apps.core.services.stats_service import admin_global_stats


# Items por página en las listas paginadas del admin.
ADMIN_PAGE_SIZE  = 6
ADMIN_REQ_BATCH  = 6   # solicitudes de cupo (load-more)


def _admin_qs_params(request, exclude=('page',)):
    """Preserva los query params actuales (excepto los excluidos) al paginar."""
    params = {k: v for k, v in request.GET.items() if k not in exclude and v}
    return urlencode(params)


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

    return render(request, 'core/admin_dashboard.html', {
        **stats,
        'top_users':      top_users,
        'recent_threats': recent_threats,
    })


@admin_required
def admin_users_view(request):
    """
    Lista de usuarios paginada server-side.

    Query params:
      ?q=<texto>     busca en email / first_name / username
      ?role=<r>      all | admin | user | threats
      ?page=<n>      paginación (ADMIN_PAGE_SIZE)
    """
    base_qs = (
        User.objects.annotate(
            aliases_count = Count('aliases', distinct=True),
            emails_count  = Count('aliases__emails', distinct=True),
            threats_count = Count(
                'aliases__emails',
                filter=Q(aliases__emails__risk_score__gte=61),
                distinct=True,
            ),
        )
    )

    # Contadores GLOBALES (sobre todo el universo de usuarios)
    counts = {
        'all':     base_qs.count(),
        'admin':   base_qs.filter(is_staff=True).count(),
        'user':    base_qs.filter(is_staff=False).count(),
        'threats': base_qs.filter(threats_count__gt=0).count(),
    }

    qs = base_qs

    # ── Filtro por rol ─────────────────────────────────────────────────
    role = (request.GET.get('role') or 'all').strip().lower()
    if role == 'admin':
        qs = qs.filter(is_staff=True)
    elif role == 'user':
        qs = qs.filter(is_staff=False)
    elif role == 'threats':
        qs = qs.filter(threats_count__gt=0)
    else:
        role = 'all'

    # ── Búsqueda libre ─────────────────────────────────────────────────
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(email__icontains=q) |
            Q(first_name__icontains=q) |
            Q(username__icontains=q)
        )

    qs = qs.order_by('-date_joined')

    paginator = Paginator(qs, ADMIN_PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    return render(request, 'core/admin_users.html', {
        'page_obj':   page_obj,
        'users':      page_obj.object_list,
        'counts':     counts,
        'q':          q,
        'role':       role,
        'qs_params':  _admin_qs_params(request),
    })


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
    Vista global de amenazas (score ≥ 61) paginada server-side.

    Query params:
      ?q=<texto>     busca en remitente / asunto / alias / email del usuario
      ?level=<l>     all | critical (≥81) | high (61-80)
      ?page=<n>      paginación (ADMIN_PAGE_SIZE)
    """
    qs = EmailMessage.objects.filter(risk_score__gte=61).select_related(
        'alias', 'alias__user', 'analysis',
    ).order_by('-received_at')

    level = (request.GET.get('level') or '').strip()
    if level == 'critical':
        qs = qs.filter(risk_score__gte=81)
    elif level == 'high':
        qs = qs.filter(risk_score__gte=61, risk_score__lt=81)

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(from_email__icontains=q) |
            Q(subject__icontains=q) |
            Q(alias__address__icontains=q) |
            Q(alias__user__email__icontains=q)
        )

    # Stats del hero (sobre el base sin filtros, totales reales)
    from datetime import timedelta
    base = EmailMessage.objects.filter(risk_score__gte=61)
    total_threats   = base.count()
    critical_count  = base.filter(risk_score__gte=81).count()
    high_count      = total_threats - critical_count
    today_count     = base.filter(
        received_at__gte=timezone.now() - timedelta(days=1),
    ).count()

    paginator = Paginator(qs, ADMIN_PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    # Formato compacto para la columna "Recibido" — "23m", "23h", "1d", "4sem".
    # Usamos UNA sola unidad (la mayor que aplique), sin combinar h+m ni d+h.
    _now = timezone.now()
    for t in page_obj.object_list:
        delta = _now - t.received_at
        secs  = int(delta.total_seconds())
        if secs < 60:
            t.time_short = 'ahora'
        elif secs < 3600:                       # < 1 h  → "23m"
            t.time_short = f'{secs // 60}m'
        elif secs < 86400:                      # < 1 d  → "23h"
            t.time_short = f'{secs // 3600}h'
        elif secs < 86400 * 7:                  # < 1 sem → "6d"
            t.time_short = f'{secs // 86400}d'
        else:                                    # ≥ 1 sem → "4sem"
            t.time_short = f'{secs // (86400 * 7)}sem'

    return render(request, 'core/admin_threats.html', {
        'page_obj':        page_obj,
        'threats':         page_obj.object_list,
        'total_threats':   total_threats,
        'critical_count':  critical_count,
        'high_count':      high_count,
        'today_count':     today_count,
        'current_level':   level or 'all',
        'current_q':       q,
        'qs_params':       _admin_qs_params(request),
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

    return render(request, 'core/admin_aliases.html', {
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

    # Info para el editor de cupo de alias. quota_used cuenta TODOS los
    # alias creados (activos + destruidos) porque el cupo no se recicla.
    target_quota_used     = Alias.objects.filter(user=target).count()
    target_quota_limit    = _user_alias_limit(target)
    target_quota_extra    = target.profile.alias_quota_extra if hasattr(target, 'profile') else 0
    target_is_unlimited   = _user_is_unlimited(target)
    target_alias_unlimited = bool(
        getattr(target.profile, 'alias_unlimited', False)
    ) if hasattr(target, 'profile') else False

    return render(request, 'core/admin_user_detail.html', {
        'target':              target,
        'aliases':             aliases,
        'recent_emails':       recent_emails,
        'emails_total':        EmailMessage.objects.filter(alias__user=target).count(),
        'threats_total':       EmailMessage.objects.filter(
                                    alias__user=target, risk_score__gte=61).count(),
        'target_quota_used':   target_quota_used,
        'target_quota_limit':  target_quota_limit,
        'target_quota_extra':  target_quota_extra,
        'target_is_unlimited': target_is_unlimited,
        'target_alias_unlimited': target_alias_unlimited,
        'quota_base_limit':    ALIAS_LIMIT_PER_USER,
        'quota_min':           1,
        'quota_max':           999,
    })


@admin_required
@require_POST
def admin_set_alias_quota(request, pk):
    """
    Permite al admin ajustar el cupo TOTAL de alias de un usuario (puede
    subirlo o bajarlo). Internamente guardamos la diferencia respecto al
    base global (ALIAS_LIMIT_PER_USER) en UserProfile.alias_quota_extra,
    así si más adelante se aprueba/rechaza una solicitud, todo sigue
    consistente.

    POST:
        new_limit  → entero entre 1 y 50 (cupo TOTAL deseado)
    """
    target = get_object_or_404(User, pk=pk)

    if target.is_staff:
        messages.error(request, "Los administradores no tienen límite.")
        return redirect('admin_user_detail', pk=pk)

    try:
        new_limit = int(request.POST.get('new_limit', '0'))
    except (TypeError, ValueError):
        new_limit = -1

    if new_limit < 1 or new_limit > 999:
        messages.error(request, "El cupo debe estar entre 1 y 999 alias.")
        return redirect('admin_user_detail', pk=pk)

    profile = target.profile
    old_limit = _user_alias_limit(target)
    profile.alias_quota_extra = new_limit - ALIAS_LIMIT_PER_USER
    profile.save(update_fields=['alias_quota_extra'])

    # Notifica al usuario del cambio (solo si efectivamente cambió).
    if new_limit != old_limit:
        delta = new_limit - old_limit
        if delta > 0:
            title = 'Cupo de alias actualizado'
            msg   = f'El administrador subió tu cupo a {new_limit} alias (+{delta}).'
        else:
            title = 'Cupo de alias actualizado'
            msg   = f'El administrador redujo tu cupo a {new_limit} alias ({delta}).'
        Notification.objects.create(
            user=target, type='system', title=title, message=msg, status='done',
        )
        messages.success(
            request,
            f"Cupo de {target.email} actualizado: {old_limit} → {new_limit} alias.",
        )
    else:
        messages.success(request, "El cupo ya era el indicado, sin cambios.")

    return redirect('admin_user_detail', pk=pk)


@admin_required
@require_POST
def admin_toggle_alias_unlimited(request, pk):
    """
    Marca o desmarca al usuario como "alias sin límite". Cuando está
    activado, el usuario puede crear alias sin tope (igual que un staff,
    pero sin promoverlo a admin). El cupo numérico (alias_quota_extra)
    queda pausado mientras esté activo — al desactivarlo vuelve a regir.
    """
    target = get_object_or_404(User, pk=pk)

    if target.is_staff:
        messages.error(request, "Los administradores ya tienen acceso ilimitado.")
        return redirect('admin_user_detail', pk=pk)

    profile = target.profile
    was_unlimited = bool(profile.alias_unlimited)
    profile.alias_unlimited = not was_unlimited
    profile.save(update_fields=['alias_unlimited'])

    if profile.alias_unlimited:
        Notification.objects.create(
            user=target, type='system',
            title='Cupo ilimitado activado',
            message='El administrador te concedió alias ilimitados. Ya no tienes tope para crear nuevos.',
            status='done',
        )
        messages.success(
            request,
            f"{target.email} ahora tiene alias ilimitados.",
        )
    else:
        Notification.objects.create(
            user=target, type='system',
            title='Cupo ilimitado desactivado',
            message='El administrador retiró tu acceso ilimitado. Ahora estás sujeto al cupo normal.',
            status='done',
        )
        messages.success(
            request,
            f"Se retiró el acceso ilimitado a {target.email}.",
        )

    return redirect('admin_user_detail', pk=pk)


# ─────────────────────────────────────────────────────────────────────
#  Handlers de error — renderizan páginas custom con la estética del
#  proyecto. Los templates viven en `templates/` raíz (ver base_error.html).
#  Django los invoca automáticamente cuando DEBUG=False; en DEBUG=True
#  Django muestra su pantalla técnica, así que añadimos un catch-all en
#  config/urls.py para igual capturar las URLs inválidas.
#
#  Solo 404 y 500 — el proyecto no renderiza 400 ni 403 como páginas
#  (todos los errores de validación devuelven JSON desde endpoints AJAX,
#  y el acceso denegado se maneja con redirects, no con pantallas).
# ─────────────────────────────────────────────────────────────────────

def page_not_found_view(request, _exception=None):
    """404 — URL no encontrada (o catch-all del urls.py raíz)."""
    return render(request, '404.html', status=404)


def server_error_view(request):
    """500 — excepción no manejada del servidor. Django captura y llama acá."""
    return render(request, '500.html', status=500)


def permission_denied_view(request, exception=None):
    """403 — permisos insuficientes o acceso denegado."""
    return render(request, '403.html', {'exception': exception}, status=403)


def csrf_failure_view(request, reason=""):
    """403 CSRF — token inválido/expirado. Muestra página amigable."""
    return render(request, '403.html', {'reason': reason}, status=403)


# ─────────────────────────────────────────────────────────────────────
#  ADMIN — Solicitudes de cupo de alias
# ─────────────────────────────────────────────────────────────────────

@admin_required
def admin_alias_requests_view(request):
    """
    Lista de solicitudes de cupo paginada server-side (estilo bandeja).

    Query params:
      ?q=<texto>     busca en email / nombre / razón del usuario
      ?status=<s>    all | pending | approved | rejected
      ?page=<n>      número de página (ADMIN_PAGE_SIZE items)
    """
    base_qs = AliasQuotaRequest.objects.select_related(
        'user', 'user__profile', 'resolved_by',
    )

    # Contadores GLOBALES (no dependen del filtro actual)
    counts = {
        'all':      base_qs.count(),
        'pending':  base_qs.filter(status='pending').count(),
        'approved': base_qs.filter(status='approved').count(),
        'rejected': base_qs.filter(status='rejected').count(),
    }

    qs = base_qs
    status_filter = (request.GET.get('status') or 'all').strip().lower()
    if status_filter in ('pending', 'approved', 'rejected'):
        qs = qs.filter(status=status_filter)
    else:
        status_filter = 'all'

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(user__email__icontains=q) |
            Q(user__first_name__icontains=q) |
            Q(user__username__icontains=q) |
            Q(reason__icontains=q)
        )

    # Ordenamos: pending arriba (por created_at desc), después resueltas
    # (por resolved_at o created_at desc). Lo hacemos en Python sobre el
    # queryset paginado-pre-orden — luego paginamos el resultado.
    all_rows = list(qs)
    pending  = sorted(
        (r for r in all_rows if r.status == 'pending'),
        key=lambda r: r.created_at, reverse=True,
    )
    resolved = sorted(
        (r for r in all_rows if r.status != 'pending'),
        key=lambda r: (r.resolved_at or r.created_at), reverse=True,
    )
    ordered = pending + resolved

    paginator = Paginator(ordered, ADMIN_PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    # Tiempo corto ("23m", "23h", "1d", "4sem") para la columna "Tiempo"
    _now = timezone.now()
    for r in page_obj.object_list:
        ref = r.resolved_at or r.created_at
        delta = _now - ref
        secs  = int(delta.total_seconds())
        if   secs < 60:           r.time_short = 'ahora'
        elif secs < 3600:         r.time_short = f'{secs // 60}m'
        elif secs < 86400:        r.time_short = f'{secs // 3600}h'
        elif secs < 86400 * 7:    r.time_short = f'{secs // 86400}d'
        else:                     r.time_short = f'{secs // (86400 * 7)}sem'

    return render(request, 'core/admin_alias_requests.html', {
        'page_obj':      page_obj,
        'requests':      page_obj.object_list,
        'counts':        counts,
        'status_filter': status_filter,
        'q':             q,
        'qs_params':     _admin_qs_params(request),
    })


@admin_required
@require_POST
def admin_alias_request_resolve(request, pk):
    """
    Aprueba o rechaza una solicitud de cupo. El admin manda:
        action       = 'approve' | 'reject'
        granted      = entero (solo si approve; default = requested_amount)
        admin_note   = texto opcional
    Al aprobar: bumpea UserProfile.alias_quota_extra y notifica al usuario.
    Al rechazar: marca rejected y notifica al usuario con la nota del admin.
    """
    req = get_object_or_404(AliasQuotaRequest, pk=pk)

    if req.status != 'pending':
        messages.error(request, 'Esta solicitud ya fue resuelta.')
        return redirect('admin_alias_requests')

    action     = request.POST.get('action', '').strip()
    admin_note = (request.POST.get('admin_note') or '').strip()[:2000]

    if action == 'approve':
        # Cuánto le concedemos. Por defecto, lo que pidió. El admin puede
        # subir o bajar la cantidad en el formulario (1 a 10).
        try:
            granted = int(request.POST.get('granted') or req.requested_amount)
        except (TypeError, ValueError):
            granted = req.requested_amount
        granted = max(1, min(granted, 10))

        # Bumpea el cupo extra del perfil del usuario.
        profile = req.user.profile
        profile.alias_quota_extra = (profile.alias_quota_extra or 0) + granted
        profile.save(update_fields=['alias_quota_extra'])

        # Marca la solicitud como aprobada.
        req.status         = 'approved'
        req.granted_amount = granted
        req.admin_note     = admin_note
        req.resolved_by    = request.user
        req.resolved_at    = timezone.now()
        req.save()

        # Notifica al usuario (campana global). status='done' porque no
        # requiere acción del usuario — solo es informativo.
        # Separador '\n\n' entre mensaje del sistema y nota del admin para
        # que el detalle los renderice como bloques distintos.
        msg_user = f"Tu solicitud fue aprobada: +{granted} alias adicionales."
        if admin_note:
            msg_user += f"\n\n{admin_note}"
        Notification.objects.create(
            user=req.user,
            type='system',
            title='Solicitud aprobada',
            message=msg_user,
            status='done',
        )
        messages.success(request, f"Aprobada: {req.user.email} +{granted} alias.")

    elif action == 'reject':
        req.status      = 'rejected'
        req.admin_note  = admin_note
        req.resolved_by = request.user
        req.resolved_at = timezone.now()
        req.save()

        # Notifica al usuario.
        msg_user = "Tu solicitud de más alias fue rechazada."
        if admin_note:
            msg_user += f"\n\n{admin_note}"
        Notification.objects.create(
            user=req.user,
            type='system',
            title='Solicitud rechazada',
            message=msg_user,
            status='done',
        )
        messages.success(request, f"Rechazada la solicitud de {req.user.email}.")

    else:
        messages.error(request, 'Acción inválida.')

    return redirect('admin_alias_requests')


# ═════════════════════════════════════════════════════════════════════
#  SOLICITUDES DE RECUPERACIÓN DE CUENTA BLOQUEADA — admin
# ═════════════════════════════════════════════════════════════════════

@admin_required
def admin_account_recovery_requests_view(request):
    """
    Lista de solicitudes de recuperación de cuenta paginada server-side.
    Mismo patrón visual y de filtros que admin_alias_requests.
    """
    from apps.accounts.models import AccountRecoveryRequest

    base_qs = AccountRecoveryRequest.objects.select_related(
        'user', 'user__profile', 'resolved_by',
    )

    counts = {
        'all':      base_qs.count(),
        'pending':  base_qs.filter(status='pending').count(),
        'approved': base_qs.filter(status='approved').count(),
        'rejected': base_qs.filter(status='rejected').count(),
    }

    qs = base_qs
    status_filter = (request.GET.get('status') or 'all').strip().lower()
    if status_filter in ('pending', 'approved', 'rejected'):
        qs = qs.filter(status=status_filter)
    else:
        status_filter = 'all'

    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(user__email__icontains=q) |
            Q(user__first_name__icontains=q) |
            Q(user__username__icontains=q) |
            Q(reason__icontains=q)
        )

    all_rows = list(qs)
    pending  = sorted(
        (r for r in all_rows if r.status == 'pending'),
        key=lambda r: r.created_at, reverse=True,
    )
    resolved = sorted(
        (r for r in all_rows if r.status != 'pending'),
        key=lambda r: (r.resolved_at or r.created_at), reverse=True,
    )
    ordered = pending + resolved

    paginator = Paginator(ordered, ADMIN_PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    _now = timezone.now()
    for r in page_obj.object_list:
        ref = r.resolved_at or r.created_at
        delta = _now - ref
        secs  = int(delta.total_seconds())
        if   secs < 60:           r.time_short = 'ahora'
        elif secs < 3600:         r.time_short = f'{secs // 60}m'
        elif secs < 86400:        r.time_short = f'{secs // 3600}h'
        elif secs < 86400 * 7:    r.time_short = f'{secs // 86400}d'
        else:                     r.time_short = f'{secs // (86400 * 7)}sem'

    return render(request, 'core/admin_account_recovery_requests.html', {
        'page_obj':      page_obj,
        'requests':      page_obj.object_list,
        'counts':        counts,
        'status_filter': status_filter,
        'q':             q,
        'qs_params':     _admin_qs_params(request),
    })


@admin_required
@require_POST
def admin_account_recovery_request_resolve(request, pk):
    """
    Aprueba o rechaza una solicitud de recuperación de cuenta. Form params:
        action      = 'approve' | 'reject'
        admin_note  = texto opcional (notificación al usuario)

    Al APROBAR: User.is_active = True, se limpian todos los campos de lock
    del profile (failed attempts, temp lock, permanent lock).
    Al RECHAZAR: la cuenta queda bloqueada. El usuario recibe notificación.
    """
    from apps.accounts.models import AccountRecoveryRequest
    from apps.accounts.services.login_lock_service import unlock_user_after_recovery

    req = get_object_or_404(AccountRecoveryRequest, pk=pk)

    if req.status != 'pending':
        messages.error(request, 'Esta solicitud ya fue resuelta.')
        return redirect('admin_account_recovery_requests')

    action     = request.POST.get('action', '').strip()
    admin_note = (request.POST.get('admin_note') or '').strip()[:2000]

    if action == 'approve':
        unlock_user_after_recovery(req.user, request.user)

        req.status      = 'approved'
        req.admin_note  = admin_note
        req.resolved_by = request.user
        req.resolved_at = timezone.now()
        req.save()

        msg_user = ("Tu solicitud de recuperación fue aprobada. "
                    "Ya podés iniciar sesión normalmente.")
        if admin_note:
            msg_user += f"\n\n{admin_note}"
        Notification.objects.create(
            user=req.user,
            type='system',
            title='Cuenta recuperada',
            message=msg_user,
            status='done',
        )

        # Email al usuario avisando que su cuenta fue reactivada — no rompe
        # el flujo si falla (la cuenta ya fue desbloqueada en BD).
        try:
            from apps.accounts.services.recovery_email_service import (
                send_account_reactivated_email,
            )
            display_name = (req.user.get_full_name() or req.user.email
                            or req.user.username)
            admin_username = (request.user.get_full_name()
                              or request.user.username)
            send_account_reactivated_email(
                to_email       = req.user.email,
                display_name   = display_name,
                admin_note     = admin_note,
                admin_username = admin_username,
            )
        except Exception as e:
            print(f"[admin_account_recovery_request_resolve] No se pudo enviar el email de reactivación: {e}")

        messages.success(request, f"Cuenta de {req.user.email} reactivada.")

    elif action == 'reject':
        req.status      = 'rejected'
        req.admin_note  = admin_note
        req.resolved_by = request.user
        req.resolved_at = timezone.now()
        req.save()

        msg_user = ("Tu solicitud de recuperación de cuenta fue rechazada. "
                    "La cuenta sigue bloqueada.")
        if admin_note:
            msg_user += f"\n\n{admin_note}"
        Notification.objects.create(
            user=req.user,
            type='system',
            title='Solicitud de recuperación rechazada',
            message=msg_user,
            status='done',
        )
        messages.success(request, f"Rechazada la recuperación de {req.user.email}.")

    else:
        messages.error(request, 'Acción inválida.')

    return redirect('admin_account_recovery_requests')
