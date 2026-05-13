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
from django.contrib.auth.models import User
from django.contrib import messages
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

    # Info para el editor de cupo de alias. quota_used cuenta TODOS los
    # alias creados (activos + destruidos) porque el cupo no se recicla.
    target_quota_used     = Alias.objects.filter(user=target).count()
    target_quota_limit    = _user_alias_limit(target)
    target_quota_extra    = target.profile.alias_quota_extra if hasattr(target, 'profile') else 0
    target_is_unlimited   = _user_is_unlimited(target)
    target_alias_unlimited = bool(
        getattr(target.profile, 'alias_unlimited', False)
    ) if hasattr(target, 'profile') else False

    return render(request, 'admin_user_detail.html', {
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
            title = '✅ Cupo de alias actualizado'
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
            title='✨ Cupo ilimitado activado',
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
#  Handlers de error — devolvemos al usuario a la página de la que venía
#  (HTTP_REFERER). Nunca mostramos pantalla de error ni filtramos rutas.
#  Si no hay referer (escribieron la URL a mano en una pestaña nueva),
#  caemos al dashboard si están logueados o al login si no lo están.
# ─────────────────────────────────────────────────────────────────────

def _safe_back(request):
    referer = request.META.get('HTTP_REFERER', '')
    # Solo aceptamos refs del mismo host — evita que un atacante con un
    # link externo logre que terceros vuelvan a su sitio (open redirect).
    host = request.get_host()
    if referer and (host in referer):
        return redirect(referer)
    fallback = 'dashboard' if request.user.is_authenticated else 'login'
    return redirect(fallback)


def page_not_found_view(request, _exception=None):
    return _safe_back(request)


def server_error_view(request):
    return _safe_back(request)


# ─────────────────────────────────────────────────────────────────────
#  ADMIN — Solicitudes de cupo de alias
# ─────────────────────────────────────────────────────────────────────

@admin_required
def admin_alias_requests_view(request):
    """
    Lista todas las solicitudes de cupo de alias. Por defecto muestra las
    `pending` arriba; las `approved`/`rejected` se muestran más abajo como
    histórico. Permite filtrar via `?status=`.
    """
    status_filter = request.GET.get('status', 'all')
    qs = AliasQuotaRequest.objects.select_related('user', 'user__profile', 'resolved_by')

    if status_filter in ('pending', 'approved', 'rejected'):
        qs = qs.filter(status=status_filter)

    requests_list = list(qs.order_by(
        # Las pending arriba, luego histórico por fecha descendente.
        '-status',  # pending > approved > rejected lexicograficamente NO sirve
        '-created_at',
    ))
    # Reordenamos manualmente: pending primero, luego por created_at desc.
    pending  = [r for r in requests_list if r.status == 'pending']
    resolved = [r for r in requests_list if r.status != 'pending']
    pending.sort(key=lambda r: r.created_at, reverse=True)
    resolved.sort(key=lambda r: (r.resolved_at or r.created_at), reverse=True)
    requests_list = pending + resolved

    # Contadores para las pills de filtro
    counts = {
        'all':      AliasQuotaRequest.objects.count(),
        'pending':  AliasQuotaRequest.objects.filter(status='pending').count(),
        'approved': AliasQuotaRequest.objects.filter(status='approved').count(),
        'rejected': AliasQuotaRequest.objects.filter(status='rejected').count(),
    }

    return render(request, 'admin_alias_requests.html', {
        'requests':      requests_list,
        'counts':        counts,
        'status_filter': status_filter,
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
        msg_user = f"Tu solicitud fue aprobada: +{granted} alias adicionales."
        if admin_note:
            msg_user += f"  Nota: {admin_note}"
        Notification.objects.create(
            user=req.user,
            type='system',
            title='✅ Solicitud aprobada',
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
            msg_user += f"  Motivo: {admin_note}"
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
