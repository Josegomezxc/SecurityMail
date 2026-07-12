
import time

from apps.aliases.models import Alias, AliasQuotaRequest
from apps.mail.models import EmailMessage, SentEmail, Draft
from apps.notifications.models import Notification
from apps.sandbox.models import SandboxAnalysis
from apps.accounts.models import AccountRecoveryRequest
from apps.accounts.services.profile_service import get_user_initials, get_user_color

CACHE_TTL = 30  


def _get_cached_counts(request):
    key = 'sidebar_counts_cache'
    cached = request.session.get(key)
    if cached and time.time() - cached['ts'] < CACHE_TTL:
        return cached['data']
    return None


def _set_cached_counts(request, data):
    request.session['sidebar_counts_cache'] = {
        'ts': time.time(), 'data': data,
    }


def sidebar_counts(request):

    if not request.user.is_authenticated:
        return {
            'alias_count':         0,
            'unread_count':        0,
            'threats_count':       0,
            'notif_pending_count':         0,
            'notif_unread_count':          0,
            'notif_unread_pending_count':  0,
            'drafts_count':        0,
            'trash_count':         0,
            'active_aliases':      [],
            'alias_requests_pending_count': 0,
            'account_recovery_pending_count': 0,
            'avatar_initials':     '',
            'avatar_color':        '#7c5cff',
        }

    user = request.user


    active_aliases = list(
        Alias.objects.filter(user=user, is_active=True).order_by('-created_at')
    )
    alias_count = len(active_aliases)

    cached = _get_cached_counts(request)
    if cached is not None:
        return {
            'alias_count':         alias_count,
            'active_aliases':      active_aliases,
            **cached,
        }

    unread_count = EmailMessage.objects.filter(
        alias__user=user, read=False, deleted_at__isnull=True,
    ).count()

    threats_count = SandboxAnalysis.objects.filter(
        email__alias__user=user, risk_score__gte=61
    ).count()

    notif_qs = Notification.objects.filter(user=user)
    notif_pending_count = notif_qs.filter(
        type='forward_request', status='pending'
    ).count()
    notif_unread_count = notif_qs.filter(read=False).count()
    notif_unread_pending_count = notif_qs.filter(
        type='forward_request', status='pending', read=False,
    ).count()

    drafts_count = Draft.objects.filter(user=user, deleted_at__isnull=True).count()

    trash_count = (
        EmailMessage.objects.filter(alias__user=user, deleted_at__isnull=False).count()
        + SentEmail.objects.filter(alias__user=user, deleted_at__isnull=False).count()
    )
    trash_count += Draft.objects.filter(user=user, deleted_at__isnull=False).count()

    alias_requests_pending_count = (
        AliasQuotaRequest.objects.filter(status='pending').count()
        if user.is_staff else 0
    )

    account_recovery_pending_count = (
        AccountRecoveryRequest.objects.filter(status='pending').count()
        if user.is_staff else 0
    )

    cached_data = {
        'unread_count':        unread_count,
        'threats_count':       threats_count,
        'notif_pending_count':         notif_pending_count,
        'notif_unread_count':          notif_unread_count,
        'notif_unread_pending_count':  notif_unread_pending_count,
        'drafts_count':        drafts_count,
        'trash_count':         trash_count,
        'alias_requests_pending_count': alias_requests_pending_count,
        'account_recovery_pending_count': account_recovery_pending_count,
        'avatar_initials':     get_user_initials(user),
        'avatar_color':        get_user_color(user),
    }

    _set_cached_counts(request, cached_data)

    return {
        'alias_count':         alias_count,
        'active_aliases':      active_aliases,
        **cached_data,
    }
