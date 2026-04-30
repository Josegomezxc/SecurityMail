# apps/core/context_processors.py

from apps.aliases.models import Alias
from apps.mail.models import EmailMessage
from apps.notifications.models import Notification
from apps.sandbox.models import SandboxAnalysis


def sidebar_counts(request):
    """
    Inyecta los contadores del sidebar en TODOS los templates automáticamente.
    Se registra en settings.py → TEMPLATES → OPTIONS → context_processors.
    """
    if not request.user.is_authenticated:
        return {
            'alias_count':         0,
            'unread_count':        0,
            'threats_count':       0,
            'notif_pending_count': 0,
            'notif_unread_count':  0,
        }

    user = request.user

    alias_count = Alias.objects.filter(
        user=user, is_active=True
    ).count()

    unread_count = EmailMessage.objects.filter(
        alias__user=user, read=False
    ).count()

    threats_count = SandboxAnalysis.objects.filter(
        email__alias__user=user, risk_score__gte=61
    ).count()

    notif_qs = Notification.objects.filter(user=user)
    notif_pending_count = notif_qs.filter(
        type='forward_request', status='pending'
    ).count()
    notif_unread_count = notif_qs.filter(read=False).count()

    return {
        'alias_count':         alias_count,
        'unread_count':        unread_count,
        'threats_count':       threats_count,
        'notif_pending_count': notif_pending_count,
        'notif_unread_count':  notif_unread_count,
    }
