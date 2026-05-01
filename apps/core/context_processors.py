# apps/core/context_processors.py

from apps.aliases.models import Alias
from apps.mail.models import EmailMessage, SentEmail, Draft
from apps.notifications.models import Notification
from apps.sandbox.models import SandboxAnalysis
from apps.accounts.services.profile_service import get_user_initials, get_user_color


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
            'drafts_count':        0,
            'trash_count':         0,
            'avatar_initials':     '',
            'avatar_color':        '#7c5cff',
        }

    user = request.user

    alias_count = Alias.objects.filter(
        user=user, is_active=True
    ).count()

    # No contamos los correos en papelera como "no leídos" — están borrados
    # desde el punto de vista del usuario.
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

    drafts_count = Draft.objects.filter(user=user, deleted_at__isnull=True).count()

    # Papelera: recibidos + enviados + borradores con deleted_at != null
    trash_count = (
        EmailMessage.objects.filter(alias__user=user, deleted_at__isnull=False).count()
        + SentEmail.objects.filter(alias__user=user, deleted_at__isnull=False).count()
    )
    trash_count += Draft.objects.filter(user=user, deleted_at__isnull=False).count()

    return {
        'alias_count':         alias_count,
        'unread_count':        unread_count,
        'threats_count':       threats_count,
        'notif_pending_count': notif_pending_count,
        'notif_unread_count':  notif_unread_count,
        'drafts_count':        drafts_count,
        'trash_count':         trash_count,
        # Iniciales y color del avatar — disponibles en TODAS las páginas
        # para que el sidebar y el perfil muestren lo mismo (ej. "JG" para
        # un usuario "Jose Gomez", siempre con el mismo color).
        'avatar_initials':     get_user_initials(user),
        'avatar_color':        get_user_color(user),
    }
