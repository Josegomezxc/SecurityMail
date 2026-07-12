
import os
from typing import Tuple

from django.conf import settings


def send_email(to: str, subject: str, html: str) -> Tuple[bool, str]:

    if not to:
        return False, "Destinatario vacío."

    api_key = os.environ.get('RESEND_API_KEY', '').strip()
    if not api_key:
        return False, 'RESEND_API_KEY no configurada'

    try:
        import resend
        resend.api_key = api_key
        domain = getattr(settings, 'MAIL_DOMAIN', 'dockershield.lat')
        params = {
            'from': f"DockerShield <noreply@{domain}>",
            'to': [to],
            'subject': subject,
            'html': html,
        }
        resend.Emails.send(params)
        return True, 'sent'
    except Exception as e:
        return False, f'error: {e}'


def get_site_url() -> str:
    """URL pública del sitio, sin slash final (se usa en links de correos)."""
    return (getattr(settings, 'SITE_URL', 'http://127.0.0.1:8000') or '').rstrip('/')
