"""
Envío centralizado de correos usando el backend de Django (Gmail SMTP).

La configuración vive en `settings.py` (EMAIL_BACKEND, EMAIL_HOST_USER, etc.)
y se lee desde el .env. Si no hay credenciales de Gmail, Django cae al
backend de consola automáticamente, así que en desarrollo el correo
aparece impreso en el terminal.
"""
from typing import Tuple

from django.conf import settings
from django.core.mail import EmailMessage


def send_email(to: str, subject: str, html: str) -> Tuple[bool, str]:
    """
    Envía un correo HTML. Devuelve (exito, mensaje_info).
    El remitente se toma de settings.DEFAULT_FROM_EMAIL.
    """
    if not to:
        return False, "Destinatario vacío."

    try:
        msg = EmailMessage(
            subject=subject,
            body=html,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to],
        )
        msg.content_subtype = 'html'   # Indica que el body es HTML
        msg.send(fail_silently=False)
        return True, 'sent'
    except Exception as e:
        return False, f'error: {e}'


def get_site_url() -> str:
    """URL pública del sitio, sin slash final (se usa en links de correos)."""
    return (getattr(settings, 'SITE_URL', 'http://127.0.0.1:8000') or '').rstrip('/')
