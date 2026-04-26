"""
Generación de direcciones únicas para alias desechables.

La lógica de construcción del string `usuario_xxxx@dominio` vive aquí
para que las vistas solo se preocupen de recibir el label y guardar.
"""
import random
import string

from django.conf import settings


DEFAULT_DOMAIN = "securemail.com"   # Fallback si no hay settings.MAIL_DOMAIN


def generate_alias_address(label: str) -> str:
    """
    Convierte un label humano ('Amazon', 'Foro Reddit') en una dirección
    de correo única del tipo `amazon_x7k2m1@dominio`.
    """
    domain = getattr(settings, 'MAIL_DOMAIN', DEFAULT_DOMAIN)

    slug = (label or '').lower().replace(' ', '_')[:20] or 'alias'
    code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{slug}_{code}@{domain}"
