"""
Generación automática de etiquetas y direcciones para alias desechables.

El usuario YA NO escribe nada — el sistema genera por su cuenta una
etiqueta creativa (adjetivo + sustantivo) y la combina con un sufijo
aleatorio para garantizar unicidad en la BD.

Ejemplos: silver-tiger, bright-falcon, mystic-storm, golden-wolf...
"""
import random
import string

from django.conf import settings


DEFAULT_DOMAIN = "dockershield.lat"   # Fallback si no hay settings.MAIL_DOMAIN


# ── Bancos de palabras curados (limpios, neutros, memorables) ────────
# Todos en inglés (estándar de "code names") — son palabras cortas,
# pronunciables y siempre seguras (no hay términos políticos, raciales,
# sexuales ni vulgares).
ADJECTIVES = [
    'silver', 'golden', 'crimson', 'azure', 'emerald', 'cosmic',
    'mystic', 'bright', 'swift', 'quiet', 'fierce', 'noble',
    'ancient', 'lunar', 'solar', 'crystal', 'shadow', 'radiant',
    'velvet', 'frozen', 'electric', 'savage', 'gentle', 'royal',
    'wild', 'sacred', 'iron', 'misty', 'blazing', 'silent',
    'amber', 'jade', 'arctic', 'polar', 'rapid', 'stellar',
    'nebula', 'phantom', 'thunder', 'crystal', 'obsidian', 'sapphire',
    'ruby', 'topaz', 'platinum', 'titanium', 'orbital', 'quantum',
]

NOUNS = [
    'tiger', 'falcon', 'wolf', 'eagle', 'lion', 'panther',
    'phoenix', 'dragon', 'griffin', 'hawk', 'fox', 'lynx',
    'storm', 'thunder', 'comet', 'meteor', 'nebula', 'galaxy',
    'arrow', 'blade', 'spear', 'shield', 'crown', 'tower',
    'forest', 'river', 'mountain', 'ocean', 'desert', 'aurora',
    'horizon', 'summit', 'vortex', 'cipher', 'echo', 'pulse',
    'circuit', 'matrix', 'orbit', 'pixel', 'vector', 'beacon',
    'specter', 'ranger', 'hunter', 'guardian', 'sentinel', 'paladin',
]


def generate_creative_label() -> str:
    """
    Devuelve una etiqueta creativa tipo 'silver-tiger', 'cosmic-falcon'.
    Cero palabras vulgares, cero información personal, fácil de recordar.
    """
    adj  = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{adj}-{noun}"


def generate_alias_address(label: str = '') -> str:
    """
    Genera una dirección única tipo `silver-tiger_x7k2m1@dominio`.

    Si no se pasa label (caso normal en este proyecto: el usuario no lo
    escribe), se genera automáticamente con `generate_creative_label()`.
    """
    domain = getattr(settings, 'MAIL_DOMAIN', DEFAULT_DOMAIN)

    if not label:
        label = generate_creative_label()

    slug = label.lower().replace(' ', '-')[:30] or 'alias'
    code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{slug}_{code}@{domain}"
