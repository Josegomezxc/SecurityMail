"""
Generación automática de etiquetas y direcciones para alias desechables.

Estrategia primaria: usamos la API de Groq (modelo Llama) para pedirle
al LLM un alias creativo del tipo `adjetivo sustantivo` EN ESPAÑOL.
Si Groq no responde (timeout, error, sin API key, respuesta inválida),
caemos a un generador LOCAL clásico con bancos curados en inglés — así
la creación de alias NUNCA depende de un servicio externo para funcionar.

Formato final: PascalCase concatenado (sin guiones, sin espacios).
Ejemplos: TigrePlateado, LoboCosmico, RubySpecter, MidnightFalcon...
La dirección queda como `TigrePlateado_x7k2m@dockershield.lat`.
"""
import os
import random
import re
import string

from django.conf import settings


DEFAULT_DOMAIN = "dockershield.lat"   # Fallback si no hay settings.MAIL_DOMAIN

# Modelo barato + rápido — esto es un "two-word generator", no necesita
# 70B. Si el modelo cambia o desaparece, el fallback local sigue funcionando.
_GROQ_MODEL = 'llama-3.1-8b-instant'
_GROQ_TIMEOUT_S = 4.0   # corto a propósito: si la API se demora, fallback


# ── Bancos de palabras curados (FALLBACK local) ──────────────────────
# Se usan SOLO cuando Groq falla. Inglés, neutros, sin términos
# políticos / raciales / sexuales / vulgares.
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


# Patrón intermedio: el LLM y el fallback producen primero "palabra-palabra"
# en lowercase ASCII (sin tildes, sin ñ), y luego convertimos a PascalCase.
# Mantener ASCII puro evita problemas con los servidores SMTP que rechazan
# caracteres internacionales en la parte local del email.
_LABEL_RE = re.compile(r'^[a-z]{2,15}-[a-z]{2,15}$')


def _to_pascal(label_hyphenated: str) -> str:
    """
    Convierte 'tigre-plateado' → 'TigrePlateado'.
    Asume que la entrada ya pasó _LABEL_RE (lowercase + un solo guión).
    """
    return ''.join(part.capitalize() for part in label_hyphenated.split('-'))


def _generate_label_via_groq() -> str:
    """
    Pide al LLM (Groq) un alias creativo EN ESPAÑOL en formato
    `adjetivo-sustantivo`. Devuelve la etiqueta limpia en formato
    intermedio (lowercase con guión), o '' si algo salió mal.

    El llamador `generate_creative_label()` se encarga de convertir
    a PascalCase y de caer al fallback si vuelve vacío.
    """
    api_key = (os.environ.get('GROQ_API_KEY') or '').strip()
    if not api_key:
        return ''

    try:
        from groq import Groq
        client = Groq(api_key=api_key, timeout=_GROQ_TIMEOUT_S)

        # Prompt en español, muy explícito. Pedimos SIN tildes ni ñ
        # porque la dirección de correo no acepta esos caracteres en la
        # parte local de forma confiable a través de servidores SMTP.
        system_msg = (
            "Generas alias creativos de dos palabras en español, estilo nombre "
            "clave. Responde SOLO con el alias, nada más: sin comillas, sin "
            "puntuación final, sin explicación, sin markdown."
        )
        user_msg = (
            "Genera UN alias creativo en español, formato adjetivo-sustantivo "
            "(dos palabras en español unidas por un guión, todo en minúscula, "
            "solo letras de la a a la z, SIN tildes, SIN eñe, sin números). "
            "Ejemplos válidos: tigre-plateado, lobo-cosmico, halcon-dorado, "
            "dragon-carmesi, fenix-radiante, leon-arcano. "
            "Evita: nombres propios, marcas, palabras vulgares, políticas, "
            "sexuales o raciales. Sé creativo y varía AMBAS palabras (no uses "
            "siempre las mismas). Responde SOLO con el alias en una sola línea."
        )

        response = client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {'role': 'system', 'content': system_msg},
                {'role': 'user',   'content': user_msg},
            ],
            max_tokens=20,
            temperature=1.0,   # alta variedad — queremos máxima diversidad
        )
        raw = (response.choices[0].message.content or '').strip()
        return _sanitize_label(raw)
    except Exception as e:
        # No spammeamos logs por esto — print simple y fallback silencioso.
        print(f"[alias_service] Groq alias generation failed: {e}")
        return ''


def _sanitize_label(raw: str) -> str:
    """
    Limpia la respuesta del LLM y valida que cumpla el formato intermedio
    `palabra-palabra` (lowercase ASCII). Devuelve la etiqueta limpia o ''
    si no pasa la validación.

    Cosas que arregla:
      'tigre-plateado'              → OK
      '"tigre-plateado"'            → quita comillas
      'Aquí va: tigre-plateado.'    → extrae el token con regex
      'Tigre-Plateado'              → lowercase
      'tigre plateado'              → reemplaza espacio por guión
      'tigré-plateado'              → falla (tildes no permitidas)
      'tigre-pequeño'               → falla (ñ no permitida)
    """
    if not raw:
        return ''
    raw = raw.strip().strip('"\'`.,;:').strip()
    # Si el modelo agregó explicación, intentamos extraer un token
    # tipo "palabra-palabra" o "palabra palabra".
    m = re.search(r'\b([a-zA-Z]{2,15}[-\s][a-zA-Z]{2,15})\b', raw)
    if not m:
        return ''
    candidate = m.group(1).lower().replace(' ', '-')
    candidate = re.sub(r'-+', '-', candidate).strip('-')
    if not _LABEL_RE.match(candidate):
        return ''
    return candidate


def _generate_label_local() -> str:
    """
    Generador LOCAL clásico — adjetivo + sustantivo random de los bancos
    en inglés. Se usa como fallback cuando Groq falla. Devuelve el formato
    intermedio `palabra-palabra` que después se pasa por _to_pascal().
    """
    adj  = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{adj}-{noun}"


def generate_creative_label() -> str:
    """
    Devuelve una etiqueta creativa en formato PascalCase concatenado
    (ej: 'TigrePlateado', 'RubySpecter', 'MidnightFalcon').

    Primero intenta con Groq (LLM) para obtener alias en ESPAÑOL con
    máxima variedad. Si la API no responde o devuelve algo inválido,
    cae al generador local con bancos en inglés. El llamador no necesita
    preocuparse — siempre recibe una etiqueta válida.
    """
    label = _generate_label_via_groq()
    if not label:
        label = _generate_label_local()
    return _to_pascal(label)


def generate_alias_address(label: str = '') -> str:
    """
    Genera una dirección única tipo `TigrePlateado_x7k2m@dominio`.

    Si no se pasa label (caso normal: el usuario no lo escribe), se
    genera automáticamente con `generate_creative_label()`.

    El label se preserva tal cual (PascalCase, sin lowercase) — la parte
    local del email es case-sensitive en el RFC, pero los servidores la
    tratan como case-insensitive, así que es solo cosmético/legibilidad.
    """
    domain = getattr(settings, 'MAIL_DOMAIN', DEFAULT_DOMAIN)

    if not label:
        label = generate_creative_label()

    slug = label[:30] or 'Alias'
    code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{slug}_{code}@{domain}"
