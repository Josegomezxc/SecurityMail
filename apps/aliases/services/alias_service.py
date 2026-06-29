"""
Generación automática de etiquetas y direcciones para alias desechables con enfoque corporativo.

Estrategia primaria: usamos la API de Groq (modelo Llama) para pedirle
al LLM un alias profesional, serio y neutro del tipo `palabra-palabra` EN ESPAÑOL.
Si Groq no responde (timeout, error, sin API key, respuesta inválida),
caemos a un generador LOCAL clásico con bancos curados en español técnico — así
la creación de alias NUNCA depende de un servicio externo para funcionar.

Formato final: PascalCase concatenado (sin guiones, sin espacios).
Ejemplos: NodoSeguro, CapaAlfa, DatosNucleo, RedHibrida...
La dirección final queda completamente en minúsculas: `nodoseguro_x7k2m@dockershield.lat`.
"""
import os
import random
import re
import string

from django.conf import settings


DEFAULT_DOMAIN = "dockershield.lat"   # Fallback si no hay settings.MAIL_DOMAIN

# Modelo barato + rápido — esto es un "two-word generator", no necesita 70B.
_GROQ_MODEL = 'llama-3.1-8b-instant'
_GROQ_TIMEOUT_S = 4.0   # corto a propósito: si la API se demora, fallback


# ── Bancos de palabras curados (FALLBACK local) ──────────────────────
# Se usan SOLO cuando Groq falla. Enfoque corporativo, técnico y neutral.
# Exclusivamente caracteres a-z (sin tildes, sin eñes).
ADJECTIVES = [
    'seguro', 'nube', 'ciber', 'datos', 'inteligente', 'tec',
    'alfa', 'beta', 'base', 'principal', 'puro', 'red',
    'enlace', 'flujo', 'malla', 'nodo', 'sincro', 'meta',
    'fijo', 'vertice', 'vortex', 'matriz', 'vector', 'lineal',
    'proxy', 'packet', 'pixel', 'logico', 'macro', 'micro',
    'rapido', 'remoto', 'global', 'local', 'directo', 'hibrido',
]

NOUNS = [
    'escudo', 'guarda', 'boveda', 'pila', 'capa', 'puerto',
    'acceso', 'portal', 'centro', 'malla', 'zona', 'cubo',
    'sala', 'modulo', 'correo', 'buzon', 'paquete', 'linea',
    'rastro', 'ruta', 'camino', 'registro', 'marca', 'signo',
    'codigo', 'script', 'host', 'sistema', 'taller', 'banco',
    'huella', 'consola', 'bloque', 'cierre', 'llave', 'panel',
]


# Patrón intermedio: el LLM y el fallback producen primero "palabra-palabra"
# en lowercase ASCII (sin tildes, sin ñ), y luego convertimos a PascalCase.
_LABEL_RE = re.compile(r'^[a-z]{2,15}-[a-z]{2,15}$')


def _to_pascal(label_hyphenated: str) -> str:
    """
    Convierte 'nodo-seguro' → 'NodoSeguro'.
    Asume que la entrada ya pasó _LABEL_RE (lowercase + un solo guión).
    """
    return ''.join(part.capitalize() for part in label_hyphenated.split('-'))


def _generate_label_via_groq() -> str:
    """
    Pide al LLM (Groq) un alias profesional EN ESPAÑOL en formato
    `palabra-palabra` utilizando restricciones y un tono estrictamente corporativo.
    Devuelve la etiqueta limpia en formato lowercase con guión.
    """
    api_key = (os.environ.get('GROQ_API_KEY') or '').strip()
    if not api_key:
        return ''

    try:
        from groq import Groq
        client = Groq(api_key=api_key, timeout=_GROQ_TIMEOUT_S)

        system_msg = (
            "Eres un backend automatizado de generación de identificadores técnicos corporativos. "
            "Tu única tarea es devolver un par de términos de TI/infraestructura en el formato exacto solicitado. "
            "No saludes, no expliques, no uses markdown. Tu respuesta será procesada por un script."
        )
        
        user_msg = (
            "Genera UN alias profesional en español con el siguiente formato estricto: "
            "dos términos técnicos o corporativos unidos por un guión medio, todo en minúscula, "
            "utilizando exclusivamente letras de la a a la z del alfabeto inglés, SIN tildes, "
            "SIN la letra ñ, SIN números, SIN espacios adicionales.\n\n"
            "Ejemplos válidos de la estructura y tono buscado: nodo-seguro, capa-alfa, datos-nucleo, "
            "red-hibrida, enlace-directo, casilla-virtual, bloque-codigo, nube-privada, puente-digital.\n\n"
            "Restricciones absolutas que debes respetar:\n"
            "- PROHIBIDO nombres de animales de cualquier tipo\n"
            "- PROHIBIDO colores, especially de fantasía o poéticos (azul, carmesi, dorado, esmeralda, rubi, zafiro, etc.)\n"
            "- PROHIBIDO elementos de fantasía, ciencia ficción o mitología (magico, cosmico, fenix, dragon, titan, quasar, nebula, etc.)\n"
            "- PROHIBIDO nombres propios de personas, marcas conocidas o referencias culturales\n\n"
            "El alias debe proyectar: formalidad, credibilidad institucional, lenguaje técnico-corporativo, "
            "seriedad empresarial y neutralidad profesional. Evita cualquier connotación poética, literaria, lúdica o informal.\n\n"
            "Responde ÚNICAMENTE con el alias generado, en una sola línea de texto, sin comillas, sin explicaciones, "
            "sin saludos, sin formato adicional."
        )

        response = client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {'role': 'system', 'content': system_msg},
                {'role': 'user',   'content': user_msg},
            ],
            max_tokens=15,       # Suficiente para dos palabras cortas con guión
            temperature=0.7,     # Consistencia óptima manteniendo variedad técnica
        )
        raw = (response.choices[0].message.content or '').strip()
        return _sanitize_label(raw)
    except Exception as e:
        print(f"[alias_service] Groq alias generation failed: {e}")
        return ''


def _sanitize_label(raw: str) -> str:
    """
    Limpia la respuesta del LLM y valida que cumpla el formato intermedio
    `palabra-palabra` (lowercase ASCII). Devuelve la etiqueta limpia o ''
    si no pasa la validación.
    """
    if not raw:
        return ''
    raw = raw.strip().strip('"\'`.,;:').strip()
    
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
    Generador LOCAL clásico — combinación aleatoria de los bancos curados
    técnicos en español. Se usa como fallback cuando Groq falla.
    """
    adj  = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{adj}-{noun}"


def generate_creative_label() -> str:
    """
    Devuelve una etiqueta profesional en formato PascalCase concatenado
    (ej: 'NodoSeguro', 'CapaAlfa', 'MatrizBoveda').
    """
    label = _generate_label_via_groq()
    if not label:
        label = _generate_label_local()
    return _to_pascal(label)


def generate_alias_address(label: str = '') -> str:
    """
    Genera una dirección única tipo `nodoseguro_x7k2m@dominio`.
    """
    domain = getattr(settings, 'MAIL_DOMAIN', DEFAULT_DOMAIN)

    if not label:
        label = generate_creative_label()

    slug = label[:30] or 'Alias'
    code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    # La salida en minúsculas asegura compatibilidad total de matcheo en bases de datos
    return f"{slug}_{code}@{domain}".lower()