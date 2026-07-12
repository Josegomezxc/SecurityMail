
import os
import random
import re
import string

from django.conf import settings


DEFAULT_DOMAIN = "dockershield.lat"   

_GROQ_MODEL = 'llama-3.1-8b-instant'
_GROQ_TIMEOUT_S = 4.0   



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


_LABEL_RE = re.compile(r'^[a-z]{2,15}-[a-z]{2,15}$')


def _to_pascal(label_hyphenated: str) -> str:

    return ''.join(part.capitalize() for part in label_hyphenated.split('-'))


def _generate_label_via_groq() -> str:
   
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
            "- PROHIBIDO usar la palabra 'servidor' o variaciones de la misma.\n"  # <--- RESTRICCIÓN NUEVA
            "- PROHIBIDO nombres de animales de cualquier tipo\n"
            "- PROHIBIDO colores, especialmente de fantasía o poéticos (azul, carmesi, dorado, esmeralda, rubi, zafiro, etc.)\n"
            "- PROHIBIDO elementos de fantasía, ciencia ficción o mitología (magico, cosmico, fenix, dragon, titan, quasar, nebula, etc.)\n"
            "- PROHIBIDO nombres propios de personas, marcas conocidas o referencias culturales\n\n"
            
            "Instrucción de diversidad: Debes ser creativo dentro del ámbito de TI. Explora términos de "
            "arquitectura de software, redes, ciberseguridad, almacenamiento, flujos de datos y gobernanza "
            "(ej. matriz, flujo, nucleo, traza, indice, puerto, modulo, vector, protocolo, terminal, malla, etc.). "
            "Asegúrate de que el alias sea único, diferente y de corte puramente institucional.\n\n" # <--- REFUERZO DE DIVERSIDAD
            
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
            max_tokens=15,     
            temperature=0.7,     
        )
        raw = (response.choices[0].message.content or '').strip()
        return _sanitize_label(raw)
    except Exception as e:
        print(f"[alias_service] Groq alias generation failed: {e}")
        return ''


def _sanitize_label(raw: str) -> str:

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
    
    adj  = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{adj}-{noun}"


def generate_creative_label() -> str:

    label = _generate_label_via_groq()
    if not label:
        label = _generate_label_local()
    return _to_pascal(label)


def generate_alias_address(label: str = '') -> str:

    domain = getattr(settings, 'MAIL_DOMAIN', DEFAULT_DOMAIN)

    if not label:
        label = generate_creative_label()

    slug = label[:30] or 'Alias'
    code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    return f"{slug}_{code}@{domain}".lower()