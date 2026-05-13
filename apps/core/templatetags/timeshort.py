"""
Filtros de plantilla para formato compacto de fechas/duraciones.

`timeshort` toma una fecha y devuelve la diferencia con ahora en formato
abreviado de UN solo segmento:

    Django timesince  →  Nuestro timeshort
    ─────────────────────────────────────────
    "1 minuto"           "1m"
    "9 horas, 56 min"    "9h"
    "3 días, 2 horas"    "3d"
    "5 meses"            "5mes"
    "2 años"             "2a"

Útil para tablas estrechas donde "9 horas, 56 minutos atrás" rompe a dos
líneas y se ve feo.
"""
import re

from django import template
from django.utils.timesince import timesince

register = template.Library()


# Mapeo unidad-español-larga → abreviatura. El orden importa: probamos
# las más largas primero ("minutos" antes que "min") para no truncar mal.
_UNIT_MAP = [
    (r'a[nñ]os?',      'a'),
    (r'meses?',        'mes'),
    (r'semanas?',      'sem'),
    (r'd[ií]as?',      'd'),
    (r'horas?',        'h'),
    (r'minutos?',      'm'),
    (r'segundos?',     's'),
]


@register.filter(name='timeshort')
def timeshort(value):
    """
    Devuelve la diferencia entre `value` y ahora, abreviada al primer
    segmento. Ejemplo: '9h', '3d', '12m'. Si value es None devuelve ''.
    """
    if value is None:
        return ''
    raw = timesince(value)
    if not raw:
        return ''

    # timesince devuelve algo como "9 horas, 56 minutos" — nos quedamos
    # SOLO con el primer segmento (antes de la coma).
    first = raw.split(',', 1)[0].strip()

    # Reemplazamos la unidad larga por su abreviatura.
    for pattern, short in _UNIT_MAP:
        new = re.sub(
            r'(\d+)\s+' + pattern + r'\b',
            r'\1' + short,
            first,
            flags=re.IGNORECASE,
        )
        if new != first:
            return new

    # Fallback: si no matcheó ninguna unidad conocida, devolvemos el raw
    # tal cual (poco probable, pero defensivo).
    return first
