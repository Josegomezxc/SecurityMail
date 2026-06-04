"""
Corrige texto con mojibake (caracteres mal codificados) en los reportes
de SandboxAnalysis viejos.

El problema: antes de que arregláramos el subprocess.run en service.py,
el stdout del contenedor Docker se decodificaba con cp1252 (default en
Windows) en lugar de UTF-8, así que "detección" se guardó como
"detecciÃ³n" en la BD.

Este comando recorre todos los SandboxAnalysis y reemplaza los patrones
de mojibake conocidos en los campos de texto (CharField y JSONField).

Uso:
    python manage.py fix_mojibake --dry-run       # ver qué se cambiaría
    python manage.py fix_mojibake                 # aplicar los cambios
"""
import json
from django.core.management.base import BaseCommand
from apps.sandbox.models import SandboxAnalysis


# Mapeo de mojibake → carácter correcto.
# UTF-8 leído como CP1252 produce estos patrones predecibles.
# El orden importa: los patrones largos (3 chars) deben ir antes
# que los cortos (2 chars) para no romper la decodificación.
MOJIBAKE_FIXES = [
    # 3+ chars (resoluciones específicas)
    ('â€œ', '"'),    # comilla izquierda
    ('â€\x9d', '"'), # comilla derecha
    ('â€™', "'"),    # apóstrofe derecho
    ('â€˜', "'"),    # apóstrofe izquierdo
    ('â€“', '–'),    # en dash
    ('â€”', '—'),    # em dash
    ('â€¦', '…'),    # ellipsis
    # 2 chars — vocales y eñe minúsculas
    ('Ã¡', 'á'),
    ('Ã©', 'é'),
    ('Ã­', 'í'),
    ('Ã³', 'ó'),
    ('Ãº', 'ú'),
    ('Ã±', 'ñ'),
    ('Ã¼', 'ü'),
    # 2 chars — mayúsculas
    ('Ã\x81', 'Á'),
    ('Ã\x89', 'É'),
    ('Ã\x8d', 'Í'),
    ('Ã\x93', 'Ó'),
    ('Ã\x9a', 'Ú'),
    ('Ã\x91', 'Ñ'),
    ('Ã\x9c', 'Ü'),
    # Signos
    ('Â¡', '¡'),
    ('Â¿', '¿'),
    ('Â°', '°'),
    ('Â®', '®'),
    ('Â©', '©'),
    ('Â·', '·'),
    ('Â´', '´'),
    ('Â¬', '¬'),
]


def fix_text(s):
    """Aplica las correcciones a una string. Devuelve (new_string, changed_bool)."""
    if not isinstance(s, str):
        return s, False
    original = s
    for bad, good in MOJIBAKE_FIXES:
        if bad in s:
            s = s.replace(bad, good)
    return s, s != original


def fix_recursive(obj):
    """
    Aplica fix_text recursivamente sobre cualquier JSON-serializable:
    dict, list, str. Otros tipos se devuelven sin tocar.
    Devuelve (obj_corregido, cantidad_de_cambios).
    """
    if isinstance(obj, str):
        new_s, changed = fix_text(obj)
        return new_s, (1 if changed else 0)
    if isinstance(obj, list):
        total = 0
        out = []
        for item in obj:
            new_item, n = fix_recursive(item)
            out.append(new_item)
            total += n
        return out, total
    if isinstance(obj, dict):
        total = 0
        out = {}
        for k, v in obj.items():
            new_v, n = fix_recursive(v)
            out[k] = new_v
            total += n
        return out, total
    return obj, 0


# Campos del modelo a revisar (mapeados a related models)
TEXT_RELATIONS = {
    'file_info': ['filename'],
    'body_analysis': ['body_threat'],
}
# threat_name se queda en SandboxAnalysis
TEXT_FIELDS = ['threat_name']

JSON_RELATIONS = {
    'dynamic': ['yara_matches', 'evidence', 'iocs', 'network_connections',
                'child_processes', 'file_writes'],
    'body_analysis': ['body_evidence', 'attachments_reports'],
}


class Command(BaseCommand):
    help = 'Repara mojibake en los reportes viejos de SandboxAnalysis'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Solo muestra qué cambiaría, sin tocar la BD',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        mode_label = 'DRY-RUN (sin cambios)' if dry_run else 'APLICANDO CAMBIOS'
        self.stdout.write(self.style.WARNING(f'Modo: {mode_label}'))
        self.stdout.write('')

        total_records = SandboxAnalysis.objects.count()
        self.stdout.write(f'Registros a revisar: {total_records}')
        self.stdout.write('')

        affected = 0
        total_replacements = 0

        for sa in SandboxAnalysis.objects.iterator(chunk_size=200):
            updates = {}
            changes_here = 0
            # Track which related objects need saving
            relations_to_save = {}

            # Campos de texto directos (threat_name)
            for f in TEXT_FIELDS:
                val = getattr(sa, f, '')
                new_val, changed = fix_text(val or '')
                if changed:
                    updates[f] = new_val
                    changes_here += 1

            # Campos de texto en related models
            for rel_name, fields in TEXT_RELATIONS.items():
                rel_obj = getattr(sa, rel_name, None)
                if rel_obj is None:
                    continue
                for f in fields:
                    val = getattr(rel_obj, f, '')
                    new_val, changed = fix_text(val or '')
                    if changed:
                        setattr(rel_obj, f, new_val)
                        relations_to_save.setdefault(rel_name, set()).add(f)
                        changes_here += 1

            # Campos JSON en related models
            for rel_name, fields in JSON_RELATIONS.items():
                rel_obj = getattr(sa, rel_name, None)
                if rel_obj is None:
                    continue
                for f in fields:
                    val = getattr(rel_obj, f, None)
                    if val is None:
                        continue
                    new_val, n = fix_recursive(val)
                    if n > 0:
                        setattr(rel_obj, f, new_val)
                        relations_to_save.setdefault(rel_name, set()).add(f)
                        changes_here += n

            if updates or relations_to_save:
                affected += 1
                total_replacements += changes_here
                fname = getattr(getattr(sa, 'file_info', None), 'filename', '?')
                self.stdout.write(
                    f'  ID {sa.id:>5} — {str(fname)[:50]:50s} → '
                    f'{changes_here} reemplazo(s) en {", ".join(updates.keys())}'
                )
                if not dry_run:
                    for f, v in updates.items():
                        setattr(sa, f, v)
                    if updates:
                        sa.save(update_fields=list(updates.keys()))
                    for rel_name, fields in relations_to_save.items():
                        rel_obj = getattr(sa, rel_name, None)
                        if rel_obj is not None:
                            rel_obj.save(update_fields=list(fields))

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(
            f'Listo: {affected} registro(s) afectado(s), '
            f'{total_replacements} reemplazo(s) total'
        ))
        if dry_run and affected > 0:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                'Esto fue dry-run. Para aplicar realmente, corré sin --dry-run:'
            ))
            self.stdout.write('    python manage.py fix_mojibake')
