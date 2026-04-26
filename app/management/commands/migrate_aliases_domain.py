"""
Migra alias antiguos a un dominio nuevo.

Útil cuando cambias de dominio (ej: de `securemail.com` al dominio real
que compraste, `dockershield.lat`).

Uso:
  # Ver qué pasaría (sin tocar la BD)
  python manage.py migrate_aliases_domain --to dockershield.lat --dry-run

  # Aplicar de verdad
  python manage.py migrate_aliases_domain --to dockershield.lat

  # Migrar desde un dominio específico (por defecto: securemail.com)
  python manage.py migrate_aliases_domain --from securemail.com --to dockershield.lat
"""
from django.core.management.base import BaseCommand
from django.db import transaction

from app.models import Alias


class Command(BaseCommand):
    help = 'Cambia el dominio de los alias existentes (ej: securemail.com → dockershield.lat)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--from', dest='from_domain', default='securemail.com',
            help='Dominio actual de los alias (por defecto: securemail.com)',
        )
        parser.add_argument(
            '--to', dest='to_domain', required=True,
            help='Dominio nuevo al que migrar (ej: dockershield.lat)',
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='No modifica la BD, solo muestra qué pasaría',
        )

    def handle(self, *args, **opts):
        from_domain = opts['from_domain'].strip().lower()
        to_domain   = opts['to_domain'].strip().lower()
        dry_run     = opts['dry_run']

        if from_domain == to_domain:
            self.stdout.write(self.style.WARNING(
                f'El dominio origen y destino son iguales ({from_domain}). Nada que hacer.'
            ))
            return

        suffix = f'@{from_domain}'
        aliases = Alias.objects.filter(address__iendswith=suffix)
        count = aliases.count()

        if count == 0:
            self.stdout.write(self.style.WARNING(
                f'No hay alias con {suffix}. Nada que migrar.'
            ))
            return

        self.stdout.write(self.style.HTTP_INFO(
            f'\nEncontrados {count} alias con {suffix}:\n'
        ))

        # Mostrar plan
        plan = []
        for alias in aliases:
            new_addr = alias.address[: -len(suffix)] + f'@{to_domain}'
            plan.append((alias, new_addr))
            mark = '  ' if dry_run else 'OK'
            self.stdout.write(f'  {mark}  {alias.address}  ->  {new_addr}')

        # Comprobar colisiones (raro pero posible)
        new_addrs = [n for _, n in plan]
        if len(set(new_addrs)) != len(new_addrs):
            self.stdout.write(self.style.ERROR(
                '\n[!] Colision: dos alias quedarian con la misma direccion. Aborto.'
            ))
            return
        existing_collisions = Alias.objects.filter(address__in=new_addrs).count()
        if existing_collisions:
            self.stdout.write(self.style.ERROR(
                f'\n[!] {existing_collisions} alias destino ya existen en BD. Aborto.'
            ))
            return

        if dry_run:
            self.stdout.write(self.style.WARNING(
                '\n--dry-run: no se modifico nada. Quita --dry-run para aplicar.\n'
            ))
            return

        # Aplicar
        with transaction.atomic():
            for alias, new_addr in plan:
                alias.address = new_addr
                alias.save(update_fields=['address'])

        self.stdout.write(self.style.SUCCESS(
            f'\n[OK] Migrados {count} alias de @{from_domain} a @{to_domain}.\n'
        ))
