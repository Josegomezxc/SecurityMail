"""
Borra usuarios que nunca completaron la verificación de correo.

Una cuenta queda "abandonada" cuando alguien empieza el registro pero nunca
ingresa el código (cierra la pestaña, se equivocó de email, lo que sea).
Esa cuenta queda en la BD con is_active=False y email_verified=False.

Ejecuta cada cierto tiempo para mantener la BD limpia:
    python manage.py limpiar_no_verificados

Por defecto borra cuentas con más de 24 horas de antigüedad.
Para cambiar el umbral, usa --horas:
    python manage.py limpiar_no_verificados --horas 48

Para hacer una "vista previa" sin borrar (dry-run):
    python manage.py limpiar_no_verificados --dry-run
"""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import timezone


class Command(BaseCommand):
    help = 'Borra cuentas que nunca completaron la verificación de correo.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--horas', type=int, default=24,
            help='Cuentas más viejas que esto se borran (default 24h).',
        )
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Solo muestra qué se borraría, sin hacerlo.',
        )

    def handle(self, *args, **opts):
        horas = opts['horas']
        dry = opts['dry_run']
        cutoff = timezone.now() - timedelta(hours=horas)

        # Cuentas no verificadas + creadas hace más del umbral
        qs = User.objects.filter(
            is_active=False,
            date_joined__lt=cutoff,
        ).filter(
            # OneToOne: profile__email_verified=False  o  profile no existe
            profile__email_verified=False,
        )

        if not qs.exists():
            self.stdout.write(self.style.SUCCESS(
                f'Sin cuentas no verificadas más viejas que {horas}h. Todo limpio.',
            ))
            return

        self.stdout.write(self.style.WARNING(
            f'Encontradas {qs.count()} cuentas abandonadas (>{horas}h sin verificar):',
        ))
        for u in qs:
            self.stdout.write(f'  - {u.email}  (registrada {u.date_joined.date()})')

        if dry:
            self.stdout.write(self.style.NOTICE(
                '\n--dry-run activo: no se borró nada.',
            ))
            return

        deleted, breakdown = qs.delete()
        self.stdout.write(self.style.SUCCESS(
            f'\nBorradas {deleted} filas en total. Detalle: {breakdown}',
        ))
