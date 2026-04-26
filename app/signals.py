"""
Señales (signals) de la app.

Por ahora solo tenemos un handler: crear un UserProfile vacío cuando
se registra un usuario nuevo. Así, cualquier plantilla puede hacer
`user.profile.avatar_url` sin comprobar si el perfil existe.
"""
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import UserProfile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Cada User nuevo recibe un UserProfile automáticamente."""
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def ensure_profile_exists(sender, instance, **kwargs):
    """
    Seguro de segundo nivel para usuarios creados antes de este signal
    (p. ej. superusers creados con createsuperuser hace tiempo).
    Si no tienen perfil, se lo creamos al guardarse.
    """
    if not hasattr(instance, 'profile'):
        UserProfile.objects.get_or_create(user=instance)
