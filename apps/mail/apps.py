from django.apps import AppConfig


class MailConfig(AppConfig):
    name = 'apps.mail'
    label = 'mail'
    default_auto_field = 'django.db.models.BigAutoField'
    verbose_name = 'Correo: bandeja, envío y recepción'
