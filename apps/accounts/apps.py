from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'apps.accounts'
    label = 'accounts'
    default_auto_field = 'django.db.models.BigAutoField'
    verbose_name = 'Cuentas y autenticación'

    def ready(self):
        # Conecta los signals al arrancar (auto-creación de UserProfile)
        from . import signals  # noqa: F401
