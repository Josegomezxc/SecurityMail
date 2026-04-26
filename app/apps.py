from django.apps import AppConfig


class AppConfig(AppConfig):
    name = 'app'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        # Conecta los signals al arrancar la app
        from . import signals  # noqa: F401
