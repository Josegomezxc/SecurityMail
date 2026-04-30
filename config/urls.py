"""
config/urls.py
──────────────────────────────────────────────────────────────────────
Router raíz del proyecto. Cada app tiene sus propias rutas en
apps/<app>/urls.py — aquí solo las incluimos.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # Cuentas (login/registro/perfil/recuperar/verificar)
    path('', include('apps.accounts.urls')),

    # Correo (dashboard, bandeja, webhook entrante)
    path('', include('apps.mail.urls')),

    # Alias desechables
    path('', include('apps.aliases.urls')),

    # Sandbox + IA
    path('', include('apps.sandbox.urls')),

    # Notificaciones
    path('', include('apps.notifications.urls')),

    # Panel admin global del proyecto (solo is_staff)
    path('', include('apps.core.urls')),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
