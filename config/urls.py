"""
config/urls.py
──────────────────────────────────────────────────────────────────────
Router raíz del proyecto. Cada app tiene sus propias rutas en
apps/<app>/urls.py — aquí solo las incluimos.
"""
from django.contrib import admin
from django.urls import path, include, register_converter, re_path
from django.conf import settings
from django.conf.urls.static import static

# Converter `sid` — usa firma criptográfica para que las URLs no muestren
# ids enteros y secuenciales (ej. /notificaciones/35/ → /notificaciones/<token>/)
from apps.core.url_converters import SignedIdConverter
register_converter(SignedIdConverter, 'sid')

# Vistas de error custom — en producción (DEBUG=False) Django usa estos
# handlers automáticamente. En DEBUG=True los ignora y muestra la pantalla
# técnica con el listado de rutas; por eso además agregamos un catch-all
# al final de urlpatterns que captura cualquier ruta no reconocida.
from apps.core.views import page_not_found_view, permission_denied_view
handler404 = 'apps.core.views.page_not_found_view'
handler403 = 'apps.core.views.permission_denied_view'
handler500 = 'apps.core.views.server_error_view'

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

# Catch-all final: cualquier URL que no haya matcheado arriba (token de
# firma manipulado, ruta inventada, id que ya no existe…) cae aquí y
# renderiza nuestro 404 con la estética del proyecto, sin filtrar rutas
# internas. Va al final para no shadear ninguna ruta legítima.
urlpatterns += [
    re_path(r'^.*$', page_not_found_view),
]
