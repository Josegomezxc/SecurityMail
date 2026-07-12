
from django.contrib import admin
from django.urls import path, include, register_converter, re_path
from django.conf import settings
from django.conf.urls.static import static


from apps.core.url_converters import SignedIdConverter
register_converter(SignedIdConverter, 'sid')


from apps.core.views import page_not_found_view, permission_denied_view
handler404 = 'apps.core.views.page_not_found_view'
handler403 = 'apps.core.views.permission_denied_view'
handler500 = 'apps.core.views.server_error_view'

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', include('apps.accounts.urls')),

    path('', include('apps.mail.urls')),

    path('', include('apps.aliases.urls')),

    path('', include('apps.sandbox.urls')),

    path('', include('apps.notifications.urls')),
    path('', include('apps.core.urls')),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


urlpatterns += [
    re_path(r'^.*$', page_not_found_view),
]
