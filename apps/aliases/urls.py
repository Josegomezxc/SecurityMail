"""URLs de la app aliases."""
from django.urls import path
from . import views


urlpatterns = [
    path('alias/',                   views.alias_list_view,    name='alias_list'),
    path('alias/mas/',               views.alias_more_api,     name='alias_more'),
    path('alias/crear/',             views.alias_create_view,  name='alias_create'),
    path('alias/<int:pk>/destruir/', views.alias_destroy_view, name='alias_destroy'),
    path('alias/<int:pk>/enviar/',   views.alias_compose_view, name='alias_compose'),
    # Solicitud de más cupo (usuario → admin)
    path('alias/solicitar-cupo/',    views.alias_quota_request_create, name='alias_quota_request'),
]
