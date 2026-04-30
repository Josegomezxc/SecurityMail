"""URLs de la app aliases."""
from django.urls import path
from . import views


urlpatterns = [
    path('alias/',          views.alias_list_view,    name='alias_list'),
    path('alias/crear/',    views.alias_create_view,  name='alias_create'),
    path('alias/<int:pk>/destruir/', views.alias_destroy_view, name='alias_destroy'),
]
