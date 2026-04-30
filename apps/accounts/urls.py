"""URLs de la app accounts."""
from django.urls import path
from . import views


urlpatterns = [
    path('',          views.login_view,    name='login'),
    path('registro/', views.registro_view, name='registro'),
    path('logout/',   views.logout_view,   name='logout'),
    path('recuperar/', views.recuperar_view, name='recuperar'),
    path('reset-password/<str:token>/', views.reset_password_view, name='reset_password'),
    path('verificar-correo/<str:token>/', views.verificar_correo_view, name='verificar_correo'),
    path('reenviar-codigo/<str:token>/',  views.reenviar_codigo_view,  name='reenviar_codigo'),

    # Perfil
    path('perfil/', views.perfil_view, name='perfil'),

    # Cambio de contraseña
    path('cuenta/cambiar-password/', views.cambiar_password, name='cambiar_password'),
]
