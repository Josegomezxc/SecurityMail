"""URLs del panel de administración (apps.core)."""
from django.urls import path
from . import views


urlpatterns = [
    # Panel global de admin (solo is_staff=True)
    path('admin-panel/',                  views.admin_dashboard_view,   name='admin_dashboard'),
    path('admin-panel/usuarios/',         views.admin_users_view,       name='admin_users'),
    path('admin-panel/usuario/<int:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin-panel/usuario/<int:pk>/toggle-staff/', views.admin_toggle_staff, name='admin_toggle_staff'),
    path('admin-panel/alias/<int:pk>/toggle/',         views.admin_toggle_alias, name='admin_toggle_alias'),
    path('admin-panel/amenazas/',         views.admin_threats_view,     name='admin_threats'),
    path('admin-panel/alias-globales/',   views.admin_aliases_view,     name='admin_aliases'),
]
