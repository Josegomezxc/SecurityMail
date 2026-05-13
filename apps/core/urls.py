"""URLs del panel de administración (apps.core)."""
from django.urls import path
from . import views


urlpatterns = [
    # Panel global de admin (solo is_staff=True)
    path('admin-panel/',                  views.admin_dashboard_view,   name='admin_dashboard'),
    path('admin-panel/usuarios/',         views.admin_users_view,       name='admin_users'),
    path('admin-panel/usuario/<sid:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin-panel/usuario/<sid:pk>/toggle-staff/', views.admin_toggle_staff, name='admin_toggle_staff'),
    path('admin-panel/usuario/<sid:pk>/set-quota/',    views.admin_set_alias_quota, name='admin_set_alias_quota'),
    path('admin-panel/usuario/<sid:pk>/toggle-unlimited/', views.admin_toggle_alias_unlimited, name='admin_toggle_alias_unlimited'),
    path('admin-panel/alias/<sid:pk>/toggle/',         views.admin_toggle_alias, name='admin_toggle_alias'),
    path('admin-panel/amenazas/',         views.admin_threats_view,     name='admin_threats'),
    path('admin-panel/alias-globales/',   views.admin_aliases_view,     name='admin_aliases'),
    # Solicitudes de cupo de alias (usuario → admin)
    path('admin-panel/solicitudes/',                   views.admin_alias_requests_view,  name='admin_alias_requests'),
    path('admin-panel/solicitudes/<sid:pk>/resolver/', views.admin_alias_request_resolve, name='admin_alias_request_resolve'),
]
