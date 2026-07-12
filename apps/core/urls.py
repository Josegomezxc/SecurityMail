from django.urls import path
from . import views


urlpatterns = [
    path('admin-panel/', views.admin_dashboard_view, name='admin_dashboard'),
    path('admin-panel/usuarios/', views.admin_users_view, name='admin_users'),
    path('admin-panel/amenazas/', views.admin_threats_view, name='admin_threats'),
    path('admin-panel/alias-globales/', views.admin_aliases_view, name='admin_aliases'),

    path('admin-panel/usuario/<sid:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin-panel/usuario/<sid:pk>/toggle-staff/', views.admin_toggle_staff, name='admin_toggle_staff'),
    path('admin-panel/usuario/<sid:pk>/set-quota/', views.admin_set_alias_quota, name='admin_set_alias_quota'),
    path('admin-panel/usuario/<sid:pk>/toggle-unlimited/', views.admin_toggle_alias_unlimited, name='admin_toggle_alias_unlimited'),
    
    path('admin-panel/alias/<sid:pk>/toggle/', views.admin_toggle_alias, name='admin_toggle_alias'),
    
    path('admin-panel/solicitudes/', views.admin_alias_requests_view, name='admin_alias_requests'),
    path('admin-panel/solicitudes/<sid:pk>/resolver/', views.admin_alias_request_resolve, name='admin_alias_request_resolve'),

    path('admin-panel/solicitudes-cuenta/', views.admin_account_recovery_requests_view, name='admin_account_recovery_requests'),
    path('admin-panel/solicitudes-cuenta/<sid:pk>/resolver/', views.admin_account_recovery_request_resolve, name='admin_account_recovery_request_resolve'),

    path('admin-panel/actividad/', views.admin_activity_api, name='admin_activity_api'),

    path('error/404/', views.page_not_found_view, name='preview_404'),
    path('error/500/', views.server_error_view, name='preview_500'),
]