# app/urls.py
from django.urls import path
from . import views
from .webhook import inbound_email_webhook

urlpatterns = [
    # Auth
    path('',          views.login_view,    name='login'),
    path('registro/', views.registro_view, name='registro'),
    path('logout/',   views.logout_view,   name='logout'),
    path('recuperar/', views.recuperar_view, name='recuperar'),
    path('reset-password/<str:token>/', views.reset_password_view, name='reset_password'),
    path('verificar-correo/<str:token>/', views.verificar_correo_view, name='verificar_correo'),
    path('reenviar-codigo/<str:token>/',  views.reenviar_codigo_view,  name='reenviar_codigo'),

    # App principal
    path('dashboard/',       views.dashboard_view,    name='dashboard'),
    path('dashboard/live/',  views.dashboard_live_api, name='dashboard_live_api'),
    path('bandeja/',         views.inbox_view,         name='inbox'),
    path('bandeja/nuevos/',  views.inbox_new_api,      name='inbox_new_api'),
    path('bandeja/vaciar/',  views.inbox_clear_api,    name='inbox_clear'),
    path('bandeja/<int:pk>/leido/', views.mark_email_read_api, name='mark_email_read'),
    path('bandeja/<int:pk>/html/',  views.email_html_api,      name='email_html_api'),
    path('perfil/',          views.perfil_view,        name='perfil'),

    # Alias
    path('alias/',          views.alias_list_view,   name='alias_list'),
    path('alias/crear/',    views.alias_create_view,  name='alias_create'),
    path('alias/<int:pk>/destruir/', views.alias_destroy_view, name='alias_destroy'),

    # Sandbox
    path('sandbox/',                      views.sandbox_list_view,    name='sandbox_list'),
    path('sandbox/analizar/<int:email_id>/', views.sandbox_analyze_view, name='sandbox_analyze'),
    path('sandbox/reporte/<int:pk>/',     views.sandbox_report_view,  name='sandbox_report'),

    # Webhook para correos entrantes (Mailgun / SendGrid)
    path('webhook/inbound/', inbound_email_webhook, name='inbound_webhook'),
    
    path('ai-analysis/', views.ai_analysis_view, name='ai_analysis'),

    # Notificaciones
    path('notificaciones/',                   views.notification_list_view,        name='notification_list'),
    path('notificaciones/<int:pk>/',          views.notification_detail_view,      name='notification_detail'),
    path('notificaciones/api/unread/',        views.notification_unread_api,       name='notification_unread_api'),
    path('notificaciones/<int:pk>/leer/',     views.notification_mark_read_api,    name='notification_mark_read'),
    path('notificaciones/leer-todo/',         views.notification_mark_all_read_api, name='notification_mark_all_read'),
    path('notificaciones/vaciar/',            views.notification_clear_api,         name='notification_clear'),
    path('notificaciones/<int:pk>/reenviar/', views.notification_forward_api,      name='notification_forward'),
    path('notificaciones/<int:pk>/descartar/',views.notification_discard_api,      name='notification_discard'),
    path("cuenta/cambiar-password/",views.cambiar_password,name="cambiar_password",),

    # ─── Panel de administración (solo para is_staff=True) ─────────────
    path('admin-panel/',                views.admin_dashboard_view,  name='admin_dashboard'),
    path('admin-panel/usuarios/',       views.admin_users_view,      name='admin_users'),
    path('admin-panel/usuario/<int:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin-panel/usuario/<int:pk>/toggle-staff/', views.admin_toggle_staff, name='admin_toggle_staff'),
    path('admin-panel/alias/<int:pk>/toggle/', views.admin_toggle_alias, name='admin_toggle_alias'),
    path('admin-panel/amenazas/',     views.admin_threats_view,  name='admin_threats'),
    path('admin-panel/alias-globales/', views.admin_aliases_view, name='admin_aliases'),
]