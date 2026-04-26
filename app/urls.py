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

    # App principal
    path('dashboard/',       views.dashboard_view,    name='dashboard'),
    path('dashboard/live/',  views.dashboard_live_api, name='dashboard_live_api'),
    path('bandeja/',         views.inbox_view,         name='inbox'),
    path('bandeja/nuevos/',  views.inbox_new_api,      name='inbox_new_api'),
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
    path("cuenta/cambiar-password/",views.cambiar_password,name="cambiar_password",),

    # ─── Panel de administración (solo para is_staff=True) ─────────────
    path('admin-panel/',                views.admin_dashboard_view,  name='admin_dashboard'),
    path('admin-panel/usuarios/',       views.admin_users_view,      name='admin_users'),
    path('admin-panel/usuario/<int:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin-panel/usuario/<int:pk>/toggle-staff/', views.admin_toggle_staff, name='admin_toggle_staff'),
]