"""URLs de la app mail (dashboard, bandeja, webhook)."""
from django.urls import path
from . import views
from .webhook import inbound_email_webhook
from .cloudflare_webhook import inbound_cloudflare_webhook


urlpatterns = [
    path('dashboard/',        views.dashboard_view,         name='dashboard'),
    path('dashboard/actividad/', views.dashboard_activity_api, name='dashboard_activity'),

    path('bandeja/',         views.inbox_view,         name='inbox'),
    path('bandeja/vaciar/',  views.inbox_clear_api,    name='inbox_clear'),
    path('bandeja/<sid:pk>/leido/', views.mark_email_read_api, name='mark_email_read'),
    path('bandeja/<sid:pk>/html/',  views.email_html_api,      name='email_html_api'),

    path('enviados/',        views.sent_view,            name='sent_list'),
    path('enviados/mas/',    views.sent_more_api,        name='sent_more'),
    path('enviados/vaciar/', views.sent_empty_api,       name='sent_empty'),
    path('contactos/',       views.compose_contacts_api, name='compose_contacts'),

    
    path('papelera/',                  views.trash_view,         name='trash_list'),
    path('papelera/mas/',              views.trash_more_api,     name='trash_more'),
    path('papelera/restaurar/',        views.trash_restore_api,  name='trash_restore'),
    path('papelera/eliminar/',         views.trash_delete_api,   name='trash_delete'),
    path('papelera/vaciar/',           views.trash_empty_api,    name='trash_empty'),
    path('bandeja/<sid:pk>/papelera/', views.email_trash_api,    name='email_trash'),
    path('enviados/<sid:pk>/papelera/',views.sent_trash_api,     name='sent_trash'),

    path('borradores/',                  views.drafts_view,       name='drafts_list'),
    path('borradores/mas/',              views.drafts_more_api,   name='drafts_more'),
    path('borradores/guardar/',          views.draft_save_api,    name='draft_save'),
    path('borradores/vaciar/',           views.drafts_empty_api,  name='drafts_empty'),
    path('borradores/<sid:pk>/',         views.draft_get_api,     name='draft_get'),
    path('borradores/<sid:pk>/eliminar/',views.draft_delete_api,  name='draft_delete'),

    path('webhook/inbound/', inbound_email_webhook, name='inbound_webhook'),
    path('webhook/inbound/cloudflare/', inbound_cloudflare_webhook, name='inbound_cloudflare'),
]
