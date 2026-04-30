"""URLs de la app mail (dashboard, bandeja, webhook)."""
from django.urls import path
from . import views
from .webhook import inbound_email_webhook


urlpatterns = [
    # Dashboard
    path('dashboard/',       views.dashboard_view,    name='dashboard'),
    path('dashboard/live/',  views.dashboard_live_api, name='dashboard_live_api'),

    # Bandeja
    path('bandeja/',         views.inbox_view,         name='inbox'),
    path('bandeja/nuevos/',  views.inbox_new_api,      name='inbox_new_api'),
    path('bandeja/vaciar/',  views.inbox_clear_api,    name='inbox_clear'),
    path('bandeja/<int:pk>/leido/', views.mark_email_read_api, name='mark_email_read'),
    path('bandeja/<int:pk>/html/',  views.email_html_api,      name='email_html_api'),

    # Webhook entrante (SendGrid Inbound Parse)
    path('webhook/inbound/', inbound_email_webhook, name='inbound_webhook'),
]
