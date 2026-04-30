"""URLs de la app notifications."""
from django.urls import path
from . import views


urlpatterns = [
    path('notificaciones/',                   views.notification_list_view,        name='notification_list'),
    path('notificaciones/<int:pk>/',          views.notification_detail_view,      name='notification_detail'),
    path('notificaciones/api/unread/',        views.notification_unread_api,       name='notification_unread_api'),
    path('notificaciones/<int:pk>/leer/',     views.notification_mark_read_api,    name='notification_mark_read'),
    path('notificaciones/leer-todo/',         views.notification_mark_all_read_api, name='notification_mark_all_read'),
    path('notificaciones/vaciar/',            views.notification_clear_api,         name='notification_clear'),
    path('notificaciones/<int:pk>/reenviar/', views.notification_forward_api,      name='notification_forward'),
    path('notificaciones/<int:pk>/descartar/',views.notification_discard_api,      name='notification_discard'),
]
