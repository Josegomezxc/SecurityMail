"""URLs de la app sandbox."""
from django.urls import path
from . import views


urlpatterns = [
    # Sandbox
    path('sandbox/',                          views.sandbox_list_view,    name='sandbox_list'),
    path('sandbox/analizar/<sid:email_id>/',  views.sandbox_analyze_view, name='sandbox_analyze'),
    path('sandbox/reporte/<sid:pk>/',         views.sandbox_report_view,  name='sandbox_report'),

    # Análisis IA bajo demanda
    path('ai-analysis/', views.ai_analysis_view, name='ai_analysis'),
]
