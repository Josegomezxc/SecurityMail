"""
Vistas del módulo sandbox:
  - Lista de análisis del usuario.
  - Reporte detallado de un análisis.
  - Trigger manual de análisis (placeholder para UI futura).

El análisis en sí (Docker, YARA, strace…) vive en `app/sandbox/`.
Estas vistas solo son el controlador que muestra los resultados.
"""
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from ..models import EmailMessage, SandboxAnalysis


@login_required(login_url='login')
def sandbox_list_view(request):
    """Lista de todos los análisis del usuario ordenados por fecha."""
    analyses = SandboxAnalysis.objects.filter(
        email__alias__user=request.user,
    ).order_by('-analyzed_at')

    return render(request, 'sandbox_list.html', {
        'analyses': analyses,
    })


@login_required(login_url='login')
def sandbox_analyze_view(request, email_id):
    """
    Dispara el análisis sandbox para un correo.
    Si ya existe análisis, redirige al reporte existente.
    """
    email_obj = get_object_or_404(
        EmailMessage, pk=email_id, alias__user=request.user,
    )

    existing = SandboxAnalysis.objects.filter(email=email_obj).first()
    if existing:
        return redirect('sandbox_report', pk=existing.pk)

    # El webhook normalmente ya dispara el análisis al recibir el correo,
    # así que esta ruta solo queda como fallback manual desde la UI.
    messages.info(request, 'Análisis en proceso...')
    return redirect('sandbox_list')


@login_required(login_url='login')
def sandbox_report_view(request, pk):
    """Reporte detallado de un análisis sandbox específico."""
    analysis = get_object_or_404(
        SandboxAnalysis, pk=pk, email__alias__user=request.user,
    )
    return render(request, 'sandbox_report.html', {
        'analysis': analysis,
    })
