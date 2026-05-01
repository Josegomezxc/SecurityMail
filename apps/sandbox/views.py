"""
Vistas del módulo sandbox:
  - Lista de análisis del usuario.
  - Reporte detallado de un análisis.
  - Trigger manual de análisis (placeholder para UI futura).
  - Análisis IA bajo demanda (Groq + Llama 3.3).

El análisis sandbox en sí (Docker, YARA, strace…) vive en `apps/sandbox/`.
Estas vistas solo son el controlador que muestra los resultados.
"""
import json
import os

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.mail.models import EmailMessage
from .models import SandboxAnalysis


# ─────────────────────────────────────────────────────────────────────
#  Sandbox: lista, análisis y reporte
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def sandbox_list_view(request):
    """Lista de todos los análisis del usuario ordenados por fecha."""
    qs = SandboxAnalysis.objects.filter(email__alias__user=request.user)

    # Stats por nivel de riesgo (los 4 cards superiores).
    # Hay 2 fuentes de verdad para "bloqueado": el flag `blocked` (que se
    # marca en webhook al guardar) y `risk_score >= 61`. Usamos el flag
    # cuando esté presente y caemos al score como fallback.
    total_count   = qs.count()
    blocked_count = qs.filter(risk_score__gte=61).count()
    safe_count    = qs.filter(risk_score__lte=30).count()
    warning_count = qs.filter(risk_score__gt=30, risk_score__lt=61).count()

    analyses = qs.order_by('-analyzed_at')

    return render(request, 'sandbox_list.html', {
        'analyses':      analyses,
        'total_count':   total_count,
        'blocked_count': blocked_count,
        'safe_count':    safe_count,
        'warning_count': warning_count,
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


# ─────────────────────────────────────────────────────────────────────
#  Análisis IA (Groq + Llama 3.3)
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
@require_POST
def ai_analysis_view(request):
    """
    Entrada:  { "prompt": "texto del prompt construido por el frontend" }
    Salida:   { "result": "veredicto en el formato VEREDICTO/TIPO/EXPLICACION/RECOMENDACION" }
    Fallo:    { "error": "mensaje" }  con status 500
    """
    try:
        from groq import Groq
        data = json.loads(request.body)

        api_key = os.environ.get('GROQ_API_KEY', '').strip()
        if not api_key:
            return JsonResponse(
                {'error': 'GROQ_API_KEY no configurada. Revisa tu archivo .env'},
                status=500,
            )
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=[{'role': 'user', 'content': data.get('prompt', '')}],
            max_tokens=2000,        # ↑ permite explicaciones detalladas con definiciones
            temperature=0.4,        # ↓ menos creativo, más consistente con el formato pedido
        )
        return JsonResponse({'result': response.choices[0].message.content})

    except Exception as e:
        print('ERROR IA:', str(e))
        return JsonResponse({'error': str(e)}, status=500)
