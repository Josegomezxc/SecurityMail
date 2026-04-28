"""
Endpoint para análisis IA con Groq.

Recibe un prompt del frontend (sandbox_report.html) y pide una explicación
en lenguaje natural a un modelo Llama alojado en Groq. Todo lo hace en una
sola llamada; no se guarda el resultado.
"""
import json
import os

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST


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
