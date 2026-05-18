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

    return render(request, 'sandbox/sandbox_list.html', {
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

    # Contexto enriquecido de reglas YARA detectadas — se inyecta al
    # prompt del análisis IA del cliente para que pueda explicar cada
    # regla en lenguaje claro sin pegarle a Groq por cada `?`.
    yara_context = []
    for match in (analysis.yara_matches or [])[:10]:
        if isinstance(match, dict):
            rule_name = match.get('rule', '')
        else:
            rule_name = str(match)
        if not rule_name:
            continue
        meta = _yara_lookup(rule_name)
        entry = {
            'rule':     rule_name,
            'desc':     (meta or {}).get('description', ''),
            'category': (meta or {}).get('category', ''),
            'severity': (meta or {}).get('severity', ''),
            'strings':  ((meta or {}).get('strings') or [])[:5],
        }
        yara_context.append(entry)

    return render(request, 'sandbox/sandbox_report.html', {
        'analysis':          analysis,
        'yara_context_json': json.dumps(yara_context, ensure_ascii=False),
    })


# ─────────────────────────────────────────────────────────────────────
#  Análisis IA (Groq + Llama 3.3)
# ─────────────────────────────────────────────────────────────────────

def _parse_ai_blocks(text: str) -> dict:
    """
    Extrae las 4 secciones (VEREDICTO, TIPO DE AMENAZA, EXPLICACION,
    RECOMENDACION) del texto plano que devuelve la IA. Reusa el mismo
    parser que el JS para poder cachear los campos por separado.
    """
    keys = ['VEREDICTO', 'TIPO DE AMENAZA', 'EXPLICACION', 'RECOMENDACION']
    out = {k: '' for k in keys}
    if not text:
        return out
    lines = text.splitlines()
    # Encontramos los índices de cada KEY: y extraemos el bloque hasta la próxima
    indices = []
    for i, line in enumerate(lines):
        s = line.strip()
        for k in keys:
            if s.startswith(k + ':'):
                indices.append((i, k))
                break
    indices.append((len(lines), None))
    for j in range(len(indices) - 1):
        start, key = indices[j]
        end = indices[j + 1][0]
        block_lines = lines[start:end]
        if not block_lines:
            continue
        first = block_lines[0]
        # Quita el "KEY:" del inicio de la primera línea
        first_stripped = first.split(':', 1)[1].lstrip() if ':' in first else first
        rest = '\n'.join([first_stripped] + block_lines[1:]).strip()
        out[key] = rest
    return out


@login_required(login_url='login')
@require_POST
def ai_analysis_view(request):
    """
    Entrada:  {
        "prompt":      "texto del prompt construido por el frontend",
        "analysis_id": <int>            ← opcional: si viene, se cachea
    }
    Salida:   {
        "result": "<respuesta completa>",
        "cached": false                 ← false si vino de Groq, true si de BD
    }
    Errores:
      - 429 (rate limit): { "error": "...", "retry_after": <minutos>, "code": "rate_limit" }
      - 500 (otros):      { "error": "..." }
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    analysis_id = data.get('analysis_id')
    prompt      = data.get('prompt', '')

    # ── 1. Cache hit ──────────────────────────────────────────────────
    # Si el reporte ya tiene análisis IA generado, devolvemos eso SIN
    # pegarle a Groq. Esto ahorra ~5,000-8,000 tokens por visualización
    # repetida del mismo reporte.
    cached_obj = None
    if analysis_id:
        try:
            cached_obj = SandboxAnalysis.objects.filter(
                pk=analysis_id,
                email__alias__user=request.user,
            ).first()
        except Exception:
            cached_obj = None

        if cached_obj and cached_obj.ai_explanation:
            # Reconstruimos el texto en el formato que espera el frontend
            parts = [
                f'VEREDICTO: {cached_obj.ai_verdict or "SEGURO"}',
                f'TIPO DE AMENAZA: {cached_obj.ai_threat_type or "No aplica"}',
                f'EXPLICACION: {cached_obj.ai_explanation}',
                f'RECOMENDACION: {cached_obj.ai_recommendation or ""}',
            ]
            return JsonResponse({
                'result': '\n\n'.join(parts),
                'cached': True,
            })

    # ── 2. Cache miss → pegamos a Groq ────────────────────────────────
    api_key = os.environ.get('GROQ_API_KEY', '').strip()
    if not api_key:
        return JsonResponse(
            {'error': 'GROQ_API_KEY no configurada. Revisa tu archivo .env'},
            status=500,
        )

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=3500,
            temperature=0.4,
        )
        raw = response.choices[0].message.content
    except Exception as e:
        err_str = str(e)
        print('ERROR IA:', err_str)
        # Detectar rate limit (429) y extraer el tiempo de espera
        if '429' in err_str or 'rate_limit' in err_str.lower() or 'tokens per day' in err_str.lower():
            import re as _re
            # Buscar el "try again in Xm" del mensaje de Groq
            m = _re.search(r'try again in\s+(\d+)\s*m', err_str, _re.IGNORECASE)
            wait_min = int(m.group(1)) if m else 60
            return JsonResponse({
                'error': 'Se alcanzó el límite diario de la API de IA.',
                'code': 'rate_limit',
                'retry_after_min': wait_min,
            }, status=429)
        return JsonResponse({'error': err_str}, status=500)

    # ── 3. Si vino analysis_id, cacheamos en la BD ────────────────────
    if cached_obj is not None:
        try:
            from django.utils import timezone
            blocks = _parse_ai_blocks(raw)
            cached_obj.ai_verdict       = (blocks.get('VEREDICTO') or '')[:20]
            cached_obj.ai_threat_type   = (blocks.get('TIPO DE AMENAZA') or '')[:100]
            cached_obj.ai_explanation   = blocks.get('EXPLICACION') or ''
            cached_obj.ai_recommendation = blocks.get('RECOMENDACION') or ''
            cached_obj.ai_generated_at  = timezone.now()
            cached_obj.save(update_fields=[
                'ai_verdict', 'ai_threat_type', 'ai_explanation',
                'ai_recommendation', 'ai_generated_at',
            ])
        except Exception as e:
            # No crítico: si falla el guardado igual servimos la respuesta
            print('ai_analysis: cache save failed:', e)

    return JsonResponse({'result': raw, 'cached': False})


# ─────────────────────────────────────────────────────────────────────
#  Indexado de reglas YARA — se usa en sandbox_report_view para enriquecer
#  el contexto que se manda al prompt de análisis IA. Antes había un
#  endpoint dedicado por click "¿Qué es?", pero consumía demasiada cuota
#  de Groq. Ahora una sola llamada por reporte cubre todo.
# ─────────────────────────────────────────────────────────────────────

# Cache en memoria del índice de reglas YARA (se carga 1 vez por proceso)
_YARA_INDEX = None


def _build_yara_index() -> dict:
    """
    Recorre apps/sandbox/analyzers/rules/*.yar y devuelve un dict
    {rule_name: {description, category, severity, sample_strings}}.
    Esto se usa para darle CONTEXTO REAL al modelo cuando el usuario
    pide una explicación de una regla YARA — el modelo ya no inventa,
    sino que reformula la descripción técnica en lenguaje claro.
    """
    import re
    import glob
    base = os.path.join(os.path.dirname(__file__), 'analyzers', 'rules')
    files = glob.glob(os.path.join(base, '*.yar'))
    index = {}

    # Parser regex SIMPLE — no compila YARA, solo extrae los campos
    # útiles del .yar para nuestro propósito. Tolerante a comillas
    # simples/dobles y variaciones de whitespace.
    rule_re = re.compile(
        r'\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*[:{]',
    )

    for path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                src = f.read()
        except Exception:
            continue

        # Para cada regla extraída, intentamos buscar su bloque meta
        for m in rule_re.finditer(src):
            name = m.group(1)
            # Buscamos las llaves balanceadas para acotar la regla
            brace = src.find('{', m.start())
            if brace < 0:
                continue
            depth = 0
            end = brace
            for i, ch in enumerate(src[brace:], start=brace):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            body = src[brace:end + 1]

            desc = _extract_meta_field(body, 'description')
            cat  = _extract_meta_field(body, 'category')
            sev  = _extract_meta_field(body, 'severity') or _extract_meta_field(body, 'score')
            strings_preview = _extract_rule_strings_preview(body)

            index[name] = {
                'description': desc,
                'category':    cat,
                'severity':    sev,
                'strings':     strings_preview,
                'file':        os.path.basename(path),
            }
    return index


def _extract_rule_strings_preview(body: str) -> list:
    """
    Saca los primeros strings de la sección strings: de una regla YARA.
    Devuelve hasta 6 ejemplos truncados, suficiente para que la IA
    intuya QUÉ patrones busca la regla (ej: /Launch, /OpenAction, ...).
    """
    import re
    # Buscamos la sección strings: ... condition:
    seg = re.search(
        r'\bstrings\s*:\s*(.+?)\bcondition\s*:',
        body, re.DOTALL | re.IGNORECASE,
    )
    if not seg:
        return []
    section = seg.group(1)

    out = []
    # Patrón 1: strings entre comillas — $foo = "texto"
    for m in re.finditer(r'\$\w+\s*=\s*"([^"\n]{1,120})"', section):
        out.append(m.group(1).strip())
    # Patrón 2: regex YARA — $foo = /patron/  (acepta \/ como slash escapado)
    for m in re.finditer(r'\$\w+\s*=\s*/((?:[^/\\\n]|\\.){1,80})/[a-z]*', section):
        # Desescapamos \/ → / para que sea legible
        pat = m.group(1).replace('\\/', '/').replace('\\\\', '\\').strip()
        if pat:
            out.append('regex: ' + pat)
    # Patrón 3: hex — $foo = { hex }
    for m in re.finditer(r'\$\w+\s*=\s*\{\s*([0-9a-fA-F\s\.\?\[\]\(\)\|]{2,80})\s*\}', section):
        hex_str = m.group(1).strip()
        out.append('hex: ' + hex_str)

    # Limitamos cantidad y largo
    cleaned = []
    seen = set()
    for s in out:
        s = s[:100]
        if s and s not in seen:
            seen.add(s)
            cleaned.append(s)
        if len(cleaned) >= 6:
            break
    return cleaned


def _extract_meta_field(body: str, field: str) -> str:
    """Saca un campo meta tipo `description = "..."` del cuerpo de la regla."""
    import re
    pat = re.compile(
        rf'\b{re.escape(field)}\s*=\s*(["\']|)([^"\'\n\r]*?)\1\s*(?:$|\n|,)',
        re.IGNORECASE | re.MULTILINE,
    )
    mm = pat.search(body)
    if mm:
        return mm.group(2).strip()
    # Caso especial: severity/score numérico sin comillas
    num = re.compile(rf'\b{re.escape(field)}\s*=\s*(\d+)', re.IGNORECASE).search(body)
    if num:
        return num.group(1)
    return ''


def _yara_lookup(name: str) -> dict | None:
    """Busca metadata de una regla YARA por nombre (case-insensitive)."""
    global _YARA_INDEX
    if _YARA_INDEX is None:
        try:
            _YARA_INDEX = _build_yara_index()
        except Exception as e:
            print('YARA index error:', e)
            _YARA_INDEX = {}
    if not _YARA_INDEX:
        return None
    if name in _YARA_INDEX:
        return _YARA_INDEX[name]
    # case-insensitive fallback
    low = name.lower()
    for k, v in _YARA_INDEX.items():
        if k.lower() == low:
            return v
    return None


def _extract_rule_name_from_detail(detail: str) -> str | None:
    """
    Extrae el nombre de la regla YARA del detail si tiene formato
    "YARA `nombre_regla`: ..." o "Acción /JS (..." (no aplica acá).
    """
    import re
    if not detail:
        return None
    m = re.search(r'YARA\s*`([A-Za-z_][A-Za-z0-9_]*)`', detail)
    if m:
        return m.group(1)
    return None


