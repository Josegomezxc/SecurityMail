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
import time

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.mail.models import EmailMessage
from .models import SandboxAnalysis, TermExplanation


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
    return render(request, 'sandbox/sandbox_report.html', {
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


# ─────────────────────────────────────────────────────────────────────
#  Explicación de términos técnicos (Groq como fallback del diccionario)
#  El frontend tiene un diccionario fijo de explicaciones (HELP_TEXTS en
#  sandbox_report.js). Cuando un término NO está ahí, se pega a este
#  endpoint que delega en Groq, cachea la respuesta en BD, y la sirve.
# ─────────────────────────────────────────────────────────────────────

# Rate limit en memoria: { ip: [(ts1, ts2, ...)] }
_EXPLAIN_RL = {}
_EXPLAIN_RL_LIMIT = 6        # máximo 6 explicaciones por ventana
_EXPLAIN_RL_WINDOW = 60      # ventana = 60 segundos
_MAX_DETAIL_LEN = 400        # truncamos el detail a 400 chars para Groq

# Cache en memoria del índice de reglas YARA (se carga 1 vez)
_YARA_INDEX = None


def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def _rate_limited(ip: str) -> bool:
    """True si esta IP excedió el límite. Limpia los timestamps viejos."""
    now = time.time()
    cutoff = now - _EXPLAIN_RL_WINDOW
    history = [t for t in _EXPLAIN_RL.get(ip, []) if t > cutoff]
    if len(history) >= _EXPLAIN_RL_LIMIT:
        _EXPLAIN_RL[ip] = history
        return True
    history.append(now)
    _EXPLAIN_RL[ip] = history
    return False


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


def _build_prompt(evidence_type: str, evidence_detail: str) -> str:
    """
    Construye el prompt para Groq. Incluye contexto real si el tipo
    es una regla YARA (o si encontramos el nombre en el detail).
    """
    detail = (evidence_detail or '').strip()[:_MAX_DETAIL_LEN]

    # ── Intentamos sacar contexto real de las reglas YARA ──────────
    # Caso A: ev_type ES el nombre de la regla (clic en sección YARA matches)
    # Caso B: ev_type es genérico (yara_*) y el detail tiene "YARA `nombre`:"
    rule_meta = _yara_lookup(evidence_type)
    rule_name = evidence_type if rule_meta else None
    if not rule_meta:
        guess = _extract_rule_name_from_detail(detail)
        if guess:
            rule_meta = _yara_lookup(guess)
            rule_name = guess if rule_meta else None

    context_block = ''
    if rule_meta:
        bits = [f"  - Nombre de la regla: {rule_name}"]
        if rule_meta.get('description'):
            bits.append(f"  - Descripción técnica: {rule_meta['description']}")
        if rule_meta.get('category'):
            bits.append(f"  - Categoría: {rule_meta['category']}")
        if rule_meta.get('severity'):
            bits.append(f"  - Severidad asignada: {rule_meta['severity']}/100")
        strings_list = rule_meta.get('strings') or []
        if strings_list:
            bits.append("  - Patrones/strings que busca la regla:")
            for s in strings_list:
                bits.append(f"      • {s}")
        context_block = (
            "INFORMACIÓN REAL DE LA REGLA YARA DETECTADA "
            f"(extraída del archivo {rule_meta.get('file', 'desconocido')}):\n"
            + "\n".join(bits)
            + "\n\nBasate en estos datos REALES para explicar qué hace la regla "
            "y qué encontró. Los strings que busca te dicen exactamente qué "
            "patrón está marcando como sospechoso.\n\n"
        )

    return (
        "Sos un asistente que explica conceptos de ciberseguridad a usuarios sin "
        "conocimiento técnico. Te paso un indicador detectado por un sandbox de "
        "análisis de correos electrónicos.\n\n"
        + context_block +
        f"Tipo del indicador: {evidence_type}\n"
        f"Detalle del análisis: {detail or '(sin detalle adicional)'}\n\n"
        "Tu respuesta tiene que tener exactamente este formato (sin saludos ni "
        "introducciones, solo las dos secciones):\n\n"
        "QUE_ENCONTRO: una oración corta (máximo 25 palabras) describiendo en "
        "lenguaje natural qué encontró el sandbox en este correo específico, "
        "basándote en el detalle y la descripción técnica si está disponible.\n"
        "QUE_SIGNIFICA: 2-3 oraciones explicando POR QUÉ eso es relevante para "
        "la seguridad, qué riesgo implica y qué hacer al respecto. Sin jerga "
        "técnica, lenguaje claro.\n\n"
        "Reglas importantes:\n"
        "- Si el contexto real de la regla YARA está disponible arriba, "
        "  USALO. NO digas 'no se pudo determinar': la información existe.\n"
        "- Si NO hay contexto, podés inferir del nombre del indicador (es "
        "  descriptivo, ej: 'PDF_Embedded_JS_Action' significa JavaScript "
        "  embebido en un PDF que se ejecuta al abrir).\n"
        "- NO uses comillas ni asteriscos ni markdown.\n"
        "- Respondé en español latinoamericano.\n"
        "- Tono neutro, factual, ni alarmista ni minimizador."
    )


def _parse_groq_response(raw: str) -> dict:
    """Parsea la respuesta del modelo en las dos secciones."""
    text = (raw or '').strip()
    found = ''
    means = ''
    # Búsqueda robusta de los marcadores
    for line in text.splitlines():
        if line.startswith('QUE_ENCONTRO:'):
            found = line.split(':', 1)[1].strip()
        elif line.startswith('QUE_SIGNIFICA:'):
            means = line.split(':', 1)[1].strip()
    if not found and not means:
        # Si el modelo no respetó el formato, devolvemos todo como "means"
        return {'found': '', 'means': text}
    return {'found': found, 'means': means}


@login_required(login_url='login')
@require_POST
def explain_term_view(request):
    """
    Recibe { "type": "<ev.type>", "detail": "<ev.detail opcional>" }
    Devuelve { "found": "...", "means": "...", "cached": bool, "source": "groq|cache" }
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    ev_type   = (body.get('type') or '').strip()[:120]
    ev_detail = (body.get('detail') or '').strip()

    if not ev_type:
        return JsonResponse({'error': 'falta el campo type'}, status=400)

    # Rate limit por IP
    ip = _get_client_ip(request)
    if _rate_limited(ip):
        return JsonResponse({
            'error': 'demasiadas explicaciones en poco tiempo, esperá un momento',
        }, status=429)

    # ── 1. Cache hit ─────────────────────────────────────────────────
    key = TermExplanation.make_key(ev_type, ev_detail)
    cached = TermExplanation.objects.filter(cache_key=key).first()
    if cached:
        cached.hit_count = (cached.hit_count or 0) + 1
        cached.save(update_fields=['hit_count', 'last_used_at'])
        parsed = _parse_groq_response(cached.explanation)
        return JsonResponse({
            'found':  parsed['found'],
            'means':  parsed['means'],
            'cached': True,
            'source': 'cache',
        })

    # ── 2. Cache miss → pegamos a Groq ───────────────────────────────
    api_key = os.environ.get('GROQ_API_KEY', '').strip()
    if not api_key:
        return JsonResponse({
            'error': 'GROQ_API_KEY no configurada en .env'
        }, status=500)

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        prompt = _build_prompt(ev_type, ev_detail)
        completion = client.chat.completions.create(
            model='llama-3.3-70b-versatile',   # el mejor disponible para esto
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=350,
            temperature=0.3,
        )
        raw = completion.choices[0].message.content
        model_used = 'llama-3.3-70b-versatile'
    except Exception as e:
        print('explain_term ERROR Groq:', e)
        return JsonResponse({
            'error': 'No se pudo contactar al modelo de IA en este momento',
            'detail': str(e),
        }, status=502)

    # ── 3. Guardamos en cache + devolvemos ───────────────────────────
    try:
        TermExplanation.objects.create(
            cache_key=key,
            evidence_type=ev_type,
            evidence_detail=ev_detail[:_MAX_DETAIL_LEN],
            explanation=raw,
            model_used=model_used,
        )
    except Exception as e:
        # No es crítico: si falla el guardado seguimos sirviendo la respuesta
        print('explain_term: cache save failed:', e)

    parsed = _parse_groq_response(raw)
    return JsonResponse({
        'found':  parsed['found'],
        'means':  parsed['means'],
        'cached': False,
        'source': 'groq',
    })
