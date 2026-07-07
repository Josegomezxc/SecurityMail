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
import re
import time
from urllib.parse import urlencode

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.mail.models import EmailMessage
from .models import SandboxAnalysis, DynamicAnalysis, IAResult

_UNICODE_CONTROL_RE = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f'
    '\u202a\u202b\u202c\u202d\u202e'
    '\u2060\u2061\u2062\u2063\u2064'
    '\u2066\u2067\u2068\u2069'
    '\ufffe\uffff]'
)

_EVI_FILE_RE = re.compile(r'^\[(.+?)\]\s')


def _group_evidence(evidence_list):
    """Agrupa evidencia por nombre de archivo (extraído de [archivo] prefijo)."""
    groups = {}
    for ev in evidence_list:
        detail = ev.get("detail", "")
        m = _EVI_FILE_RE.match(detail)
        if m:
            fname = _UNICODE_CONTROL_RE.sub("", m.group(1))
            ev_clean = dict(ev, detail=_EVI_FILE_RE.sub("", detail))
            groups.setdefault(fname, []).append(ev_clean)
        else:
            groups.setdefault("__general__", []).append(ev)

    def _has_password(items):
        return any(ev.get('type') == 'password_protected' for ev in items)

    # Ordenar: primero "general", luego grupos con password (alfabético),
    # después grupos sin password (alfabético)
    result = []
    if "__general__" in groups:
        result.append(("__general__", groups.pop("__general__")))

    protected = []
    unprotected = []
    for fname in sorted(groups):
        (protected if _has_password(groups[fname]) else unprotected).append((fname, groups[fname]))

    result.extend(protected)
    result.extend(unprotected)
    return result


def _sanitize_value(obj):
    """Recorre listas/dicts y limpia caracteres de control Unicode de strings."""
    if isinstance(obj, str):
        return _UNICODE_CONTROL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _sanitize_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_value(v) for v in obj]
    return obj


# Items por página — coincide con el resto del proyecto (bandeja, etc.)
PAGE_SIZE = 6


def _qs_params(request, exclude=('page',)):
    """Query params actuales como string, para preservarlos al paginar."""
    params = {k: v for k, v in request.GET.items() if k not in exclude and v}
    return urlencode(params)


# ─────────────────────────────────────────────────────────────────────
#  Sandbox: lista, análisis y reporte
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
def sandbox_list_view(request):
    """
    Lista de análisis sandbox paginada server-side.

    Query params:
      ?q=<texto>     busca en filename / asunto / remitente / amenaza
      ?filter=<f>    all | malware | danger | warning | safe
      ?page=<n>      número de página (PAGE_SIZE items)
    """
    base_qs = SandboxAnalysis.objects.filter(email__alias__user=request.user)

    # Contadores por categoría (sobre el base_qs, no sobre lo filtrado)
    counts = {
        'all':     base_qs.count(),
        'malware': base_qs.filter(risk_score__gte=81).count(),
        'danger':  base_qs.filter(risk_score__gte=61, risk_score__lt=81).count(),
        'warning': base_qs.filter(risk_score__gt=30, risk_score__lt=61).count(),
        'safe':    base_qs.filter(risk_score__lte=30).count(),
    }

    qs = base_qs

    # ── Filtro por categoría ───────────────────────────────────────────
    filter_ = (request.GET.get('filter') or 'all').strip().lower()
    if filter_ == 'malware':
        qs = qs.filter(risk_score__gte=81)
    elif filter_ == 'danger':
        qs = qs.filter(risk_score__gte=61, risk_score__lt=81)
    elif filter_ == 'warning':
        qs = qs.filter(risk_score__gt=30, risk_score__lt=61)
    elif filter_ == 'safe':
        qs = qs.filter(risk_score__lte=30)
    else:
        filter_ = 'all'

    # ── Búsqueda libre ─────────────────────────────────────────────────
    q = (request.GET.get('q') or '').strip()
    if q:
        qs = qs.filter(
            Q(file_info__filename__icontains=q) |
            Q(email__subject__icontains=q) |
            Q(email__from_email__icontains=q) |
            Q(threat_name__icontains=q)
        )

    qs = qs.select_related('email', 'email__alias').order_by('-analyzed_at')

    # ── Paginación ─────────────────────────────────────────────────────
    paginator = Paginator(qs, PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    # Timestamp compacto ("3 d", "53 min", "2 h"…)
    _now = timezone.now()
    for a in page_obj.object_list:
        delta = _now - a.analyzed_at
        secs = int(delta.total_seconds())
        if   secs < 45:        a.time_short = 'ahora'
        elif secs < 3600:      a.time_short = f'{max(1, secs // 60)} min'
        elif secs < 86400:     a.time_short = f'{secs // 3600} h'
        elif secs < 86400 * 7: a.time_short = f'{secs // 86400} d'
        else:                  a.time_short = f'{secs // (86400*7)} sem'

    return render(request, 'sandbox/sandbox_list.html', {
        'page_obj':      page_obj,
        'analyses':      page_obj.object_list,
        'counts':        counts,
        'q':             q,
        'filter':        filter_,
        'qs_params':     _qs_params(request),
        # Compat: estadísticas en el hero (4 stat cards)
        'total_count':   counts['all'],
        'blocked_count': counts['danger'] + counts['malware'],
        'safe_count':    counts['safe'],
        'warning_count': counts['warning'],
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
    qs = SandboxAnalysis.objects.select_related(
        'email__alias', 'dynamic', 'file_info', 'body_analysis', 'ai_result',
    )
    if request.user.is_staff:
        analysis = get_object_or_404(qs, pk=pk)
    else:
        analysis = get_object_or_404(qs, pk=pk, email__alias__user=request.user)

    # Contexto enriquecido de reglas YARA detectadas — se inyecta al
    # prompt del análisis IA del cliente para que pueda explicar cada
    # regla en lenguaje claro sin pegarle a Groq por cada `?`.
    yara_context = []
    dynamic = getattr(analysis, 'dynamic', None)
    yara_matches = dynamic.yara_matches if dynamic else []
    for match in (yara_matches or [])[:10]:
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

    # Sanitiza evidencia y otros campos JSON para eliminar
    # caracteres de control Unicode (RTL override, etc.)
    if dynamic:
        if dynamic.evidence:
            dynamic.evidence = _sanitize_value(dynamic.evidence)
        if dynamic.iocs:
            dynamic.iocs = _sanitize_value(dynamic.iocs)
    body = getattr(analysis, 'body_analysis', None)
    if body and body.body_evidence:
        body.body_evidence = _sanitize_value(body.body_evidence)

    evidence_groups = _group_evidence(analysis.dynamic.evidence if dynamic else [])

    return render(request, 'sandbox/sandbox_report.html', {
        'analysis':          analysis,
        'yara_context_json': json.dumps(yara_context, ensure_ascii=False),
        'evidence_groups':   evidence_groups,
    })


# ─────────────────────────────────────────────────────────────────────
#  Desbloquear archivo protegido con contraseña
# ─────────────────────────────────────────────────────────────────────

@login_required(login_url='login')
@require_POST
def sandbox_unlock_view(request, pk):
    """POST {password: "..."} → re-analiza con contraseña, actualiza BD."""
    qs = SandboxAnalysis.objects.select_related(
        'email__alias', 'email__attachment', 'dynamic', 'file_info', 'body_analysis',
    )
    if request.user.is_staff:
        analysis = get_object_or_404(qs, pk=pk)
    else:
        analysis = get_object_or_404(qs, pk=pk, email__alias__user=request.user)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'ok': False, 'error': 'JSON inválido'}, status=400)

    password = (data.get('password') or '').strip()
    if not password:
        return JsonResponse({'ok': False, 'error': 'Contraseña requerida'}, status=400)

    if len(password) > 128:
        return JsonResponse({'ok': False, 'error': 'Contraseña demasiado larga'}, status=400)

    if any(ord(c) < 32 for c in password):
        return JsonResponse({'ok': False, 'error': 'Caracteres no válidos en la contraseña'}, status=400)

    filename = (data.get('filename') or '').strip()
    if not filename:
        return JsonResponse({'ok': False, 'error': 'Nombre de archivo requerido'}, status=400)

    session_key = f'unlock_attempts_{pk}'
    now = time.time()
    attempt_data = request.session.get(session_key)
    if isinstance(attempt_data, dict):
        attempts = attempt_data.get('count', 0)
        first_time = attempt_data.get('time', 0)
        if attempts >= 3 and (now - first_time) < 600:
            return JsonResponse({
                'ok': False, 'error': 'Demasiados intentos. Esperá unos minutos.',
            }, status=429)
        if (now - first_time) >= 600:
            attempts = 0
    else:
        attempts = 0

    # Buscar filepath del archivo específico en attachments_reports
    filepath = ''
    body_analysis = analysis.body_analysis
    if body_analysis and body_analysis.attachments_reports:
        for att in body_analysis.attachments_reports:
            if att.get('filename') == filename:
                filepath = att.get('filepath', '') or ''
                break
    if not filepath:
        try:
            filepath = analysis.email.attachment.attachment_path if analysis.email and hasattr(analysis.email, 'attachment') and analysis.email.attachment else ''
        except Exception:
            filepath = ''
    if not filepath or not os.path.exists(filepath):
        return JsonResponse({'ok': False, 'error': 'Archivo no disponible'}, status=404)

    request.session[session_key] = {
        'count': attempts + 1,
        'time': now if attempts == 0 else attempt_data['time'],
    }

    from .service import run_sandbox_with_password
    report = run_sandbox_with_password(filepath, password)

    if not report:
        return JsonResponse({'ok': False, 'error': 'Error al re-analizar'}, status=500)

    # Verificar si el reporte sigue teniendo password_protected (contraseña incorrecta)
    still_protected = any(
        ev.get('type') == 'password_protected'
        for ev in (report.get('evidence') or [])
    )
    has_password_ev = report.get('evidence') and still_protected

    if has_password_ev:
        return JsonResponse({
            'ok': True,
            'changed': False,
            'error': 'Contraseña incorrecta',
        })

    # Contraseña correcta — resetear intentos y actualizar BD
    if session_key in request.session:
        del request.session[session_key]

    dynamic, _ = DynamicAnalysis.objects.get_or_create(analysis=analysis)

    # Reemplazar solo la evidencia del archivo desbloqueado
    old_evidence = dynamic.evidence or []
    prefix = f'[{filename}]'
    new_evidence = []
    for ev in (report.get('evidence') or []):
        ev_copy = dict(ev)
        ev_copy['detail'] = f'{prefix} {_sanitize_value(ev.get("detail", ""))}'
        new_evidence.append(ev_copy)
    filtered = [ev for ev in old_evidence if not ev.get('detail', '').startswith(prefix)]
    dynamic.evidence = filtered + new_evidence

    dynamic.iocs = _sanitize_value(report.get('iocs', {}))
    dynamic.category = report.get('category', dynamic.category)
    dynamic.yara_matches = _sanitize_value(report.get('yara_matches', []))
    dynamic.network_connections = _sanitize_value(report.get('network_connections', []))
    dynamic.child_processes = _sanitize_value(report.get('child_processes', []))
    dynamic.file_writes = _sanitize_value(report.get('file_writes', []))
    dynamic.analyzers_run = _sanitize_value(report.get('analyzers_run', []))
    dynamic.save()

    analysis.dynamic = dynamic

    # Actualizar attachments_reports con el nuevo reporte del archivo desbloqueado
    if body_analysis and body_analysis.attachments_reports:
        updated = []
        for att in body_analysis.attachments_reports:
            if att.get('filename') == filename:
                att['risk_score'] = int(report.get('risk_score', 0))
                att['risk_level'] = report.get('risk_level', 'safe')
                att['threat_name'] = report.get('threat_name', '')
                att['evidence'] = report.get('evidence', [])
                att['iocs'] = report.get('iocs', {'urls': [], 'ips': [], 'domains': [], 'hashes': []})
                att['yara_matches'] = report.get('yara_matches', [])
                att['analyzers_run'] = report.get('analyzers_run', [])
                att['category'] = report.get('category', att.get('category', 'unknown'))
            updated.append(att)
        body_analysis.attachments_reports = updated
        body_analysis.save(update_fields=['attachments_reports'])

    # Recalcular score global como el max score de todos los attachments
    all_scores = [0]
    if body_analysis and body_analysis.attachments_reports:
        for att in body_analysis.attachments_reports:
            all_scores.append(int(att.get('risk_score', 0)))
    final_score = max(all_scores)
    analysis.risk_score = final_score
    analysis.risk_level = 'malware' if final_score >= 81 else ('danger' if final_score >= 61 else ('warning' if final_score >= 31 else 'safe'))
    analysis.threat_name = report.get('threat_name', '')
    analysis.save(update_fields=['risk_score', 'risk_level', 'threat_name'])

    # Actualizar el score en el EmailMessage para bandeja/detalle/color
    analysis.email.risk_score = final_score
    analysis.email.save(update_fields=['risk_score'])

    # Actualizar la notificación existente con el nuevo score/tipo
    from apps.notifications.models import Notification
    try:
        notif = Notification.objects.filter(
            related_email=analysis.email,
            user=request.user,
        ).latest('created_at')
        alias_email = analysis.email.alias.address if analysis.email and analysis.email.alias else '—'
        sender = analysis.email.from_email or '—'
        if final_score >= 61:
            notif.type = 'threat_alert'
            notif.title = f'Correo AMENAZA BLOQUEADA en {alias_email}'
            notif.message = f'De: {sender} · Riesgo alto ({final_score}/100)'
            notif.status = 'done'
        elif final_score >= 31:
            notif.type = 'forward_request'
            notif.title = f'Correo SOSPECHOSO en {alias_email}'
            notif.message = f'De: {sender} · Riesgo medio ({final_score}/100) — ¿reenviar a tu correo real?'
            notif.status = 'pending'
        else:
            notif.type = 'forwarded'
            notif.title = f'Correo SEGURO en {alias_email}'
            notif.message = f'De: {sender} · Riesgo bajo ({final_score}/100)'
            notif.status = 'approved'
        notif.read = False
        notif.save()
    except Notification.DoesNotExist:
        pass

    # Enviar alerta por correo si el desbloqueo reveló una amenaza real
    if final_score >= 61:
        from apps.mail.webhook import send_threat_alert
        send_threat_alert(
            analysis.email,
            {
                'risk_score':  final_score,
                'threat_name': analysis.threat_name,
                'filename':    filename,
                'attachment_count': 1,
            },
            sandbox_id=analysis.id,
            alert_type='unlock',
        )

    # Eliminar análisis IA previo para que se regenere con la nueva evidencia
    try:
        if hasattr(analysis, 'ai_result') and analysis.ai_result:
            analysis.ai_result.delete()
    except Exception:
        pass

    messages.success(request, 'Archivo desbloqueado — reporte actualizado con los nuevos datos del análisis.')
    if final_score >= 61:
        messages.error(request, f'Amenaza bloqueada — Riesgo alto ({final_score}/100)')
    elif final_score >= 31:
        messages.warning(request, f'Sospechoso — Riesgo medio ({final_score}/100)')
    else:
        messages.success(request, f'Seguro — Riesgo bajo ({final_score}/100)')

    # Renderizar HTML de la sección de evidencia actualizada
    evidence_groups = _group_evidence(dynamic.evidence if dynamic else [])
    evidence_html = render_to_string(
        'sandbox/_evidence_section.html',
        {'evidence_groups': evidence_groups, 'analysis': analysis},
        request=request,
    )

    return JsonResponse({
        'ok': True,
        'changed': True,
        'score': analysis.risk_score,
        'risk_level': analysis.risk_level,
        'threat_name': analysis.threat_name,
        'evidence_html': evidence_html,
        'evidence_count': len(dynamic.evidence) if dynamic else 0,
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


def _run_groq_analysis_async(prompt: str, analysis):
    """Ejecuta Groq y cachea el resultado en BD. Corre en un thread separado."""
    api_key = os.environ.get('GROQ_API_KEY', '').strip()
    if not api_key:
        print('[ia] GROQ_API_KEY no configurada')
        return
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model='openai/gpt-oss-120b',
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=3500,
            temperature=0.4,
        )
        raw = response.choices[0].message.content
    except Exception as e:
        print('[ia] Error Groq:', e)
        return

    try:
        from django.utils import timezone
        ai_result, _ = IAResult.objects.get_or_create(analysis=analysis)
        blocks = _parse_ai_blocks(raw)
        ai_result.ai_verdict       = (blocks.get('VEREDICTO') or '')[:20]
        ai_result.ai_threat_type   = (blocks.get('TIPO DE AMENAZA') or '')[:100]
        ai_result.ai_explanation   = blocks.get('EXPLICACION') or ''
        ai_result.ai_recommendation = blocks.get('RECOMENDACION') or ''
        ai_result.ai_generated_at  = timezone.now()
        ai_result.save(update_fields=[
            'ai_verdict', 'ai_threat_type', 'ai_explanation',
            'ai_recommendation', 'ai_generated_at',
        ])
    except Exception as e:
        print('[ia] Error al cachear resultado:', e)


@login_required(login_url='login')
@require_POST
def ai_analysis_view(request):
    """
    Entrada:  {
        "prompt":      "texto del prompt construido por el frontend",
        "analysis_id": <int>            ← si viene, se cachea y corre async
    }
    Salida (cache hit):
        { "result": "...", "cached": true }
    Salida (cache miss + analysis_id):
        { "status": "processing", "analysis_id": <id> }
    Salida (sin analysis_id, síncrono):
        { "result": "...", "cached": false }
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

        ai_result = getattr(cached_obj, 'ai_result', None) if cached_obj else None
        if ai_result and ai_result.ai_explanation:
            # Reconstruimos el texto en el formato que espera el frontend
            parts = [
                f'VEREDICTO: {ai_result.ai_verdict or "SEGURO"}',
                f'TIPO DE AMENAZA: {ai_result.ai_threat_type or "No aplica"}',
                f'EXPLICACION: {ai_result.ai_explanation}',
                f'RECOMENDACION: {ai_result.ai_recommendation or ""}',
            ]
            return JsonResponse({
                'result': '\n\n'.join(parts),
                'cached': True,
            })

    # ── 2. Cache miss → Groq ──────────────────────────────────────────
    if cached_obj is not None:
        # Tenemos un análisis asociado → disparamos Groq en thread y
        # respondemos inmediatamente. El resultado se cachea en BD.
        import threading
        threading.Thread(
            target=_run_groq_analysis_async,
            kwargs={'prompt': prompt, 'analysis': cached_obj},
            daemon=True,
        ).start()
        return JsonResponse({'status': 'processing', 'analysis_id': analysis_id})

    # Sin analysis_id → modo síncrono (resultado sin cachear)
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
            model='openai/gpt-oss-120b',
            messages=[{'role': 'user', 'content': prompt}],
            max_tokens=3500,
            temperature=0.4,
        )
        raw = response.choices[0].message.content
    except Exception as e:
        err_str = str(e)
        print('ERROR IA:', err_str)
        if '429' in err_str or 'rate_limit' in err_str.lower() or 'tokens per day' in err_str.lower():
            import re as _re
            m = _re.search(r'try again in\s+(\d+)\s*m', err_str, _re.IGNORECASE)
            wait_min = int(m.group(1)) if m else 60
            return JsonResponse({
                'error': 'Se alcanzó el límite diario de la API de IA.',
                'code': 'rate_limit',
                'retry_after_min': wait_min,
            }, status=429)
        return JsonResponse({'error': err_str}, status=500)

    return JsonResponse({'result': raw, 'cached': False})


# ─────────────────────────────────────────────────────────────────────
#  Indexado de reglas YARA — se usa en sandbox_report_view para
#  enriquecer el contexto del análisis IA solo de las reglas que
#  hicieron match en el reporte. NO se parsean las 870 reglas
#  completas, solo se indexa nombre→posición (~50ms) y se extrae
#  metadata de las 1-5 reglas que realmente aplican.
# ─────────────────────────────────────────────────────────────────────

# {nombre_regla: (nombre_archivo, byte_offset)}
_NAME_INDEX = None
# {nombre_archivo: contenido_str}
_FILE_CACHE = {}
# {nombre_regla: {description, category, severity, strings, file}}
_META_CACHE = {}


def _build_name_index() -> dict:
    """
    Escanea todos los .yar y construye un índice liviano
    nombre_regla → (archivo, offset). Sin parsear meta blocks.
    """
    import re
    import glob
    base = os.path.join(os.path.dirname(__file__), 'analyzers', 'rules')
    files = sorted(glob.glob(os.path.join(base, '*.yar')))
    index = {}
    rule_re = re.compile(r'\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*[:{]')

    for fpath in files:
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            continue
        fkey = os.path.basename(fpath)
        _FILE_CACHE[fkey] = content
        for m in rule_re.finditer(content):
            index[m.group(1)] = (fkey, m.start())
    return index


def _parse_single_rule_body(body: str, fkey: str) -> dict:
    """Extrae metadata de UNA sola regla YARA desde su bloque de código."""
    desc = _extract_meta_field(body, 'description')
    cat = _extract_meta_field(body, 'category')
    sev = _extract_meta_field(body, 'severity') or _extract_meta_field(body, 'score')
    strings_preview = _extract_rule_strings_preview(body)
    return {
        'description': desc,
        'category':    cat,
        'severity':    sev,
        'strings':     strings_preview,
        'file':        fkey,
    }


def _yara_lookup(name: str) -> dict | None:
    """
    Busca metadata de UNA regla YARA por nombre sin parsear las 870.
    Construye el índice de nombres (~50ms) una sola vez y extrae el
    bloque de la regla solicitada (~1ms).
    """
    global _NAME_INDEX, _META_CACHE, _FILE_CACHE
    if _NAME_INDEX is None:
        try:
            _NAME_INDEX = _build_name_index()
        except Exception as e:
            print('YARA name index error:', e)
            _NAME_INDEX = {}
    if not _NAME_INDEX:
        return None

    # Cache de metadata ya extraída
    if name in _META_CACHE:
        return _META_CACHE[name]

    entry = _NAME_INDEX.get(name)
    if not entry:
        low = name.lower()
        for k, v in _NAME_INDEX.items():
            if k.lower() == low:
                entry = v
                break
    if not entry:
        return None

    fkey, start = entry
    content = _FILE_CACHE.get(fkey)
    if content is None:
        return None

    # Encontrar el bloque de la regla con balanceo de llaves
    brace = content.find('{', start)
    if brace < 0:
        return None
    depth = 0
    end = brace
    for i, ch in enumerate(content[brace:], start=brace):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i
                break
    body = content[brace:end + 1]

    meta = _parse_single_rule_body(body, fkey)
    _META_CACHE[name] = meta
    return meta


def _extract_rule_strings_preview(body: str) -> list:
    """
    Saca los primeros strings de la sección strings: de una regla YARA.
    Devuelve hasta 6 ejemplos truncados, suficiente para que la IA
    intuya QUÉ patrones busca la regla (ej: /Launch, /OpenAction, ...).
    """
    import re
    seg = re.search(
        r'\bstrings\s*:\s*(.+?)\bcondition\s*:',
        body, re.DOTALL | re.IGNORECASE,
    )
    if not seg:
        return []
    section = seg.group(1)

    out = []
    for m in re.finditer(r'\$\w+\s*=\s*"([^"\n]{1,120})"', section):
        out.append(m.group(1).strip())
    for m in re.finditer(r'\$\w+\s*=\s*/((?:[^/\\\n]|\\.){1,80})/[a-z]*', section):
        pat = m.group(1).replace('\\/', '/').replace('\\\\', '\\').strip()
        if pat:
            out.append('regex: ' + pat)
    for m in re.finditer(r'\$\w+\s*=\s*\{\s*([0-9a-fA-F\s\.\?\[\]\(\)\|]{2,80})\s*\}', section):
        hex_str = m.group(1).strip()
        out.append('hex: ' + hex_str)

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
    num = re.compile(rf'\b{re.escape(field)}\s*=\s*(\d+)', re.IGNORECASE).search(body)
    if num:
        return num.group(1)
    return ''


def _extract_rule_name_from_detail(detail: str) -> str | None:
    """Extrae el nombre de la regla YARA del detail si tiene formato
    'YARA `nombre_regla`: ...'."""
    import re
    if not detail:
        return None
    m = re.search(r'YARA\s*`([A-Za-z_][A-Za-z0-9_]*)`', detail)
    if m:
        return m.group(1)
    return None


