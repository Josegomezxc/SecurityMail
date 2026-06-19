"""
apps/mail/webhook.py
Endpoint para recibir correos entrantes vía Resend Inbound.

Resend recibe los correos en el dominio dockershield.lat y los reenvía
a /webhook/inbound/ como POST JSON.

Para enviar (alertas + reenvíos) usamos también Resend (Email API).
"""

import os
import json
import re
import base64
import traceback
from datetime import datetime, timezone

from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

from apps.aliases.models import Alias
from apps.sandbox.models import SandboxAnalysis
from apps.sandbox.service import run_sandbox_analysis
from apps.sandbox import body_analyzer
from apps.sandbox import auth_check
from .models import EmailMessage, EmailAuthVerdict, EmailAttachment
from apps.sandbox.models import FileInfo, DynamicAnalysis, BodyAnalysis, IAResult


@csrf_exempt
@require_POST
def inbound_email_webhook(request):
    """
    Wrapper que captura cualquier excepción del pipeline y loguea con detalle.
    Siempre devuelve 200 para que Resend no reintente en bucle por un bug
    transitorio.

    """

    try:
        return _handle_inbound(request)
    except Exception as e:
        print("━" * 60)
        print("WEBHOOK FATAL — el correo se intentará guardar pero el análisis falló")
        print(f"  motivo: {e}")
        print(traceback.format_exc())
        print("━" * 60)
        try:
            _save_minimal_email(request, reason=str(e))
        except Exception as inner:
            print(f"  además falló el guardado mínimo: {inner}")
        return HttpResponse("OK (error logged)", status=200)


def _save_minimal_email(request, reason=""):
    """Guardado mínimo cuando todo el pipeline falla."""
    try:
        fields, _ = _extract_payload(request)
    except Exception:
        return
    recipient = _bare_email(fields['recipient'])
    if not recipient:
        return
    try:
        # Case-insensitive: los MTAs normalizan el destinatario a minúsculas
        alias = Alias.objects.get(address__iexact=recipient, is_active=True)
    except Alias.DoesNotExist:
        return
    EmailMessage.objects.create(
        alias=alias,
        from_email=fields['sender'] or "(desconocido)",
        subject=f"[ERROR ANÁLISIS] {fields['subject']}"[:255],
        body=(fields['body'] or "") + f"\n\n[Webhook: {reason}]",
    )


# ──────────────────────────────────────────────────────────────────────
#  Parser del payload de Resend Inbound (JSON)
# ──────────────────────────────────────────────────────────────────────

def _extract_payload(request):
    """
    Devuelve  (fields_dict, attachments_list).

    fields_dict = {
        'recipient', 'sender', 'subject', 'body', 'body_html', 'reply_to'
    }
    attachments_list = [(filename, bytes), ...]
    """
    try:
        raw = request.body
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='replace')
        envelope = json.loads(raw)
        # Resend envía el payload envuelto en { type, created_at, data: { ... } }
        webhook_data = envelope.get('data', envelope)
    except Exception as e:
        print(f"[webhook] error parseando JSON de Resend: {e}")
        return {}, []

    email_id = webhook_data.get('email_id', '')

    # Resend webhooks solo traen metadata — hay que llamar a la API
    # para obtener el cuerpo completo (html, text, headers).
    # Documentación: https://resend.com/docs/dashboard/receiving/get-email-content
    api_key = os.environ.get('RESEND_API_KEY', '').strip()
    if email_id and api_key:
        try:
            import resend
            resend.api_key = api_key
            full = resend.Emails.Receiving.get(email_id)
            data = {
                'from':          full.get('from', webhook_data.get('from', '')),
                'to':            full.get('to', webhook_data.get('to', [])),
                'subject':       full.get('subject', webhook_data.get('subject', 'Sin asunto')),
                'html':          full.get('html', '') or '',
                'text':          full.get('text', '') or '',
                'reply_to':      full.get('reply_to', webhook_data.get('reply_to', '')) or '',
                'headers':       full.get('headers', webhook_data.get('headers', {})),
                'attachments':   full.get('attachments', webhook_data.get('attachments', [])),
                'dkim':          full.get('dkim', webhook_data.get('dkim', '')),
                'spf':           full.get('spf', webhook_data.get('spf', '')),
                'spam_score':    full.get('spam_score', webhook_data.get('spam_score', 0.0)),
                'sender_ip':     full.get('sender_ip', webhook_data.get('sender_ip', '')),
            }
        except Exception as e:
            print(f"[webhook] error obteniendo contenido de API Resend: {e}")
            data = webhook_data
    else:
        data = webhook_data

    request._resend_payload = data

    fields = {
        'recipient': '',
        'sender':    data.get('from', ''),
        'subject':   data.get('subject', 'Sin asunto'),
        'body':      data.get('text', '') or '',
        'body_html': data.get('html', '') or '',
        'reply_to':  '',
    }

    reply_to = data.get('reply_to', '')
    if isinstance(reply_to, list) and reply_to:
        fields['reply_to'] = reply_to[0] or ''
    elif isinstance(reply_to, str):
        fields['reply_to'] = reply_to

    to_list = data.get('to', [])
    if isinstance(to_list, list) and to_list:
        fields['recipient'] = to_list[0]
    elif isinstance(to_list, str):
        fields['recipient'] = to_list

    # Descargar adjuntos desde Resend si tienen download_url
    attachments = []
    if email_id and api_key:
        for att in data.get('attachments', []):
            att_id = att.get('id', '') if isinstance(att, dict) else getattr(att, 'id', '')
            if not att_id:
                continue
            try:
                import resend
                resend.api_key = api_key
                details = resend.Emails.Receiving.Attachments.get(email_id, att_id)
                download_url = details.get('download_url', '') if isinstance(details, dict) else getattr(details, 'download_url', '')
                if download_url:
                    import requests as _req
                    resp = _req.get(download_url, timeout=30)
                    if resp.status_code == 200:
                        fname = att.get('filename', 'attachment') if isinstance(att, dict) else getattr(att, 'filename', 'attachment')
                        attachments.append((fname or 'attachment', resp.content))
            except Exception as e:
                print(f"[webhook] error descargando adjunto {att_id}: {e}")

    # Fallback: si algún attachment trae content base64 directo
    # (Resend nunca lo envía así — útil para test_webhook)
    for att in data.get('attachments', []):
        content_b64 = att.get('content', '') if isinstance(att, dict) else ''
        if content_b64:
            try:
                fname = att.get('filename', 'attachment') or 'attachment'
                file_bytes = base64.b64decode(content_b64)
                if not any(f == fname for f, _ in attachments):
                    attachments.append((fname, file_bytes))
            except Exception as e:
                print(f"[webhook] error decodificando attachment base64: {e}")

    return fields, attachments[:15]


# ──────────────────────────────────────────────────────────────────────
# _parse_raw_mime y _decode_part fueron eliminadas — Resend entrega
# todos los campos parseados directamente en JSON.


def _bare_email(value: str) -> str:
    """ 'Name <a@b.com>' → 'a@b.com' lowercase. """
    if not value:
        return ''
    if '<' in value and '>' in value:
        value = value.split('<')[-1].split('>')[0]
    return value.strip().lower()


def _extract_auth_status(headers):
    """Extrae dkim/spf del header Authentication-Results que Resend incluye en headers."""
    if not isinstance(headers, dict):
        return '', ''
    auth = ''
    for k, v in headers.items():
        if k.lower() == 'authentication-results':
            auth = v or ''
            break
    dkim_match = re.search(r'dkim\s*=\s*(pass|fail|neutral|none|softfail|hardfail)', auth, re.I)
    spf_match = re.search(r'spf\s*=\s*(pass|fail|neutral|none|softfail|hardfail)', auth, re.I)
    return (
        (dkim_match.group(1) if dkim_match else ''),
        (spf_match.group(1) if spf_match else ''),
    )


def _neutralize_links_html(html: str) -> str:
    """
    Quita la capacidad de navegar de los <a> del HTML del correo:
      - Borra el atributo href (el ctrl+click ya no abre nada).
      - Borra target/rel.
      - Marca el original como data-blocked-href para auditoría.
      - Añade clase 'sms-blocked-link' + title con motivo.
    Las imágenes externas también se neutralizan (no se cargan tracking pixels).
    Esto es defensa en profundidad: además del sandbox del iframe,
    los <a> ya no son clicables.
    """
    if not html:
        return html
    import re

    def _process_anchor(match):
        # Capturamos el contenido del tag <a ...>, lo limpiamos
        attrs = match.group(1)
        href_match = re.search(r'''href\s*=\s*["']([^"']*)["']''', attrs, re.IGNORECASE)
        original_href = href_match.group(1) if href_match else ''
        # Quitamos href, target, rel, onclick, etc.
        cleaned = re.sub(r'''\s*(href|target|rel|onclick|onmouseover|onmouseout)\s*=\s*["'][^"']*["']''',
                         '', attrs, flags=re.IGNORECASE)
        # Inline style + title con el href original
        safe_title = original_href.replace('"', '&quot;').replace('<', '&lt;')[:300]
        block_attrs = (
            f' class="sms-blocked-link"'
            f' data-blocked-href="{safe_title}"'
            f' title="Enlace bloqueado por seguridad — destino: {safe_title}"'
            f' style="pointer-events:none;cursor:not-allowed;color:#dc2626;'
            f'text-decoration:line-through wavy;opacity:0.75"'
            f' role="link" aria-disabled="true"'
        )
        return f'<a{cleaned}{block_attrs}>'

    # Procesa <a ...> de apertura (no toca el contenido ni el cierre)
    html = re.sub(r'<a\b([^>]*)>', _process_anchor, html, flags=re.IGNORECASE)

    # Quita imágenes externas (tracking pixels, blob, etc.) — solo deja inline data:
    def _process_img(match):
        attrs = match.group(1)
        src_match = re.search(r'''src\s*=\s*["']([^"']*)["']''', attrs, re.IGNORECASE)
        src = src_match.group(1) if src_match else ''
        if src.startswith('data:'):
            return match.group(0)  # Imagen inline, no es tracking → la dejamos
        # Reemplazamos por placeholder visible
        return ('<img src="data:image/svg+xml;utf8,'
                '<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22120%22 height=%2240%22>'
                '<rect width=%22120%22 height=%2240%22 fill=%22%23f3f4f6%22/>'
                '<text x=%2260%22 y=%2225%22 text-anchor=%22middle%22 '
                'font-family=%22monospace%22 font-size=%2210%22 fill=%22%236b7280%22>'
                'imagen bloqueada</text></svg>" '
                f'alt="Imagen externa bloqueada" title="Imagen externa bloqueada por seguridad" '
                f'style="border:1px dashed #9ca3af;padding:4px;border-radius:4px">')

    html = re.sub(r'<img\b([^>]*)>', _process_img, html, flags=re.IGNORECASE)

    # Inyecta CSS al principio del HTML para reforzar el bloqueo y dar feedback visual
    block_css = (
        '<style>'
        'a.sms-blocked-link:hover{background:#fee2e2 !important;outline:1px dashed #dc2626;}'
        'a[href]{pointer-events:none !important;cursor:not-allowed !important;}'
        '</style>'
    )
    # Si hay <head>, insertamos ahí; si no, al principio del documento
    if '<head>' in html.lower():
        html = re.sub(r'<head([^>]*)>', r'<head\1>' + block_css, html, count=1, flags=re.IGNORECASE)
    else:
        html = block_css + html

    return html


def _decode_unicode_escapes(text: str) -> str:
    """
    Algunos remitentes (Gamma, ciertas plataformas SaaS) mandan el body
    con secuencias unicode literales tipo  \\u002D  o  \\u000D\\u000A  en
    vez de los caracteres reales. Las decodificamos a su carácter Unicode.
    """
    if not text or '\\u' not in text:
        return text
    try:
        import re
        return re.sub(
            r'\\u([0-9a-fA-F]{4})',
            lambda m: chr(int(m.group(1), 16)),
            text,
        )
    except Exception:
        return text


def _html_to_text(html: str) -> str:
    """
    Convierte HTML a texto plano legible. Útil para mostrar en la bandeja
    cuando el correo viene solo en HTML (caso típico de Reddit, newsletters…).
    Limpia <style>, <script>, comentarios, y colapsa whitespace agresivamente
    para evitar bloques masivos de líneas vacías de tablas anidadas.
    """
    if not html:
        return ''
    import re
    import html as _html_lib
    from django.utils.html import strip_tags

    # Eliminar bloques con contenido no útil
    html = re.sub(r'<style[^>]*>.*?</style>',   '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<head[^>]*>.*?</head>',     '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<!--.*?-->',                '', html, flags=re.DOTALL)

    # Convertir tags estructurales en saltos antes de quitar
    html = re.sub(r'<br\s*/?>',                 '\n',  html, flags=re.IGNORECASE)
    html = re.sub(r'</(p|div|li|h[1-6]|tr)>',   '\n',  html, flags=re.IGNORECASE)

    # Quitar tags y decodificar entidades
    text = _html_lib.unescape(strip_tags(html))

    # Limpieza por línea: trim cada una, eliminar las vacías,
    # y colapsar runs de blancos múltiples → un solo salto entre párrafos.
    lines = [ln.strip() for ln in text.split('\n')]
    out = []
    prev_blank = True   # no dejar líneas vacías al principio
    for ln in lines:
        if ln:
            out.append(re.sub(r'[ \t ]+', ' ', ln))
            prev_blank = False
        elif not prev_blank:
            out.append('')
            prev_blank = True
    return '\n'.join(out).strip()


# ──────────────────────────────────────────────────────────────────────
#  Handler principal
# ──────────────────────────────────────────────────────────────────────

def _handle_inbound(request):

    # ── 1. Parsear payload del POST de Resend Inbound ──────────────────
    fields, raw_attachments = _extract_payload(request)

    if not fields['recipient'] or not fields['sender']:
        return HttpResponseBadRequest("Faltan campos requeridos")

    # ── 1.b Verificar autenticidad criptográfica (SPF/DKIM/DMARC) ──────
    # Resend ya hace estos chequeos y los entrega en el JSON del webhook.
    # Los usamos para distinguir correos legítimos (Netflix, Google,
    # etc.) de phishers que solo escriben un From falso.
    try:
        resend_data = getattr(request, '_resend_payload', {})
        raw_dkim_auth, raw_spf_auth = _extract_auth_status(resend_data.get('headers', {}))
        auth_post_data = {
            'SPF': raw_spf_auth or resend_data.get('spf', ''),
            'dkim': raw_dkim_auth or resend_data.get('dkim', ''),
            'headers': (
                json.dumps(resend_data.get('headers', {}))
                if isinstance(resend_data.get('headers'), dict)
                else (resend_data.get('headers', '') or '')
            ),
        }
        auth_result = auth_check.check_authentication(
            auth_post_data, sender_email=fields['sender'],
        )
    except Exception as e:
        print(f"[webhook] auth_check falló (continuando sin auth): {e}")
        auth_result = {
            'verdict': 'unverified', 'spf': '', 'dkim': '', 'dmarc': '',
            'dkim_domain': '', 'sender_domain': '', 'aligned': False,
            'evidence': '', 'score_multiplier': 1.0, 'score_floor': 0,
        }

    sender    = fields['sender']
    subject   = fields['subject']
    body      = fields['body']
    body_html = fields['body_html']
    reply_to  = fields['reply_to']

    # Decodifica escapes unicode literales que algunos remitentes envían
    # sin procesar (ej. la cadena "-" en vez del carácter "-").
    body      = _decode_unicode_escapes(body)
    body_html = _decode_unicode_escapes(body_html)

    # Si el correo solo trae HTML (típico de Reddit, Amazon, newsletters…),
    # extraemos texto plano para que la bandeja muestre algo legible.
    if not (body or '').strip() and body_html:
        body = _html_to_text(body_html)

    # ── 2. Buscar el alias destino ─────────────────────────────────────
    # Los MTAs normalizan el destinatario a minúsculas en el transporte.
    # Usamos __iexact para que coincida sin importar el case.
    alias_address = _bare_email(fields['recipient'])
    try:
        alias = Alias.objects.get(address__iexact=alias_address, is_active=True)
    except Alias.DoesNotExist:
        print(f"[webhook] alias desconocido: {alias_address} (correo descartado)")
        return HttpResponse("OK", status=200)

    # Neutraliza enlaces e imágenes externas SOLO para mostrar en la bandeja.
    # Guardamos también la versión RAW para poder reenviarla intacta al correo
    # real cuando el usuario lo apruebe (y sepa lo que está pidiendo).
    body_html_original = body_html or ''
    body_html_safe     = _neutralize_links_html(body_html_original)

    # ── Crear el EmailMessage ──────────────────────────────────────────
    email_obj = EmailMessage.objects.create(
        alias=alias,
        from_email=sender,
        subject=subject[:255],
        body=body,
        body_html=body_html_safe,
        body_html_raw=body_html_original,
    )
    EmailAuthVerdict.objects.create(
        email=email_obj,
        auth_verdict=auth_result.get('verdict', 'unverified'),
        auth_spf=auth_result.get('spf', '')[:10],
        auth_dkim=auth_result.get('dkim', '')[:10],
        auth_dmarc=auth_result.get('dmarc', '')[:10],
        auth_signed_by=(auth_result.get('dkim_domain') or '')[:120],
    )

    # ── 1. Analizar el CUERPO del correo (siempre) ─────────────────────
    try:
        resend_data = getattr(request, '_resend_payload', {})
        raw_dkim, raw_spf = _extract_auth_status(resend_data.get('headers', {}))
        body_report = body_analyzer.analyze(
            body_text=body,
            body_html=body_html,
            from_addr=sender,
            reply_to=reply_to,
            subject=subject,
            dkim_status=raw_dkim,
            spf_status=raw_spf,
        )
    except Exception as e:
        print(f"[webhook] body_analyzer falló: {e}")
        body_report = {"score": 0, "evidence": [], "threat": ""}

    # ── 2. Procesar TODOS los adjuntos (ya extraídos como (nombre, bytes)) ─
    attachment_reports = []    # uno por adjunto
    attachments_summary = []   # lo que se guarda en SandboxAnalysis.attachments_reports

    for i, (att_name, att_bytes) in enumerate(raw_attachments, start=1):
        print(f"[sandbox] adjunto {i}/{len(raw_attachments)}: {att_name}", flush=True)
        try:
            save_path  = f"attachments/{alias.user.id}/{email_obj.id}_{i}_{att_name}"
            saved_name = default_storage.save(save_path, ContentFile(att_bytes))
            full_path  = default_storage.path(saved_name)

            # En el 1er adjunto llenamos los campos en EmailAttachment
            if i == 1:
                EmailAttachment.objects.update_or_create(
                    email=email_obj,
                    defaults={
                        'has_attachment': True,
                        'attachment_name': att_name,
                        'attachment_path': full_path,
                    },
                )

            # Punto clave: damos un EmailMessage "proxy" al sandbox con la ruta
            # correcta para este adjunto (sin romper al 1er adjunto).
            proxy = _AttachmentProxy(full_path)
            report = run_sandbox_analysis(proxy)
            print(f"[sandbox] → score:{report['risk_score']} amenaza:{report.get('threat_name','')[:40]}", flush=True)
            report["_filename"] = att_name
            report["_filepath"] = full_path
            attachment_reports.append(report)
            attachments_summary.append(_summarize(report, att_name, full_path))
        except Exception as e:
            print(f"[webhook] adjunto {att_name} falló: {e}")
            print(traceback.format_exc())
            # Seguimos con los demás adjuntos en vez de caer
            attachments_summary.append({
                "filename": att_name,
                "filepath": "",
                "risk_score": 0,
                "risk_level": "safe",
                "threat_name": f"Error al analizar: {e}",
                "evidence": [{"type": "pipeline_error",
                              "detail": f"No se pudo analizar {att_name}: {e}",
                              "severity": 30}],
                "iocs": {"urls": [], "ips": [], "domains": [], "hashes": []},
                "category": "unknown",
                "real_mime": "", "extension": "", "extension_spoof": False,
                "sha256": "", "md5": "", "size": 0,
                "yara_matches": [], "analyzers_run": [],
            })

    # ── 3. URLs consolidadas (body + todos los adjuntos) ───────────────
    all_urls = list(body_report.get('iocs', {}).get('urls', []))
    for rep in attachment_reports:
        for u in (rep.get('iocs', {}) or {}).get('urls', []):
            if u not in all_urls:
                all_urls.append(u)

    url_report = None
    if all_urls:
        try:
            from apps.sandbox.analyzers import url_analyzer
            url_report = url_analyzer.analyze_urls(all_urls)
        except Exception as e:
            print("URL analyzer error:", e)

    # ── 4. Combinar todos los reportes ─────────────────────────────────
    final_score, threat_name, evidence_list, iocs, category, analyzers_run = \
        _combine_many(attachment_reports, body_report, url_report)

    # ── 4.b Ajustar score con el veredicto de autenticación ────────────
    # IMPORTANTE: la verificación SPF/DKIM/DMARC solo dice QUIÉN envió el
    # correo, NO si el contenido es peligroso. Un atacante puede firmar
    # legítimamente con DKIM su propio dominio y mandar malware desde ahí.
    #
    # Por eso aplicamos el ajuste cripto SOLO al score del contenido textual
    # (cuerpo del correo + URLs). El score del SANDBOX/YARA del adjunto
    # NUNCA se baja por DKIM — si hay malware, hay malware, sin importar
    # quién firmó el correo.
    attachment_max_score = max(
        [int(r.get('risk_score', 0)) for r in (attachment_reports or []) if r] + [0]
    )
    body_score = int((body_report or {}).get('score', 0))
    url_score  = int((url_report  or {}).get('score', 0))
    non_attachment_score = max(body_score, url_score)

    pre_auth_score = final_score
    adjusted_non_attachment, auth_evidence = auth_check.apply_to_score(
        non_attachment_score, auth_result,
    )
    # El veredicto final es el peor entre el adjunto (intacto) y el
    # contenido textual (ajustado por DKIM). Así, si llega malware con
    # firma DKIM válida, el score sigue siendo 100 y se bloquea.
    final_score = max(adjusted_non_attachment, attachment_max_score)

    # Solo metemos la evidencia del auth si afectó al veredicto final.
    # Si el adjunto domina con score 100, no tiene sentido decir
    # "score reducido" porque el correo se bloquea igual.
    if auth_evidence and final_score != pre_auth_score:
        evidence_list.append(auth_evidence)
        if 'auth' not in analyzers_run:
            analyzers_run.append('auth')

    # Si la auth bajó el score a "safe" Y no había malware en adjuntos,
    # limpiamos el threat_name (era falso positivo del body/URL).
    # Si el adjunto sí tenía amenaza, el threat_name se mantiene tal cual.
    if (pre_auth_score >= 61 and final_score <= 30
            and attachment_max_score <= 30):
        threat_name = ''   # falso positivo del contenido textual

    # Si la auth detectó spoof y no había threat_name, le ponemos uno
    if auth_result.get('verdict') == 'spoofed' and not threat_name:
        threat_name = f"Suplantación de {auth_result.get('sender_domain', 'remitente')}"

    # Si al menos un adjunto tiene extension_spoof, lo marcamos
    extension_spoof = any(r.get("extension_spoof") for r in attachment_reports)

    # Campos del 1er adjunto (retrocompat con el reporte visual actual)
    first = attachment_reports[0] if attachment_reports else {}

    # ── 5. Persistir el análisis ───────────────────────────────────────
    sandbox = SandboxAnalysis.objects.create(
        email=email_obj,
        risk_score=final_score,
        risk_level=_to_level(final_score),
        threat_name=threat_name,
        blocked=final_score >= 81,
    )
    FileInfo.objects.create(
        analysis=sandbox,
        filename=(
            attachments_summary[0]["filename"] if attachments_summary
            else "(sin adjunto)"
        ),
        real_mime_type=first.get('real_mime', ''),
        sha256_hash=first.get('sha256', ''),
        md5_hash=first.get('md5', ''),
        file_size=first.get('size', 0),
        extension=first.get('extension', ''),
        extension_spoof=extension_spoof,
    )
    DynamicAnalysis.objects.create(
        analysis=sandbox,
        category=category,
        yara_matches=_merge_lists(attachment_reports, 'yara_matches'),
        network_connections=_merge_lists(attachment_reports, 'network_connections'),
        child_processes=_merge_lists(attachment_reports, 'child_processes'),
        file_writes=_merge_lists(attachment_reports, 'file_writes'),
        evidence=evidence_list,
        iocs=iocs,
        analyzers_run=analyzers_run,
    )
    body_evidence_raw = body_report.get('evidence', [])
    seen = set()
    body_evidence = []
    for ev in body_evidence_raw:
        key = (ev.get("type"), ev.get("detail"))
        if key not in seen:
            seen.add(key)
            body_evidence.append(ev)

    BodyAnalysis.objects.create(
        analysis=sandbox,
        body_score=body_report.get('score', 0),
        body_evidence=body_evidence,
        body_threat=body_report.get('threat', ''),
        attachments_reports=attachments_summary,
    )

    email_obj.risk_score = final_score
    email_obj.save()

    if final_score >= 61:
        combined_for_alert = {
            "risk_score":  final_score,
            "threat_name": threat_name,
            "filename":    (attachments_summary[0]["filename"]
                            if attachments_summary else "(sin adjunto)"),
            "attachment_count": len(attachments_summary),
        }
        send_threat_alert(email_obj, combined_for_alert, sandbox_id=sandbox.id)
        # Notificación de amenaza bloqueada (informativa, sin acción)
        _create_notification(
            user=alias.user,
            ntype='threat_alert',
            title=f"Amenaza bloqueada en {alias.address}",
            message=f"De: {sender}  ·  {threat_name or 'Archivo malicioso'}",
            email=email_obj,
            status='done',
        )
    elif final_score <= 30:
        # Correo SEGURO:
        # 1) Si el usuario tiene auto-forward → reenviar y notificar como "forwarded".
        # 2) Si NO tiene auto-forward → crear notificación PENDIENTE para que decida.
        try:
            opted_in = bool(getattr(alias.user.profile, 'forward_safe_emails', False))
        except Exception:
            opted_in = False

        if opted_in:
            send_safe_email_forward(email_obj)
            _create_notification(
                user=alias.user,
                ntype='forwarded',
                title=f"Correo reenviado a tu correo real",
                message=f"De: {sender}  ·  {subject[:80]}",
                email=email_obj,
                status='done',
            )
        else:
            _create_notification(
                user=alias.user,
                ntype='forward_request',
                title=f"Nuevo correo seguro en {alias.address}",
                message=f"De: {sender}  ·  ¿quieres que llegue a tu correo real?",
                email=email_obj,
                status='pending',
            )
    else:
        # Rango medio (31-60): sospechoso pero NO bloqueado.
        # Lo tratamos como forward_request PENDIENTE para que el usuario decida
        # explícitamente si quiere reenviarlo a su Gmail asumiendo el riesgo.
        _create_notification(
            user=alias.user,
            ntype='forward_request',
            title=f"Correo SOSPECHOSO en {alias.address}",
            message=f"De: {sender}  ·  Riesgo medio ({final_score}/100) — ¿reenviar a tu correo real?",
            email=email_obj,
            status='pending',
        )

    return HttpResponse("OK", status=200)


def _create_notification(user, ntype, title, message, email=None, status='done'):
    """Helper: crea una Notification de forma segura (no rompe el webhook si falla)."""
    try:
        from apps.notifications.models import Notification
        Notification.objects.create(
            user=user, type=ntype, title=title[:200],
            message=message or '', related_email=email, status=status,
        )
    except Exception as e:
        print(f"[webhook] no se pudo crear notificación ({ntype}): {e}")


# _collect_attachments fue eliminada — los adjuntos ahora vienen como
# base64 dentro del JSON de Resend.


class _AttachmentProxy:
    """Objeto mínimo para que run_sandbox_analysis lea attachment_path."""
    def __init__(self, path):
        self.attachment_path = path


def _summarize(report, filename, filepath):
    """Crea el dict compacto que guardamos en attachments_reports."""
    return {
        "filename":       filename,
        "filepath":       filepath,
        "size":           report.get("size", 0),
        "real_mime":      report.get("real_mime", ""),
        "extension":      report.get("extension", ""),
        "extension_spoof": bool(report.get("extension_spoof")),
        "sha256":         report.get("sha256", ""),
        "md5":            report.get("md5", ""),
        "category":       report.get("category", "unknown"),
        "risk_score":     int(report.get("risk_score", 0)),
        "risk_level":     report.get("risk_level", "safe"),
        "threat_name":    report.get("threat_name", ""),
        "evidence":       report.get("evidence", []),
        "iocs":           report.get("iocs", {"urls": [], "ips": [], "domains": [], "hashes": []}),
        "yara_matches":   report.get("yara_matches", []),
        "analyzers_run":  report.get("analyzers_run", []),
    }


def _merge_lists(reports, key):
    """Une listas de varios reportes sin duplicados, mantiene orden."""
    out = []
    for r in reports:
        for item in (r or {}).get(key, []) or []:
            if item not in out:
                out.append(item)
    return out


# ──────────────────────────────────────────────────────────────────────
#  Combinación adjunto + cuerpo
# ──────────────────────────────────────────────────────────────────────

def _combine(attachment_report, body_report):
    """
    Combina los dos análisis en un veredicto único.
    El score final = MAX(adjunto, cuerpo) — el peor decide.
    """
    a = attachment_report or {}
    b = body_report or {}

    a_score = int(a.get('risk_score', 0))
    b_score = int(b.get('score', 0))

    final_score = max(a_score, b_score)

    # Threat name: el del adjunto pesa más, si no, el del body
    if a_score >= b_score and a.get('threat_name'):
        threat = a['threat_name']
    elif b.get('threat'):
        threat = b['threat']
    elif a.get('threat_name'):
        threat = a['threat_name']
    else:
        threat = ""

    # Evidence: combinada
    evidence = list(a.get('evidence', [])) + list(b.get('evidence', []))

    # IOCs: union
    iocs = {"urls": [], "ips": [], "domains": [], "hashes": []}
    for src in (a, b):
        src_iocs = src.get('iocs', {}) or {}
        for key in iocs.keys():
            for item in src_iocs.get(key, []):
                if item not in iocs[key]:
                    iocs[key].append(item)

    # Categoría: la del adjunto, si no, body
    category = a.get('category') or ('body' if b.get('evidence') else 'unknown')

    analyzers = list(a.get('analyzers_run', []))
    if b.get('evidence'):
        analyzers.append('body')

    return final_score, threat, evidence, iocs, category, analyzers


def _combine_many(attachment_reports, body_report, url_report=None):
    """
    Combina N reportes de adjuntos + el body + las URLs consolidadas.
    Devuelve el veredicto agregado.

    - final_score = MAX de todos — el peor adjunto / URL / body decide.
    - evidence    = unión con prefijo [archivo.ext] cuando viene de un adjunto
                    específico, para que sea claro a qué archivo pertenece.
    - iocs        = unión global sin duplicados.
    - category    = categoría del adjunto MÁS peligroso (si hay), si no body/url.
    - threat_name = el del adjunto con mayor score, o del body/url si pesan más.
    """
    scores    = []        # (score, label, category, threat)
    evidence  = []
    iocs      = {"urls": [], "ips": [], "domains": [], "hashes": []}
    analyzers = []

    # --- Cada adjunto ---
    for rep in attachment_reports or []:
        if not rep:
            continue
        fname = rep.get("_filename", rep.get("filename", "archivo"))
        score = int(rep.get("risk_score", 0))
        scores.append((score, f"attachment[{fname}]",
                       rep.get("category", "unknown"),
                       rep.get("threat_name", "")))

        # Evidencia con prefijo del archivo
        for ev in rep.get("evidence", []) or []:
            ev2 = dict(ev)
            ev2["detail"] = f"[{fname}] {ev.get('detail', '')}"
            evidence.append(ev2)

        # IOCs
        for key in iocs.keys():
            for item in (rep.get("iocs", {}) or {}).get(key, []) or []:
                if item not in iocs[key]:
                    iocs[key].append(item)

        # Analyzers
        for a in rep.get("analyzers_run", []) or []:
            tag = f"{a}:{fname}"
            if tag not in analyzers:
                analyzers.append(tag)

    # --- Body ---
    b = body_report or {}
    b_score = int(b.get("score", 0))
    if b.get("evidence") or b_score > 0:
        scores.append((b_score, "body", "body", b.get("threat", "")))
    for ev in b.get("evidence", []) or []:
        evidence.append(ev)
    for key in iocs.keys():
        for item in (b.get("iocs", {}) or {}).get(key, []) or []:
            if item not in iocs[key]:
                iocs[key].append(item)
    if b.get("evidence"):
        analyzers.append("body")

    # --- URLs consolidadas (body + todos los adjuntos) ---
    u = url_report or {}
    u_score = int(u.get("score", 0))
    if u.get("evidence"):
        scores.append((u_score, "url", "url", u.get("threat", "")))
        for ev in u.get("evidence", []) or []:
            evidence.append(ev)
        for key in iocs.keys():
            for item in (u.get("iocs", {}) or {}).get(key, []) or []:
                if item not in iocs[key]:
                    iocs[key].append(item)
        analyzers.append("url")

    # --- Veredicto agregado ---
    if not scores:
        return 0, "", evidence, iocs, "unknown", analyzers

    scores.sort(key=lambda t: t[0], reverse=True)
    final_score = scores[0][0]
    category    = scores[0][2]

    # Threat name: el del de mayor score. Si hay más de un adjunto con
    # score alto, lo indicamos.
    top = [s for s in scores if s[0] == final_score and s[3]]
    if len(top) > 1:
        threat = " · ".join(dict.fromkeys(s[3] for s in top))
    elif top:
        threat = top[0][3]
    else:
        threat = scores[0][3] or ""

    n_att = len([r for r in (attachment_reports or []) if r])
    if n_att > 1 and final_score >= 61:
        threat = f"{threat} (en {n_att} adjuntos)"

    # Deduplicar evidence por (type, detail)
    seen = set()
    unique = []
    for ev in evidence:
        key = (ev.get("type"), ev.get("detail"))
        if key not in seen:
            seen.add(key)
            unique.append(ev)
    evidence = unique

    # threat_name del modelo tiene max_length=200 — truncamos con elipsis
    if len(threat) > 200:
        threat = threat[:197].rstrip() + "…"

    return final_score, threat, evidence, iocs, category, analyzers


def _to_level(score: int) -> str:
    if score <= 30:  return 'safe'
    if score <= 60:  return 'warning'
    if score <= 80:  return 'danger'
    return 'malware'


# ══════════════════════════════════════════════════════════════════════
#  HELPER CENTRALIZADO DE ENVÍO POR RESEND
# ══════════════════════════════════════════════════════════════════════

def _send_via_resend(from_addr, to_email, subject, html_body,
                     reply_to=None, attachments=None, send_at=None):
    """
    Envía un correo HTML usando la API de Resend.

    Parámetros:
        from_addr   : "Nombre <correo@dominio>" o solo "correo@dominio"
        to_email    : str (un solo destinatario)
        subject     : str
        html_body   : str con HTML completo del correo
        reply_to    : str opcional con el correo de respuesta
        attachments : lista opcional de {filename, content (base64 str), type}
        send_at     : Unix timestamp opcional para envío programado.
                      Se convierte a ISO 8601 para Resend.

    Devuelve True si se envió, False si falló.
    """
    api_key = os.environ.get('RESEND_API_KEY', '').strip()
    if not api_key:
        print('[webhook] RESEND_API_KEY no configurada — correo no enviado.')
        return False

    try:
        import resend
        resend.api_key = api_key

        params = {
            'from':    from_addr,
            'to':      [to_email] if isinstance(to_email, str) else to_email,
            'subject': subject,
            'html':    html_body,
        }

        if reply_to:
            params['reply_to'] = reply_to

        # Envío programado: convertir Unix timestamp a ISO 8601
        if send_at:
            try:
                dt = datetime.fromtimestamp(int(send_at), tz=timezone.utc)
                params['scheduled_at'] = dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            except Exception as e:
                print(f'[webhook] send_at inválido ({send_at}): {e}')

        if attachments:
            params['attachments'] = []
            for att in attachments:
                resend_att = {
                    'filename': att['filename'],
                    'content':  att['content'],
                }
                if 'type' in att:
                    resend_att['content_type'] = att['type']
                params['attachments'].append(resend_att)

        resp = resend.Emails.send(params)
        return True

    except Exception as e:
        print(f'[webhook] error enviando vía Resend: {e}')
        return False


# ══════════════════════════════════════════════════════════════════════
#  ALERTA DE AMENAZA VÍA RESEND
# ══════════════════════════════════════════════════════════════════════

def send_threat_alert(email_obj, result, sandbox_id=None):
    """
    Envía un correo de alerta al usuario cuando se detecta
    un archivo malicioso en uno de sus alias.

    sandbox_id: pk del SandboxAnalysis para enlazar directo al reporte.
    En producción define SITE_URL en tu .env:
        SITE_URL=https://tudominio.com
    """
    try:
        risk_score  = result.get('risk_score', 0)
        threat_name = result.get('threat_name', 'Amenaza desconocida')
        filename    = result.get('filename', getattr(getattr(email_obj, 'attachment', None), 'attachment_name', ''))
        alias_addr  = email_obj.alias.address
        sender      = email_obj.from_email
        subject_txt = email_obj.subject
        user_email  = email_obj.alias.user.email
        timestamp   = datetime.now(timezone.utc).strftime('%d %b %Y · %H:%M UTC')

        # ── URL del reporte ────────────────────────────────────────────
        # Usamos el helper centralizado para que TODOS los correos
        # apunten al mismo dominio (settings.SITE_URL ← .env SITE_URL),
        # y la barra final se normalice automáticamente.
        from apps.core.services.email_service import get_site_url
        from django.urls import reverse
        base_url   = get_site_url()
        report_url = (
            f"{base_url}{reverse('sandbox_report', kwargs={'pk': sandbox_id})}"
            if sandbox_id
            else f"{base_url}/sandbox/"
        )
        logo_url = f"{base_url}/static/core/img/logo.png"

        # ── Nivel de amenaza ───────────────────────────────────────────
        if risk_score >= 81:
            level_label  = "MALWARE DETECTADO Y BLOQUEADO"
            level_color  = "#ef4444"
            level_bg     = "rgba(239,68,68,0.08)"
            level_border = "rgba(239,68,68,0.15)"
            level_tag    = "CRÍTICO"
        else:
            level_label  = "ARCHIVO DE ALTO RIESGO BLOQUEADO"
            level_color  = "#f97316"
            level_bg     = "rgba(249,115,22,0.08)"
            level_border = "rgba(249,115,22,0.15)"
            level_tag    = "ALTO RIESGO"

        html_body = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Alerta de amenaza · DockerShield</title>
</head>
<body style="margin:0;padding:0;background:#0d0c1a;font-family:'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d0c1a;padding:32px 16px">
  <tr>
    <td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
        <tr>
          <td style="background:#161527;border:1px solid rgba(109,74,255,0.25);border-radius:14px;overflow:hidden">

            <!-- HEADER morado — Logo centrado + tagline + pill ALERTA -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#6d4aff">
              <tr>
                <td align="center" style="padding:26px 20px 22px">
                  <!-- Logo grande centrado (con tinte blanco implícito por fondo morado) -->
                  <img src="{logo_url}" alt="DockerShield · Sistema de correo seguro" width="200"
                       style="display:block;height:auto;max-width:200px;margin:0 auto 10px;border:0;outline:none;text-decoration:none">

                  <!-- Tagline blanco translúcido -->
                  <div style="font-size:11.5px;color:rgba(255,255,255,0.78);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;letter-spacing:0.02em;margin-bottom:14px">
                    Detectamos una amenaza en tu alias y la bloqueamos
                  </div>

                  <!-- Pill ALERTA ACTIVA centrada -->
                  <span style="background:rgba(255,255,255,0.18);border:1px solid rgba(255,255,255,0.3);border-radius:20px;padding:5px 14px;color:#ffffff;font-size:10.5px;font-family:monospace;letter-spacing:0.1em;white-space:nowrap;font-weight:700">&#9679; ALERTA ACTIVA</span>
                </td>
              </tr>
            </table>

            <!-- BANNER nivel de amenaza -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:{level_bg};border-bottom:1px solid {level_border}">
              <tr>
                <td style="padding:16px 28px">
                  <table cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="vertical-align:middle;padding-right:14px">
                        <div style="width:40px;height:40px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.25);border-radius:10px;text-align:center;line-height:40px">
                          <span style="color:{level_color};font-size:18px">&#9888;</span>
                        </div>
                      </td>
                      <td style="vertical-align:middle">
                        <div style="font-size:13px;font-weight:700;color:{level_color};letter-spacing:0.05em;text-transform:uppercase">{level_label}</div>
                        <div style="font-size:12px;color:#9e9cb8;margin-top:3px;line-height:1.5">Tu correo real <strong style="color:#e8e6f0">{user_email}</strong> nunca recibió este archivo.</div>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>

            <!-- CONTENIDO PRINCIPAL -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:24px 28px">

                  <!-- Score de riesgo -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:#1a1829;border:1px solid rgba(255,255,255,0.07);border-radius:10px;margin-bottom:18px">
                    <tr>
                      <td style="padding:16px 20px">
                        <table width="100%" cellpadding="0" cellspacing="0">
                          <tr>
                            <td><span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.08em">Puntuación de riesgo</span></td>
                            <td align="right"><span style="font-size:26px;font-weight:800;color:{level_color};letter-spacing:-0.02em">{risk_score}</span><span style="font-size:13px;color:#6b6884">/100</span></td>
                          </tr>
                        </table>
                        <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;background:#2a2840;border-radius:3px;height:6px">
                          <tr>
                            <td width="{risk_score}%" style="background:{level_color};border-radius:3px;height:6px;line-height:6px;font-size:1px">&nbsp;</td>
                            <td style="height:6px;line-height:6px;font-size:1px">&nbsp;</td>
                          </tr>
                        </table>
                        <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:6px">
                          <tr>
                            <td style="font-size:10px;color:#4b4868;font-family:monospace">0 — Seguro</td>
                            <td align="center" style="font-size:10px;color:{level_color};font-family:monospace;font-weight:700">{level_tag}</td>
                            <td align="right" style="font-size:10px;color:#4b4868;font-family:monospace">100 — Crítico</td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                  </table>

                  <!-- Archivo bloqueado -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid rgba(255,255,255,0.07);border-radius:10px;margin-bottom:18px">
                    <tr>
                      <td style="padding:10px 16px;background:#1a1829;border-bottom:1px solid rgba(255,255,255,0.06);border-radius:10px 10px 0 0">
                        <span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.07em">Archivo bloqueado</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:12px 16px">
                        <table cellpadding="0" cellspacing="0">
                          <tr>
                            <td style="padding-right:12px">
                              <span style="font-family:monospace;font-size:13px;color:#fca5a5;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);padding:4px 10px;border-radius:5px">{filename}</span>
                            </td>
                            <td><span style="font-size:12px;color:#6b6884">Análisis sandbox completado</span></td>
                          </tr>
                        </table>
                      </td>
                    </tr>
                  </table>

                  <!-- Detalles del correo -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid rgba(255,255,255,0.07);border-radius:10px;margin-bottom:18px">
                    <tr>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05);width:130px">
                        <span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.07em">Tipo de amenaza</span>
                      </td>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
                        <span style="font-size:13px;color:#e8e6f0">{threat_name}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
                        <span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.07em">Remitente</span>
                      </td>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
                        <span style="font-size:13px;color:#e8e6f0">{sender}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
                        <span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.07em">Asunto</span>
                      </td>
                      <td style="padding:11px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
                        <span style="font-size:13px;color:#e8e6f0">{subject_txt}</span>
                      </td>
                    </tr>
                    <tr>
                      <td style="padding:11px 16px">
                        <span style="font-size:11px;color:#6b6884;font-family:monospace;text-transform:uppercase;letter-spacing:0.07em">Alias atacado</span>
                      </td>
                      <td style="padding:11px 16px">
                        <span style="font-family:monospace;font-size:12px;color:#a78bfa;background:rgba(109,74,255,0.1);border:1px solid rgba(109,74,255,0.25);padding:3px 9px;border-radius:5px">{alias_addr}</span>
                      </td>
                    </tr>
                  </table>

                  <!-- Nota de seguridad -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(109,74,255,0.07);border:1px solid rgba(109,74,255,0.18);border-radius:10px;margin-bottom:24px">
                    <tr>
                      <td style="padding:14px 16px;font-size:12px;color:#9e9cb8;line-height:1.6">
                        El archivo fue analizado en un <strong style="color:#c4b8ff">contenedor Docker aislado</strong>. Tu PC nunca lo ejecutó ni lo vio. Tu correo real <strong style="color:#c4b8ff">{user_email}</strong> sigue 100% protegido.
                      </td>
                    </tr>
                  </table>

                  <!-- BOTÓN VER REPORTE -->
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td align="center" style="padding-bottom:12px">
                        <a href="{report_url}" target="_blank"
                           style="display:inline-block;background:#6d4aff;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;letter-spacing:0.02em;padding:14px 40px;border-radius:9px;border:1px solid rgba(255,255,255,0.15);font-family:'Helvetica Neue',Arial,sans-serif">
                          Ver reporte completo &rarr;
                        </a>
                      </td>
                    </tr>
                    <tr>
                      <td align="center" style="padding-bottom:2px">
                        <span style="font-size:11px;color:#4b4868;font-family:monospace">Si el botón no funciona, copia este enlace:</span>
                      </td>
                    </tr>
                    <tr>
                      <td align="center" style="padding-bottom:4px">
                        <a href="{report_url}" target="_blank"
                           style="font-size:11px;color:#8b6fff;font-family:monospace;text-decoration:none;word-break:break-all">{report_url}</a>
                      </td>
                    </tr>
                  </table>

                </td>
              </tr>
            </table>

            <!-- FOOTER -->
            <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid rgba(255,255,255,0.05)">
              <tr>
                <td style="padding:14px 28px">
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="font-size:11px;color:#4b4868;font-family:monospace">DockerShield &middot; alerta automática</td>
                      <td align="right" style="font-size:11px;color:#4b4868;font-family:monospace">{timestamp}</td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>

          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

</body>
</html>"""

        # Remitente: usa tu dominio verificado en Resend (MAIL_DOMAIN del .env)
        from django.conf import settings
        domain = settings.MAIL_DOMAIN or 'dockershield.lat'
        from_addr = f"DockerShield <alerts@{domain}>"

        ok = _send_via_resend(
            from_addr = from_addr,
            to_email  = user_email,   # ← Correo REAL del dueño del alias
            subject   = f"Amenaza bloqueada en tu alias — {filename}",
            html_body = html_body,
        )
        if ok:
            print(f"Alerta enviada a {user_email} · reporte: {report_url}")

    except Exception as e:
        print(f"Error enviando alerta: {e}")


# ══════════════════════════════════════════════════════════════════════
#  REENVÍO DE CORREOS SEGUROS (opt-in del usuario) — VÍA RESEND
# ══════════════════════════════════════════════════════════════════════

def send_safe_email_forward(email_obj, force=False):
    """
    Reenvía un correo SEGURO al correo real del usuario.

    - Si `force=False` (default): solo envía si el usuario activó la opción
      `forward_safe_emails` en su perfil (auto-forward).
    - Si `force=True`: ignora la opción y siempre envía. Se usa cuando el
      usuario aprueba MANUALMENTE un reenvío desde el panel de notificaciones.
    """
    try:
        user = email_obj.alias.user

        # Solo verificamos opt-in si NO es un envío forzado
        if not force:
            try:
                if not user.profile.forward_safe_emails:
                    return
            except Exception:
                return  # Sin profile, no reenviamos automáticamente

        user_email = user.email
        if not user_email:
            print("[forward] usuario sin correo real — no se reenvía")
            return

        from django.conf import settings
        from apps.core.services.email_service import get_site_url
        domain = settings.MAIL_DOMAIN or 'dockershield.lat'
        from_addr = f"DockerShield <forward@{domain}>"
        logo_url = f"{get_site_url()}/static/core/img/logo.png"

        original_sender  = email_obj.from_email or '(remitente desconocido)'
        original_subject = email_obj.subject or '(sin asunto)'
        alias_address    = email_obj.alias.address
        # Para reenviar usamos el HTML ORIGINAL sin neutralizar (links activos,
        # imágenes cargan, formato exacto). Fallback a la versión neutralizada
        # solo para correos viejos que no tienen el campo raw.
        body_html_raw    = getattr(email_obj, 'body_html_raw', '') or email_obj.body_html or ''
        body_text        = email_obj.body or ''
        # `original_subject` y `original_sender` ya están definidos arriba; el
        # wrapper minimalista no usa timestamp ni reabre estos campos.

        # ── Recolectar TODOS los adjuntos del correo ─────────────────────
        # Resend acepta adjuntos con {filename, content (base64), type}.
        # Limite total recomendado: ~25 MB por correo.
        import base64 as _b64

        attachments_payload = []
        attachments_meta = []   # para mostrar en el wrapper HTML
        total_size = 0
        MAX_TOTAL_SIZE = 25 * 1024 * 1024   # 25 MB

        # 1) Adjuntos del análisis (cubre múltiples adjuntos)
        att_paths = []
        try:
            body_analysis = getattr(email_obj.analysis, 'body_analysis', None)
            reports = body_analysis.attachments_reports if body_analysis else []
            for r in reports:
                fpath = r.get('filepath') if isinstance(r, dict) else None
                fname = r.get('filename') if isinstance(r, dict) else None
                if fpath and fname:
                    att_paths.append((fname, fpath))
        except Exception:
            pass

        # 2) Fallback: el campo del modelo EmailAttachment (1er adjunto)
        att = getattr(email_obj, 'attachment', None)
        if not att_paths and att and att.has_attachment and att.attachment_path:
            att_paths.append((att.attachment_name or 'attachment', att.attachment_path))

        # Leer y encodear cada uno
        for fname, fpath in att_paths:
            try:
                if not os.path.isfile(fpath):
                    print(f"[forward] adjunto no encontrado en disco: {fpath}")
                    continue
                size = os.path.getsize(fpath)
                if total_size + size > MAX_TOTAL_SIZE:
                    print(f"[forward] adjunto {fname} omitido (tamaño total excedería 25MB)")
                    continue
                with open(fpath, 'rb') as f:
                    content_b64 = _b64.b64encode(f.read()).decode('ascii')
                attachments_payload.append({
                    'filename': fname,
                    'content':  content_b64,
                })
                attachments_meta.append({'filename': fname, 'size': size})
                total_size += size
            except Exception as e:
                print(f"[forward] no se pudo leer adjunto {fname}: {e}")

        # Si tenemos HTML ORIGINAL lo usamos tal cual; si solo hay texto plano,
        # lo formateamos en <pre> para que mantenga saltos de línea.
        original_body_html = body_html_raw if body_html_raw else (
            f'<pre style="font-family:Consolas,Monaco,monospace;font-size:13px;'
            f'color:#1a1830;white-space:pre-wrap;word-wrap:break-word;margin:0">'
            f'{(body_text or "(Sin contenido)").replace("<", "&lt;").replace(">", "&gt;")}'
            f'</pre>'
        )

        # ── Banner HTML con la lista de adjuntos (si hay) ────────────────
        attachments_banner_html = ''
        if attachments_meta:
            def _fmt_size(b):
                if b < 1024: return f"{b} B"
                if b < 1024*1024: return f"{b // 1024} KB"
                return f"{b / 1048576:.1f} MB"
            items_html = ''
            for a in attachments_meta:
                items_html += (
                    f'<tr><td style="padding:9px 14px;border-bottom:1px solid rgba(255,255,255,0.06)">'
                    f'<table cellpadding="0" cellspacing="0" width="100%"><tr>'
                    f'<td width="32" valign="middle">'
                    f'<div style="width:30px;height:30px;background:rgba(124,92,255,0.18);border:1px solid rgba(124,92,255,0.3);border-radius:7px;text-align:center;line-height:30px">'
                    f'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg></div></td>'
                    f'<td valign="middle" style="padding-left:12px">'
                    f'<div style="font-size:12.5px;color:#f0eeff;font-weight:600;font-family:monospace">{a["filename"]}</div>'
                    f'<div style="font-size:11px;color:#9ca3af;margin-top:2px">{_fmt_size(a["size"])} · escaneado por sandbox</div>'
                    f'</td></tr></table></td></tr>'
                )
            # Envoltorio en tabla propia (fondo oscuro consistente)
            attachments_banner_html = (
                '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                'style="background:#0c0a18;border-bottom:1px solid rgba(255,255,255,0.06)">'
                '<tr><td style="padding:14px 22px 18px">'
                '<div style="font-size:11px;color:#a78bfa;font-family:monospace;letter-spacing:0.06em;margin-bottom:10px;text-transform:uppercase;font-weight:700">'
                f'Adjuntos ({len(attachments_meta)})</div>'
                '<table cellpadding="0" cellspacing="0" width="100%" style="border:1px solid rgba(255,255,255,0.08);border-radius:10px;overflow:hidden;background:#14121f">'
                f'{items_html}'
                '</table></td></tr></table>'
            )

        wrapper_html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
</head>
<body style="margin:0;padding:0;background:#0c0a18;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;color:#e5e7eb">

<!-- Línea de acento superior (firma de marca) -->
<div style="height:4px;background:linear-gradient(90deg,#6d4aff 0%,#9b6dff 40%,#22c55e 100%);font-size:0;line-height:0">&nbsp;</div>

<!-- ═══════ HEADER OSCURO — Logo centrado + tagline + pill VERIFICADO ═══════ -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0c0a18;border-bottom:1px solid rgba(255,255,255,0.06)">
  <tr>
    <td align="center" style="padding:28px 20px 22px">
      <!-- Logo grande centrado -->
      <img src="{logo_url}" alt="DockerShield · Correo seguro anti-phishing" width="220"
           style="display:block;height:auto;max-width:220px;margin:0 auto 12px;border:0;outline:none;text-decoration:none">

      <!-- Tagline informativo -->
      <div style="font-size:12px;color:#9ca3af;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;letter-spacing:0.01em;margin-bottom:14px">
        Correo seguro · sandbox aislado · análisis automático
      </div>

      <!-- Pill VERIFICADO centrada debajo del logo (tonos verdes adaptados a fondo oscuro) -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr>
        <td height="28" valign="middle" style="background:rgba(34,197,94,0.16);border:1px solid rgba(34,197,94,0.45);border-radius:20px;padding:0 14px 0 10px;line-height:28px">
          <table cellpadding="0" cellspacing="0" border="0"><tr>
            <td width="16" height="16" valign="middle" align="center" style="background:#22c55e;border-radius:50%;text-align:center;vertical-align:middle;line-height:16px;mso-line-height-rule:exactly;font-size:10px;color:#ffffff;font-weight:700;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif">
              &#10003;
            </td>
            <td width="6" style="line-height:0;font-size:0">&nbsp;</td>
            <td style="font-size:11px;font-weight:800;color:#86efac;letter-spacing:0.08em;line-height:1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">VERIFICADO POR SANDBOX</td>
          </tr></table>
        </td>
      </tr></table>
    </td>
  </tr>
</table>

<!-- ═══════ Sub-info OSCURO: alias + estado ═══════ -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#14121f;border-bottom:1px solid rgba(255,255,255,0.06)">
  <tr>
    <td style="padding:13px 28px;font-size:12px;color:#9ca3af">
      Recibido en tu alias
      <span style="display:inline-block;color:#a78bfa;font-family:'SF Mono',Menlo,Consolas,monospace;font-weight:600;background:rgba(124,92,255,0.14);border:1px solid rgba(124,92,255,0.25);padding:2px 8px;border-radius:5px;margin:0 3px;font-size:11px">{alias_address}</span>
      &nbsp;·&nbsp;
      Análisis sandbox <strong style="color:#4ade80">sin amenazas</strong>
    </td>
  </tr>
</table>

{attachments_banner_html or ''}

<!-- ═══════ CORREO ORIGINAL — card blanca con padding sobre fondo oscuro ═══════
     IMPORTANTE: el HTML del remitente puede tener su propio estilo (newsletters,
     correos con fondo blanco, etc.). NO oscurecemos ese contenido — solo lo
     envolvemos en un card blanco con margen para que se vea claramente que
     es el correo original, separado del chrome de DockerShield. -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0c0a18">
  <tr>
    <td style="padding:0 0">
      <div style="background:#ffffff;color:#1a1830">
        {original_body_html}
      </div>
    </td>
  </tr>
</table>

<!-- ═══════ FOOTER PROFESIONAL ═══════ -->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0c0a18;color:#e5e7eb;margin-top:36px">

  <tr><td style="height:3px;background:linear-gradient(90deg,#6d4aff,#9b6dff,#22c55e);font-size:0;line-height:0">&nbsp;</td></tr>

  <tr>
    <td style="padding:32px 28px 24px">

      <!-- Outer table que organiza el footer en bloques verticales -->
      <table cellpadding="0" cellspacing="0" border="0" width="100%">

        <!-- ROW 1: Logo real DockerShield (footer oscuro) -->
        <tr>
          <td style="padding-bottom:20px">
            <table cellpadding="0" cellspacing="0" border="0">
              <tr>
                <td valign="middle">
                  <img src="{logo_url}" alt="DockerShield" width="150" style="display:block;height:auto;max-width:150px;border:0;outline:none;text-decoration:none">
                </td>
                <td width="14" style="line-height:0;font-size:0">&nbsp;</td>
                <td valign="middle" style="font-size:11px;color:#8a87a8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;line-height:1.4;border-left:1px solid rgba(255,255,255,0.1);padding-left:14px">
                  Correo seguro<br>
                  <span style="color:#a78bfa">anti-phishing</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ROW 2: Eyebrow morado -->
        <tr>
          <td style="padding-bottom:8px">
            <div style="font-size:11px;font-weight:700;color:#a78bfa;text-transform:uppercase;letter-spacing:0.14em;font-family:'SF Mono',Menlo,Consolas,monospace;line-height:1.4">El sandbox protegió tu inbox</div>
          </td>
        </tr>

        <!-- ROW 3: Headline -->
        <tr>
          <td style="padding-bottom:24px">
            <div style="font-size:18px;font-weight:800;color:#f0eeff;line-height:1.4;letter-spacing:-0.01em;max-width:480px">Antes de llegar a ti, este correo pasó tres capas de seguridad.</div>
          </td>
        </tr>

        <!-- ROW 4: 3 cards con icons SÓLIDOS y blancos -->
        <tr>
          <td style="padding-bottom:18px">
            <table cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr>
                <!-- Card 1: Sandbox Docker — caja contenedor unicode -->
                <td valign="top" width="33%" style="padding-right:6px">
                  <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#13111d;border:1px solid #2a2742;border-radius:12px">
                    <tr>
                      <td style="padding:16px 14px">
                        <table cellpadding="0" cellspacing="0" border="0"><tr>
                          <td width="36" height="36" valign="middle" align="center" style="background:#22c55e;background:linear-gradient(135deg,#22c55e 0%,#16a34a 100%);border-radius:9px;text-align:center;vertical-align:middle;line-height:36px;mso-line-height-rule:exactly;font-size:18px;color:#ffffff;font-weight:700;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;box-shadow:0 3px 10px rgba(34,197,94,0.35)">
                            &#9635;
                          </td>
                        </tr></table>
                        <div style="font-size:12px;color:#f0eeff;font-weight:700;letter-spacing:0.005em;margin-top:12px;line-height:1.3">Sandbox Docker</div>
                        <div style="font-size:10.5px;color:#7d7a96;margin-top:4px;line-height:1.5">Adjuntos analizados en contenedor aislado sin internet</div>
                      </td>
                    </tr>
                  </table>
                </td>
                <!-- Card 2: Reglas YARA — check unicode -->
                <td valign="top" width="33%" style="padding:0 3px">
                  <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#13111d;border:1px solid #2a2742;border-radius:12px">
                    <tr>
                      <td style="padding:16px 14px">
                        <table cellpadding="0" cellspacing="0" border="0"><tr>
                          <td width="36" height="36" valign="middle" align="center" style="background:#22c55e;background:linear-gradient(135deg,#22c55e 0%,#16a34a 100%);border-radius:9px;text-align:center;vertical-align:middle;line-height:36px;mso-line-height-rule:exactly;font-size:20px;color:#ffffff;font-weight:700;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;box-shadow:0 3px 10px rgba(34,197,94,0.35)">
                            &#10003;
                          </td>
                        </tr></table>
                        <div style="font-size:12px;color:#f0eeff;font-weight:700;letter-spacing:0.005em;margin-top:12px;line-height:1.3">Reglas YARA</div>
                        <div style="font-size:10.5px;color:#7d7a96;margin-top:4px;line-height:1.5">Comparado contra firmas conocidas de malware</div>
                      </td>
                    </tr>
                  </table>
                </td>
                <!-- Card 3: Análisis IA — estrella unicode -->
                <td valign="top" width="33%" style="padding-left:6px">
                  <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#13111d;border:1px solid #2a2742;border-radius:12px">
                    <tr>
                      <td style="padding:16px 14px">
                        <table cellpadding="0" cellspacing="0" border="0"><tr>
                          <td width="36" height="36" valign="middle" align="center" style="background:#22c55e;background:linear-gradient(135deg,#22c55e 0%,#16a34a 100%);border-radius:9px;text-align:center;vertical-align:middle;line-height:36px;mso-line-height-rule:exactly;font-size:18px;color:#ffffff;font-weight:700;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;box-shadow:0 3px 10px rgba(34,197,94,0.35)">
                            &#9733;
                          </td>
                        </tr></table>
                        <div style="font-size:12px;color:#f0eeff;font-weight:700;letter-spacing:0.005em;margin-top:12px;line-height:1.3">Análisis IA</div>
                        <div style="font-size:10.5px;color:#7d7a96;margin-top:4px;line-height:1.5">Llama 3.3 evaluó el contenido por phishing</div>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ROW 5: Card "Tu correo real sigue oculto" -->
        <tr>
          <td>
            <table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:linear-gradient(135deg,rgba(124,92,255,0.14) 0%,rgba(124,92,255,0.05) 100%);border:1px solid rgba(124,92,255,0.32);border-radius:12px">
              <tr>
                <td style="padding:16px 18px">
                  <table cellpadding="0" cellspacing="0" border="0" width="100%">
                    <tr>
                      <td width="40" valign="top" style="padding-right:14px">
                        <table cellpadding="0" cellspacing="0" border="0">
                          <tr>
                            <td width="38" height="38" valign="middle" align="center" style="background:#6d4aff;background:linear-gradient(135deg,#6d4aff 0%,#9b6dff 100%);border-radius:9px;text-align:center;vertical-align:middle;line-height:38px;mso-line-height-rule:exactly;font-size:20px;color:#ffffff;font-weight:700;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;box-shadow:0 4px 12px rgba(109,74,255,0.4)">
                              &#128274;
                            </td>
                          </tr>
                        </table>
                      </td>
                      <td valign="top">
                        <div style="font-size:13px;color:#f0eeff;font-weight:700;line-height:1.4;margin-bottom:4px;letter-spacing:-0.005em">Tu correo real sigue oculto</div>
                        <div style="font-size:11.5px;color:#9b97b8;line-height:1.55">El remitente solo conoce el alias. Cuando quieras, destrúyelo desde tu panel sin afectar tu cuenta de Gmail.</div>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>

    </td>
  </tr>

  <!-- Pie fino -->
  <tr>
    <td style="padding:16px 28px;border-top:1px solid #1c1a2c;background:#08070f">
      <table cellpadding="0" cellspacing="0" border="0" width="100%">
        <tr>
          <td style="font-size:10.5px;color:#5e5b75;font-family:'SF Mono',Menlo,Consolas,monospace;letter-spacing:0.04em">
            © DockerShield
          </td>
          <td align="right" style="font-size:10.5px;color:#5e5b75">
            <span style="color:#a78bfa;font-weight:600">Gestionar reenvíos</span>
            <span style="color:#3a3850;margin:0 8px">·</span>
            <span style="font-family:'SF Mono',Menlo,Consolas,monospace">v1.0</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

</body>
</html>"""

        ok = _send_via_resend(
            from_addr   = from_addr,
            to_email    = user_email,
            subject     = f"[via {alias_address.split('@')[0]}] {original_subject}",
            html_body   = wrapper_html,
            reply_to    = original_sender,
            attachments = attachments_payload or None,
        )
        if ok:
            att_info = f" + {len(attachments_payload)} adjunto(s)" if attachments_payload else ""
            print(f"Correo seguro reenviado a {user_email} (alias: {alias_address}){att_info}")

    except Exception as e:
        print(f"Error reenviando correo seguro: {e}")