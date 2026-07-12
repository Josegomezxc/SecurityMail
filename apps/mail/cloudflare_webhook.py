

import os
import json
import re
import traceback
import email
from email import policy
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

from apps.aliases.models import Alias
from apps.sandbox.models import SandboxAnalysis, FileInfo, DynamicAnalysis, BodyAnalysis
from apps.sandbox.service import run_sandbox_analysis
from apps.sandbox import body_analyzer
from apps.sandbox import auth_check
from .models import EmailMessage, EmailAuthVerdict, EmailAttachment
from .webhook import (
    _bare_email,
    _neutralize_links_html,
    _decode_unicode_escapes,
    _html_to_text,
    _combine_many,
    _summarize,
    _merge_lists,
    _to_level,
    _create_notification,
    send_threat_alert,
    send_safe_email_forward,
)


@csrf_exempt
@require_POST
def inbound_cloudflare_webhook(request):
    try:
        return _handle_cloudflare(request)
    except Exception as e:
        print("━" * 60)
        print("CLOUDFLARE WEBHOOK FATAL")
        print(f"  motivo: {e}")
        print(traceback.format_exc())
        print("━" * 60)
        return HttpResponse("OK (error logged)", status=200)


def _parse_raw_mime(raw_bytes: bytes) -> dict:
   
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    sender = str(msg.get('From', ''))
    recipient = str(msg.get('To', ''))
    subject = str(msg.get('Subject', 'Sin asunto')) or 'Sin asunto'
    reply_to = str(msg.get('Reply-To', '')) or ''
    message_id = str(msg.get('Message-ID', '')) or ''

    body_text = ''
    body_html = ''

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain' and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = str(part.get_payload(decode=True) or b'', errors='replace')
            elif ct == 'text/html' and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    body_html = str(part.get_payload(decode=True) or b'', errors='replace')
    else:
        ct = msg.get_content_type()
        try:
            if ct == 'text/plain':
                body_text = msg.get_content()
            elif ct == 'text/html':
                body_html = msg.get_content()
            else:
                body_text = str(msg.get_payload(decode=True) or b'', errors='replace')
        except Exception:
            body_text = str(msg.get_payload(decode=True) or b'', errors='replace')

    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        cd = part.get('Content-Disposition', '')
        if not cd or 'attachment' not in cd.lower():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload:
            attachments.append((filename, payload))

    return {
        'sender': sender,
        'recipient': recipient,
        'subject': subject,
        'reply_to': reply_to,
        'body': body_text or '',
        'body_html': body_html or '',
        'message_id': message_id,
        'raw_attachments': attachments,
        'raw_headers': {k.lower(): str(v) for k, v in msg.items()},
    }


def _verify_raw_email(raw_bytes: bytes, sender_email: str) -> dict:
    import dkim as dkim_module

    sender_domain = _bare_email(sender_email).split('@')[-1].lower() if '@' in _bare_email(sender_email) else ''

    dkim_result = 'none'
    dkim_domain = ''
    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        dkim_header = str(msg.get('DKIM-Signature', ''))
        if dkim_header:
            for part in dkim_header.split(';'):
                part = part.strip()
                if part.lower().startswith('d='):
                    dkim_domain = part[2:].strip().lower()
                    break
            if dkim_module.verify(raw_bytes, timeout=10):
                dkim_result = 'pass'
            else:
                dkim_result = 'fail'
    except Exception as e:
        print(f"[cloudflare] dkim error: {e}")

    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    spf_result = 'none'
    received_spf = msg.get('Received-SPF', '')
    if received_spf:
        m = re.search(r'(pass|fail|softfail|neutral|none)', received_spf, re.I)
        if m:
            spf_result = m.group(1).lower()
    if spf_result == 'none':
        auth_h = msg.get('Authentication-Results', '')
        if auth_h:
            m = re.search(r'\bspf\s*=\s*(pass|fail|softfail|neutral|none)\b', auth_h, re.I)
            if m:
                spf_result = m.group(1).lower()

    dmarc_result = 'none'
    auth_h = msg.get('Authentication-Results', '')
    if auth_h:
        m = re.search(r'\bdmarc\s*=\s*(pass|fail|bestguesspass|none)\b', auth_h, re.I)
        if m:
            dmarc_result = m.group(1).lower()
            if dmarc_result == 'bestguesspass':
                dmarc_result = 'pass'

    def _align(dkim_d, sender_d):
        if not dkim_d or not sender_d:
            return False
        d = dkim_d.lower()
        s = sender_d.lower()
        return d == s or d.endswith('.' + s) or s.endswith('.' + d)

    aligned = _align(dkim_domain, sender_domain)

    if dkim_result == 'pass' and aligned:
        multiplier, floor = (0.35, 0) if dmarc_result == 'pass' else (0.45, 0)
        verdict = 'verified'
        evidence = f'Remitente verificado · DKIM pass · firmado por {dkim_domain}'
    elif dmarc_result == 'fail':
        verdict = 'spoofed'
        multiplier, floor = 1.0, 75
        evidence = f'Suplantación · DMARC fail · {sender_domain}'
    elif dkim_result == 'fail' and dmarc_result == 'fail':
        verdict = 'spoofed'
        multiplier, floor = 1.0, 75
        evidence = f'Suplantación · DKIM fail + DMARC fail · {sender_domain}'
    elif dkim_result == 'fail':
        verdict = 'unverified'
        multiplier, floor = 1.0, 0
        evidence = 'Firma DKIM no verificable (timeout DNS o algoritmo no soportado)'
    elif spf_result == 'fail' and dkim_result in ('none', ''):
        verdict = 'spoofed'
        multiplier, floor = 1.0, 65
        evidence = f'SPF fail · IP no autorizada por {sender_domain}'
    elif spf_result == 'pass' and dkim_result in ('none', ''):
        verdict = 'unverified'
        multiplier, floor = 0.85, 0
        evidence = 'SPF pass sin DKIM · autenticidad parcial'
    else:
        verdict = 'unverified'
        multiplier, floor = 1.0, 0
        evidence = 'Sin información de autenticación'

    return {
        'verdict': verdict, 'spf': spf_result, 'dkim': dkim_result,
        'dmarc': dmarc_result, 'dkim_domain': dkim_domain,
        'sender_domain': sender_domain, 'aligned': aligned,
        'evidence': evidence, 'score_multiplier': multiplier,
        'score_floor': floor,
    }


def _handle_cloudflare(request):
    raw_bytes = request.body
    if not raw_bytes:
        return HttpResponseBadRequest("Cuerpo vacío")

    parsed = _parse_raw_mime(raw_bytes)
    sender = parsed['sender']
    subject = parsed['subject']
    body = parsed['body']
    body_html = parsed['body_html']
    reply_to = parsed['reply_to']
    raw_attachments = parsed['raw_attachments']
    message_id = parsed['message_id']

    if not parsed['recipient'] or not sender:
        return HttpResponseBadRequest("Faltan campos requeridos")

    auth_result = _verify_raw_email(raw_bytes, sender)

    body = _decode_unicode_escapes(body)
    body_html = _decode_unicode_escapes(body_html)

    if not (body or '').strip() and body_html:
        body = _html_to_text(body_html)

    alias_address = _bare_email(parsed['recipient'])
    try:
        alias = Alias.objects.get(address__iexact=alias_address, is_active=True)
    except Alias.DoesNotExist:
        print(f"[cloudflare] alias desconocido: {alias_address}")
        return HttpResponse("OK", status=200)

    body_html_original = body_html or ''
    body_html_safe = _neutralize_links_html(body_html_original)

    if message_id and EmailMessage.objects.filter(resend_email_id=message_id).exists():
        print(f"[cloudflare] message_id {message_id} ya procesado, saltando")
        return HttpResponse("OK (duplicado)", status=200)

    email_obj = EmailMessage.objects.create(
        alias=alias,
        from_email=sender,
        subject=subject[:255],
        body=body,
        body_html=body_html_safe,
        body_html_raw=body_html_original,
        resend_email_id=message_id or None,
    )
    EmailAuthVerdict.objects.create(
        email=email_obj,
        auth_verdict=auth_result.get('verdict', 'unverified'),
        auth_spf=auth_result.get('spf', '')[:10],
        auth_dkim=auth_result.get('dkim', '')[:10],
        auth_dmarc=auth_result.get('dmarc', '')[:10],
        auth_signed_by=(auth_result.get('dkim_domain') or '')[:120],
    )

    try:
        body_report = body_analyzer.analyze(
            body_text=body,
            body_html=body_html,
            from_addr=sender,
            reply_to=reply_to,
            subject=subject,
            dkim_status='',
            spf_status='',
        )
    except Exception as e:
        print(f"[cloudflare] body_analyzer falló: {e}")
        body_report = {"score": 0, "evidence": [], "threat": ""}

    try:
        from apps.sandbox.cloud_downloader import download_from_urls
        body_urls = body_report.get('iocs', {}).get('urls', [])
        cloud_attachments = download_from_urls(body_urls)
        for fname, fbytes in cloud_attachments:
            raw_attachments.append((fname, fbytes))
    except Exception as e:
        print(f"[cloudflare] cloud_downloader error: {e}")

    attachment_reports = []
    attachments_summary = []
    for i, (att_name, att_bytes) in enumerate(raw_attachments, start=1):
        print(f"[cloudflare] adjunto {i}/{len(raw_attachments)}: {att_name}", flush=True)
        try:
            save_path = f"attachments/{alias.user.id}/{email_obj.id}_{i}_{att_name}"
            saved_name = default_storage.save(save_path, ContentFile(att_bytes))
            full_path = default_storage.path(saved_name)

            if i == 1:
                EmailAttachment.objects.update_or_create(
                    email=email_obj,
                    defaults={
                        'has_attachment': True,
                        'attachment_name': att_name,
                        'attachment_path': full_path,
                    },
                )

            class _AttachmentProxy:
                def __init__(self, path):
                    self.attachment_path = path
                @property
                def pk(self):
                    return None

            proxy = _AttachmentProxy(full_path)
            report = run_sandbox_analysis(proxy)
            print(f"[cloudflare] → score:{report['risk_score']} amenaza:{report.get('threat_name','')[:40]}", flush=True)
            report["_filename"] = att_name
            report["_filepath"] = full_path
            attachment_reports.append(report)
            attachments_summary.append(_summarize(report, att_name, full_path))
        except Exception as e:
            print(f"[cloudflare] adjunto {att_name} falló: {e}")
            attachments_summary.append({
                "filename": att_name, "filepath": "", "risk_score": 0,
                "risk_level": "safe", "threat_name": f"Error: {e}",
                "evidence": [{"type": "pipeline_error",
                              "detail": f"No se pudo analizar {att_name}: {e}",
                              "severity": 30}],
                "iocs": {"urls": [], "ips": [], "domains": [], "hashes": []},
                "category": "unknown", "real_mime": "", "extension": "",
                "extension_spoof": False, "sha256": "", "md5": "", "size": 0,
                "yara_matches": [], "analyzers_run": [],
            })

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

    final_score, threat_name, evidence_list, iocs, category, analyzers_run = \
        _combine_many(attachment_reports, body_report, url_report)

    attachment_max_score = max(
        [int(r.get('risk_score', 0)) for r in (attachment_reports or []) if r] + [0]
    )
    body_score = int((body_report or {}).get('score', 0))
    url_score = int((url_report or {}).get('score', 0))
    non_attachment_score = max(body_score, url_score)

    pre_auth_score = final_score
    adjusted_non_attachment, auth_evidence = auth_check.apply_to_score(
        non_attachment_score, auth_result,
    )
    final_score = max(adjusted_non_attachment, attachment_max_score)

    if auth_evidence and final_score != pre_auth_score:
        evidence_list.append(auth_evidence)
        if 'auth' not in analyzers_run:
            analyzers_run.append('auth')

    if (pre_auth_score >= 61 and final_score <= 30
            and attachment_max_score <= 30):
        threat_name = ''

    if auth_result.get('verdict') == 'spoofed' and not threat_name:
        threat_name = f"Suplantación de {auth_result.get('sender_domain', 'remitente')}"

    extension_spoof = any(r.get("extension_spoof") for r in attachment_reports)
    first = attachment_reports[0] if attachment_reports else {}

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
        top_att = max(attachments_summary, key=lambda a: a.get('risk_score', 0)) if attachments_summary else None
        combined_for_alert = {
            "risk_score": final_score,
            "threat_name": threat_name,
            "filename": top_att["filename"] if top_att else "(sin adjunto)",
            "attachment_count": len(attachments_summary),
        }
        send_threat_alert(email_obj, combined_for_alert, sandbox_id=sandbox.id)
        _create_notification(
            user=alias.user,
            ntype='threat_alert',
            title=f"Amenaza bloqueada en {alias.address}",
            message=f"De: {sender}  ·  {threat_name or 'Archivo malicioso'}",
            email=email_obj,
            status='done',
        )
    elif final_score <= 30:
        try:
            opted_in = bool(getattr(alias.user.profile, 'forward_safe_emails', False))
        except Exception:
            opted_in = False
        if opted_in:
            send_safe_email_forward(email_obj)
            _create_notification(
                user=alias.user,
                ntype='forwarded',
                title="Correo reenviado a tu correo real",
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
        _create_notification(
            user=alias.user,
            ntype='forward_request',
            title=f"Correo SOSPECHOSO en {alias.address}",
            message=f"De: {sender}  ·  Riesgo medio ({final_score}/100) — ¿reenviar a tu correo real?",
            email=email_obj,
            status='pending',
        )

    return HttpResponse("OK", status=200)
