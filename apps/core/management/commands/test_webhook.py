"""
Simula un POST de Resend Inbound al webhook local.

Útil para probar el sandbox SIN depender de servicios externos.
Envía un payload JSON como lo haría Resend Inbound.

Ejemplos:
  # Test mínimo con EICAR
  python manage.py test_webhook --file eicar.com --to alias@dockershield.lat

  # Test con remitente y asunto custom
  python manage.py test_webhook --file evil.exe --to alias@dockershield.lat \
      --from "atacante@phishing.com" --subject "Abre este archivo URGENTE"

  # Apuntando a otro host
  python manage.py test_webhook --file sample.pdf --to alias@dockershield.lat \
      --url https://app.dockershield.lat/webhook/inbound/

  # Firmar con secreto (cuando RESEND_WEBHOOK_SECRET está configurado en el server)
  python manage.py test_webhook --file eicar.com --to alias@dockershield.lat \
      --secret whsec_S6wC9il/FD8TiTQqVMBXZGJP3udtQxni
"""
import json
import os
import hmac
import hashlib
import base64
import mimetypes
import time

import requests

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Simula un POST de Resend Inbound al webhook con un archivo adjunto.'

    def add_arguments(self, parser):
        parser.add_argument('--file',    required=True, help='Ruta al archivo a adjuntar.')
        parser.add_argument('--to',      required=True, help='Alias destino (ej: algo@dockershield.lat).')
        parser.add_argument('--from',    dest='sender', default='attacker@evil.example.com',
                            help='Email del remitente simulado.')
        parser.add_argument('--subject', default='[TEST] Sandbox webhook test',
                            help='Asunto del correo.')
        parser.add_argument('--body',    default='Hola, te mando este archivo super legitimo. Abrelo ya.',
                            help='Cuerpo en texto plano.')
        parser.add_argument('--html',    default='',
                            help='Cuerpo HTML. Si está vacío se genera uno simple.')
        parser.add_argument('--url',     default='http://localhost:8000/webhook/inbound/',
                            help='URL del webhook (default: localhost).')
        parser.add_argument('--secret',  default='',
                            help='Firmar el payload con este secreto (RESEND_WEBHOOK_SECRET)')

    def handle(self, *args, **opts):
        filepath = opts['file']
        to_addr  = opts['to']
        sender   = opts['sender']
        subject  = opts['subject']
        body     = opts['body']
        html     = opts['html'] or f'<p>{body}</p>'
        url      = opts['url']
        secret   = opts['secret']

        # ── Validar archivo ────────────────────────────────────────────
        if not os.path.isfile(filepath):
            raise CommandError(f'Archivo no encontrado: {filepath}')

        size = os.path.getsize(filepath)
        if size > 25 * 1024 * 1024:
            raise CommandError(f'Archivo demasiado grande ({size // 1024} KB). Max 25 MB.')

        filename = os.path.basename(filepath)
        mime, _  = mimetypes.guess_type(filename)
        mime     = mime or 'application/octet-stream'

        with open(filepath, 'rb') as f:
            file_bytes = f.read()

        # ── Construir payload Resend Inbound (JSON) ────────────────────
        payload = {
            'subject': subject,
            'html':    html,
            'text':    body,
            'from':    sender,
            'to':      [to_addr],
            'cc':      [],
            'bcc':     [],
            'reply_to': None,
            'attachments': [
                {
                    'filename':     filename,
                    'content_type': mime,
                    'content':      base64.b64encode(file_bytes).decode('ascii'),
                }
            ],
            'dkim':       'pass',
            'spf':        'pass',
            'spam_score': 0.0,
            'sender_ip':  '127.0.0.1',
        }
        json_bytes = json.dumps(payload).encode('utf-8')

        headers = {'Content-Type': 'application/json'}

        if secret:
            ts = str(int(time.time()))
            sig = hmac.new(
                secret.encode('utf-8'),
                f"{ts}.".encode('utf-8') + json_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers['Resend-Signature'] = f"t={ts},v1={sig}"

        # ── Mostrar lo que vamos a enviar ──────────────────────────────
        self.stdout.write(self.style.HTTP_INFO('\n=== Simulando POST de Resend ==='))
        self.stdout.write(f'  URL:        {url}')
        self.stdout.write(f'  De:         {sender}')
        self.stdout.write(f'  Para:       {to_addr}')
        self.stdout.write(f'  Asunto:     {subject}')
        self.stdout.write(f'  Adjunto:    {filename} ({size} bytes, {mime})')
        self.stdout.write('')

        # ── Enviar ─────────────────────────────────────────────────────
        try:
            resp = requests.post(url, data=json_bytes, headers=headers, timeout=60)
        except requests.exceptions.ConnectionError as e:
            raise CommandError(
                f'No se pudo conectar a {url}. '
                f'¿Tienes el runserver corriendo?\n  Detalle: {e}'
            )
        except requests.exceptions.Timeout:
            raise CommandError(f'Timeout. El webhook tardó más de 60s en responder.')

        # ── Reportar resultado ─────────────────────────────────────────
        if 200 <= resp.status_code < 300:
            self.stdout.write(self.style.SUCCESS(f'[OK] Webhook respondió {resp.status_code}'))
            self.stdout.write(f'  Respuesta: {resp.text[:200]}')
            self.stdout.write('')
            self.stdout.write(self.style.HTTP_INFO('Donde mirar el resultado:'))
            self.stdout.write('  - Bandeja:  http://localhost:8000/bandeja/')
            self.stdout.write('  - Sandbox:  http://localhost:8000/sandbox/')
            self.stdout.write('  - Logs:     mira la terminal del runserver')
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                'Si el alias no existe en BD, el webhook responde 200 pero descarta el correo.'
            ))
        else:
            self.stdout.write(self.style.ERROR(
                f'[ERROR] Webhook respondió {resp.status_code}'
            ))
            self.stdout.write(f'  Respuesta: {resp.text[:500]}')
