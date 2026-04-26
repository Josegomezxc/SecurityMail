"""
Simula un POST de SendGrid Inbound Parse al webhook local.

Útil para probar el sandbox SIN depender de Gmail/SendGrid filtrando
los adjuntos en SMTP. Bypaseas todos los filtros y testeas
end-to-end con cualquier archivo.

Ejemplos:
  # Test mínimo con EICAR
  python manage.py test_webhook --file eicar.com --to alias@dockershield.lat

  # Test con remitente y asunto custom
  python manage.py test_webhook --file evil.exe --to alias@dockershield.lat \
      --from "atacante@phishing.com" --subject "Abre este archivo URGENTE"

  # Apuntando a otro host (ej. ngrok público)
  python manage.py test_webhook --file sample.pdf --to alias@dockershield.lat \
      --url https://twilight-baking-viewing.ngrok-free.dev/webhook/inbound/
"""
import json
import os
import mimetypes

import requests

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Simula un POST de SendGrid al webhook con un archivo adjunto (para testear el sandbox).'

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

    def handle(self, *args, **opts):
        filepath = opts['file']
        to_addr  = opts['to']
        sender   = opts['sender']
        subject  = opts['subject']
        body     = opts['body']
        html     = opts['html'] or f'<p>{body}</p>'
        url      = opts['url']

        # ── Validar archivo ────────────────────────────────────────────
        if not os.path.isfile(filepath):
            raise CommandError(f'Archivo no encontrado: {filepath}')

        size = os.path.getsize(filepath)
        if size > 25 * 1024 * 1024:
            raise CommandError(f'Archivo demasiado grande ({size // 1024} KB). Max 25 MB.')

        filename = os.path.basename(filepath)
        mime, _  = mimetypes.guess_type(filename)
        mime     = mime or 'application/octet-stream'

        # ── Construir el payload SendGrid ──────────────────────────────
        # Formato Inbound Parse: multipart/form-data con campos planos +
        # attachment1, attachment2... como files. attachment-info es JSON.
        attachment_info = {
            'attachment1': {
                'filename':     filename,
                'name':         filename,
                'type':         mime,
                'content-id':   '',
            }
        }

        with open(filepath, 'rb') as f:
            file_bytes = f.read()

        fields = {
            'to':              to_addr,
            'from':            sender,
            'subject':         subject,
            'text':            body,
            'html':            html,
            'envelope':        json.dumps({'to': [to_addr], 'from': sender}),
            'charsets':        json.dumps({'to': 'UTF-8', 'from': 'UTF-8',
                                           'subject': 'UTF-8', 'text': 'UTF-8'}),
            'attachments':     '1',
            'attachment-info': json.dumps(attachment_info),
            'SPF':             'pass',
            'spam_score':      '0.0',
            'sender_ip':       '127.0.0.1',
            'dkim':            json.dumps({'@example.com': 'pass'}),
        }

        files = {
            'attachment1': (filename, file_bytes, mime),
        }

        # ── Mostrar lo que vamos a enviar ──────────────────────────────
        self.stdout.write(self.style.HTTP_INFO('\n=== Simulando POST de SendGrid ==='))
        self.stdout.write(f'  URL:        {url}')
        self.stdout.write(f'  De:         {sender}')
        self.stdout.write(f'  Para:       {to_addr}')
        self.stdout.write(f'  Asunto:     {subject}')
        self.stdout.write(f'  Adjunto:    {filename} ({size} bytes, {mime})')
        self.stdout.write('')

        # ── Enviar ─────────────────────────────────────────────────────
        try:
            resp = requests.post(url, data=fields, files=files, timeout=60)
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
