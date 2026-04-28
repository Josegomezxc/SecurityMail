"""
Genera el PDF de la guía completa del proyecto SecureMail Shield.
Salida: guia_proyecto.pdf en la raíz del proyecto.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Preformatted, KeepTogether,
)


PURPLE       = HexColor('#6d4aff')
PURPLE_LIGHT = HexColor('#a78bfa')
DARK         = HexColor('#1a1828')
GRAY         = HexColor('#6b6884')
GRAY_LIGHT   = HexColor('#f4f4fb')
TEXT         = HexColor('#1a1830')
SUCCESS      = HexColor('#10b981')
WARNING      = HexColor('#f59e0b')
DANGER       = HexColor('#ef4444')
CODE_BG      = HexColor('#f8f8fd')
CODE_BORDER  = HexColor('#e0deec')


styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    'TitleX', parent=styles['Title'],
    fontSize=24, textColor=PURPLE, spaceAfter=8,
    alignment=TA_CENTER, fontName='Helvetica-Bold',
)
subtitle_style = ParagraphStyle(
    'SubtitleX', parent=styles['Normal'],
    fontSize=12, textColor=GRAY, alignment=TA_CENTER,
    spaceAfter=24, fontName='Helvetica',
)
h1_style = ParagraphStyle(
    'H1X', parent=styles['Heading1'],
    fontSize=18, textColor=PURPLE, spaceBefore=20, spaceAfter=10,
    fontName='Helvetica-Bold', borderPadding=(0, 0, 4, 0),
)
h2_style = ParagraphStyle(
    'H2X', parent=styles['Heading2'],
    fontSize=14, textColor=DARK, spaceBefore=14, spaceAfter=8,
    fontName='Helvetica-Bold',
)
h3_style = ParagraphStyle(
    'H3X', parent=styles['Heading3'],
    fontSize=11.5, textColor=PURPLE, spaceBefore=10, spaceAfter=6,
    fontName='Helvetica-Bold',
)
body_style = ParagraphStyle(
    'BodyX', parent=styles['BodyText'],
    fontSize=10.5, textColor=TEXT, leading=15,
    spaceAfter=8, alignment=TA_JUSTIFY, fontName='Helvetica',
)
body_compact = ParagraphStyle(
    'BodyCompact', parent=body_style,
    spaceAfter=4,
)
bullet_style = ParagraphStyle(
    'BulletX', parent=body_style,
    leftIndent=18, bulletIndent=4, spaceAfter=4,
)
code_style = ParagraphStyle(
    'CodeX', parent=styles['Code'],
    fontSize=9, textColor=DARK, fontName='Courier',
    leading=12, leftIndent=8, rightIndent=8,
    backColor=CODE_BG, borderColor=CODE_BORDER, borderWidth=1,
    borderPadding=8, spaceAfter=10, spaceBefore=4,
)
note_style = ParagraphStyle(
    'NoteX', parent=body_style,
    fontSize=9.5, textColor=GRAY,
    leftIndent=12, rightIndent=12, fontName='Helvetica-Oblique',
)


# ─────────────────────────────────────────────────────────────────────
#  Helpers para construir bloques
# ─────────────────────────────────────────────────────────────────────

def p(text, style=body_style):
    return Paragraph(text, style)


def code(text):
    return Preformatted(text, code_style)


def heading(text, level=1):
    return Paragraph(text, h1_style if level == 1 else h2_style if level == 2 else h3_style)


def make_table(rows_with_header, col_widths=None, header_bg=PURPLE):
    """rows_with_header[0] es el header. Resto son filas."""
    t = Table(rows_with_header, colWidths=col_widths, repeatRows=1)
    style = [
        ('BACKGROUND',     (0, 0), (-1, 0), header_bg),
        ('TEXTCOLOR',      (0, 0), (-1, 0), white),
        ('FONTNAME',       (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, 0), 10),
        ('ALIGN',          (0, 0), (-1, 0), 'LEFT'),
        ('BOTTOMPADDING',  (0, 0), (-1, 0), 8),
        ('TOPPADDING',     (0, 0), (-1, 0), 8),

        ('FONTNAME',       (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',       (0, 1), (-1, -1), 9),
        ('TEXTCOLOR',      (0, 1), (-1, -1), TEXT),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, GRAY_LIGHT]),
        ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING',    (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',   (0, 0), (-1, -1), 8),
        ('TOPPADDING',     (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING',  (0, 1), (-1, -1), 6),
        ('LINEBELOW',      (0, 0), (-1, 0), 1, PURPLE),
        ('GRID',           (0, 1), (-1, -1), 0.25, HexColor('#e0deec')),
    ]
    t.setStyle(TableStyle(style))
    return t


# ─────────────────────────────────────────────────────────────────────
#  Contenido del documento
# ─────────────────────────────────────────────────────────────────────

story = []

# Portada
story.append(Spacer(1, 1.5 * cm))
story.append(p('SecureMail Shield', title_style))
story.append(p('Guía completa del proyecto', subtitle_style))
story.append(p(
    '<i>Servicios externos, arquitectura, flujo del sistema, '
    'cómo arrancar el proyecto.</i>',
    ParagraphStyle('cover', parent=body_style, alignment=TA_CENTER, textColor=GRAY),
))
story.append(Spacer(1, 1 * cm))


# ──────── Sección 1 ────────
story.append(heading('1. Servicios externos que usa tu proyecto', 1))
story.append(p(
    'Tu proyecto se apoya en <b>5 servicios externos</b> porque cada uno hace algo '
    'que tu Django solo no puede:'
))

table_servicios = [
    ['Servicio', 'Para qué sirve', 'Cómo se usa'],
    ['PostgreSQL',
     'Guardar todos los datos (usuarios, alias, correos recibidos, reportes sandbox).',
     'Local en tu PC, puerto 5432.'],
    ['Docker Desktop',
     'Ejecutar el sandbox aislado donde se analiza el malware.',
     'App de escritorio que arrancas tú.'],
    ['ngrok',
     'Dar a tu Django local una URL pública en internet.',
     'CLI que tunela localhost:8000 → URL pública.'],
    ['SendGrid',
     'RECIBIR los correos que llegan a tus alias @dockershield.lat Y ENVIAR las alertas '
     'y reenvíos al correo real del usuario.',
     'Inbound Parse + Mail Send API. Un solo proveedor para entrada y salida.'],
    ['Gmail SMTP',
     'ENVIAR los correos de "recuperar contraseña".',
     'Django se conecta a smtp.gmail.com desde tu cuenta personal.'],
    ['Groq',
     'Analizar los reportes del sandbox con IA (Llama 3.3 70B).',
     'API HTTP que recibe un prompt y devuelve veredicto en lenguaje natural.'],
]
story.append(make_table(table_servicios, col_widths=[3.0 * cm, 6.5 * cm, 6.5 * cm]))
story.append(Spacer(1, 0.5 * cm))

story.append(heading('¿Por qué SendGrid hace todo el trabajo de correo?', 3))
story.append(p(
    'SendGrid ofrece dos productos que cubren las dos necesidades del proyecto:'
))
story.append(p(
    '• <b>Inbound Parse → recibir</b> correos entrantes en el dominio dockershield.lat. '
    'Los reenvía como POST multipart/form-data al webhook /webhook/inbound/.',
    bullet_style,
))
story.append(p(
    '• <b>Mail Send API → enviar</b> alertas de amenaza y reenvíos de correos seguros '
    'al Gmail real del usuario, autenticados con DKIM/SPF del dominio.',
    bullet_style,
))
story.append(p(
    'Antes el envío lo hacía Resend, pero unificamos en SendGrid porque su plan '
    'gratuito permite ambas funciones sin las limitaciones de Resend Free '
    '(que solo permite enviar al correo verificado del dueño de la cuenta).'
))

story.append(heading('¿Por qué Groq y no usas tu propia detección?', 3))
story.append(p(
    'Los analyzers (YARA, oletools, sandbox) detectan el <b>comportamiento técnico</b> '
    'del archivo (matches de reglas, hashes, patrones). Pero el reporte es <b>demasiado '
    'técnico</b> para un usuario normal — ve "YARA: Suspicious_Powershell_Loader" y no entiende.'
))
story.append(p(
    'Groq con Llama traduce todo eso a lenguaje natural: <i>"Este archivo es un descargador '
    'de PowerShell que intenta bajar otro malware. Recomendamos eliminar el alias y reportar '
    'al remitente."</i>'
))
story.append(p(
    'El veredicto técnico lo da YARA, la <b>explicación amigable</b> la da Groq.'
))

story.append(PageBreak())


# ──────── Sección 2 ────────
story.append(heading('2. Carpetas y archivos del proyecto', 1))

story.append(heading('app/services/', 2))
story.append(p(
    'Lógica de negocio separada de las vistas (patrón MVC). Cada archivo agrupa una '
    'responsabilidad:'
))
servicios = [
    ('alias_service.py',         'genera direcciones de alias (amazon_x7k2@dockershield.lat).'),
    ('auth_service.py',          'autenticación + rate limiting de login (bloquea fuerza bruta).'),
    ('email_service.py',         'wrapper para enviar correos por Gmail SMTP.'),
    ('password_reset_service.py','genera tokens de recuperación + envía el correo.'),
    ('profile_service.py',       'manejo del avatar del usuario.'),
    ('stats_service.py',         'cálculos del dashboard (correos hoy, esta semana, etc.).'),
]
for name, desc in servicios:
    story.append(p(f'• <b>{name}</b> → {desc}', bullet_style))
story.append(p(
    '<b>Por qué existe</b>: si pones todo en las views, el código se vuelve un infierno. '
    'Las views solo coordinan; los services hacen el trabajo pesado.',
    note_style,
))

story.append(heading('app/sandbox/', 2))
story.append(p('El motor de análisis de malware. Tres niveles:'))
story.append(p(
    '• <b>service.py</b> → recibe un archivo y dispara el contenedor Docker '
    '(ejecuta <font face="Courier">docker run --network none ...</font>).',
    bullet_style,
))
story.append(p(
    '• <b>run_analysis.py</b> → script que CORRE DENTRO del contenedor, decide qué '
    'analyzer usar según el tipo de archivo.',
    bullet_style,
))
story.append(p('• <b>analyzers/</b> → 9 archivos especializados:', bullet_style))
analyzers = [
    ('yara_analyzer.py',       'corre reglas YARA contra el binario.'),
    ('executable_analyzer.py', 'analiza .exe/.dll (PE headers, packers).'),
    ('office_analyzer.py',     'docs Office con macros VBA.'),
    ('pdf_analyzer.py',        'PDFs con JavaScript embebido.'),
    ('archive_analyzer.py',    'ZIP/RAR/7Z (extrae y analiza recursivo).'),
    ('script_analyzer.py',     'scripts (.bat, .ps1, .vbs, .sh) buscando patrones.'),
    ('dynamic_executor.py',    'ejecuta el script bajo strace para ver qué llama.'),
    ('url_analyzer.py',        'analiza URLs sospechosas.'),
    ('body_analyzer.py',       'cuerpo del correo (phishing, brand impersonation).'),
]
for name, desc in analyzers:
    story.append(p(
        f'      <b>{name}</b> → {desc}',
        ParagraphStyle('subB', parent=bullet_style, leftIndent=36, fontSize=9.5),
    ))

story.append(heading('Dockerfile.sandbox', 2))
story.append(p(
    'La "receta" de cómo construir el contenedor del sandbox. Tiene Python 3.12 + las '
    'librerías para analizar (yara-python, oletools, pefile, etc.). Cada vez que cambias '
    'algo del sandbox, lo rebuilds con:'
))
story.append(code('docker build -f Dockerfile.sandbox -t email_seguro_sandbox .'))

story.append(heading('docker/, docker-compose.yml y nginx.conf', 2))
story.append(p(
    'Configuración para deployar TODO con docker-compose (Django + Postgres + sandbox + '
    'nginx) en un servidor de producción. <b>No los usas en desarrollo</b> — son para '
    'cuando un día montes esto en un VPS y quieras tener nginx como reverse proxy delante '
    'de Django. Por ahora puedes ignorarlos.'
))

story.append(heading('test_samples/', 2))
story.append(p('Carpeta para tus muestras de prueba del sandbox:'))
test_samples = [
    ('eicar.txt',          'archivo de prueba estándar de antivirus.'),
    ('suspicious.bat',     'script con patrones maliciosos (no es real malware).'),
    ('examen_final.pdf',   'un PDF para probar.'),
    ('run_tests.py',       'suite de tests automatizados del sandbox.'),
]
for name, desc in test_samples:
    story.append(p(f'• <b>{name}</b> → {desc}', bullet_style))
story.append(p(
    'Esta carpeta está en la <b>exclusión de Defender</b> que añadimos antes, para que '
    'no borre los samples.',
    note_style,
))

story.append(heading('.env', 2))
story.append(p(
    'TODOS los secretos: SECRET_KEY de Django, password de Postgres, API keys de '
    'SendGrid/Groq, contraseña de aplicación de Gmail, etc. <b>Nunca subir a git</b> '
    '(el .gitignore ya lo excluye).'
))

story.append(heading('media/', 2))
story.append(p(
    'Donde Django guarda los archivos subidos (avatares de usuarios + adjuntos de '
    'correos recibidos). También en exclusión de Defender.'
))

story.append(PageBreak())


# ──────── Sección 3 ────────
story.append(heading('3. Docker Desktop: cómo saberlo y por qué', 1))

story.append(heading('Por qué hay que tenerlo abierto', 3))
story.append(p(
    'Tu sandbox <b>NO</b> es código Python que corre en Django. Es un <b>proceso aparte</b> '
    'dentro de un contenedor Linux completamente aislado. Cuando llega un correo con '
    'adjunto, tu webhook ejecuta literalmente esto:'
))
story.append(code(
    'docker run --rm --network none --read-only --memory 256m \\\n'
    '  -v ARCHIVO:/tmp/sample:ro email_seguro_sandbox \\\n'
    '  python /app/sandbox/run_analysis.py /tmp/sample'
))
story.append(p(
    'Si Docker Desktop está cerrado, el comando <font face="Courier">docker</font> no '
    'funciona → el sandbox falla → el correo se guarda pero sin análisis.'
))

story.append(heading('Cómo saber si está corriendo', 3))
story.append(p(
    '<b>Visualmente</b>: el icono de la ballena de Docker en la barra de tareas (esquina '
    'inferior derecha). Si la ballena está blanca/quieta = corriendo. Si está ausente o '
    '"loading" = apagado/iniciando.'
))
story.append(p('<b>En terminal</b>:'))
story.append(code('docker info 2>&1 | head -5'))
story.append(p(
    'Si responde con info del servidor → activo. Si dice <font face="Courier">Cannot '
    'connect to the Docker daemon</font> → cerrado.'
))

story.append(heading('Cómo saber si tu imagen del sandbox existe', 3))
story.append(code('docker images email_seguro_sandbox'))
story.append(p('Si aparece la línea, tienes la imagen lista. Si no aparece, hay que rebuildar:'))
story.append(code('docker build -f Dockerfile.sandbox -t email_seguro_sandbox .'))


# ──────── Sección 4 ────────
story.append(heading('4. ¿Por qué ngrok antes que runserver (o después)?', 1))
story.append(p('En realidad <b>el orden no importa</b>, pero es más cómodo así:'))
story.append(p(
    '<b>1.</b> Docker Desktop primero (tarda 30s en arrancar, mejor adelantarlo).',
    bullet_style,
))
story.append(p('<b>2.</b> Django runserver segundo (rápido).', bullet_style))
story.append(p(
    '<b>3.</b> ngrok tercero — y verás en su output que se conecta a localhost:8000. '
    'Si ngrok arranca antes que Django, también funciona, pero hasta que Django no esté '
    'arriba ngrok te dará error 502 si alguien hace request.',
    bullet_style,
))
story.append(p(
    '<b>Lo importante</b>: si reinicias Django, NO necesitas reiniciar ngrok. ngrok solo '
    'tunela; no le importa si Django se cae y vuelve. Pero si reinicias ngrok, sí debes '
    'verificar que la URL siga siendo la misma (con '
    '<font face="Courier">--url=twilight-baking-viewing.ngrok-free.dev</font> siempre será '
    'la misma).'
))

story.append(PageBreak())


# ──────── Sección 5 ────────
story.append(heading('5. El flujo completo paso a paso', 1))
story.append(p('Con todo lo de arriba, este es el viaje de un correo:'))
flujo = """[1] Spammer manda correo: "spam@phisher.com" envia a "amazon_x7k2@dockershield.lat"
       |
[2] DNS de Internet busca el MX de dockershield.lat -> apunta a SendGrid
       |
[3] SendGrid recibe el correo SMTP, lo parsea, hace POST con multipart/form-data
       |
[4] El POST viaja a https://twilight-baking-viewing.ngrok-free.dev/webhook/inbound/
       |
[5] ngrok recibe ese POST publico y lo tunela a tu localhost:8000
       |
[6] Django webhook (app/webhook.py) recibe el request, parsea campos
       |
[7] Busca el alias en Postgres -> encuentra al usuario real (jgomezm10@unemi.edu.ec)
       |
[8] Crea EmailMessage en BD -> aparece en /bandeja/ casi inmediato
       |
[9] Para cada adjunto:
    Django llama a docker run -> arranca contenedor email_seguro_sandbox
    El contenedor corre run_analysis.py -> ejecuta YARA + analyzers segun tipo
    Devuelve JSON con score, evidencia, IOCs
       |
[10] Combina todos los reportes (cuerpo + adjuntos + URLs)
       |
[11] Si score >= 61: Django llama a SendGrid Mail Send API -> manda alerta HTML
       SendGrid usa tu DKIM/SPF de dockershield.lat -> llega a la inbox real
       |
[12] Cuando el usuario abre el reporte en /sandbox/reporte/<id>/:
       El frontend hace POST a /ai-analysis/ con todos los datos del reporte
       Django llama a Groq API -> Llama 3.3 traduce el reporte a espanol sencillo
       Aparece el veredicto IA en la pagina"""
story.append(code(flujo))


# ──────── Sección 6 ────────
story.append(heading('6. Checklist rápido para arrancar', 1))
story.append(code(
    '# 1. Abrir Docker Desktop (icono barra de tareas, esperar ballena estable)\n'
    '\n'
    '# 2. Activar venv\n'
    'ent_email\\Scripts\\activate\n'
    '\n'
    '# 3. Terminal A: Django\n'
    'python manage.py runserver\n'
    '\n'
    '# 4. Terminal B: ngrok con dominio fijo\n'
    'ngrok http --url=twilight-baking-viewing.ngrok-free.dev 8000\n'
    '\n'
    '# 5. (Opcional) Verificar que todo esta vivo:\n'
    'docker info | head -3\n'
    'curl http://localhost:8000/                                  # Django\n'
    'curl https://twilight-baking-viewing.ngrok-free.dev/         # ngrok -> Django'
))
story.append(Spacer(1, 0.5 * cm))
story.append(p(
    'Si los 4 puntos están OK, tu proyecto recibe correos reales y los analiza al instante.',
    ParagraphStyle('final', parent=body_style, alignment=TA_CENTER, textColor=PURPLE,
                   fontName='Helvetica-Bold'),
))


# ─────────────────────────────────────────────────────────────────────
#  Pie de página y construcción final
# ─────────────────────────────────────────────────────────────────────

def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(GRAY)
    canvas.drawRightString(
        A4[0] - 1.5 * cm, 1 * cm,
        f"SecureMail Shield — Guía del proyecto · página {doc.page}",
    )
    canvas.restoreState()


doc = SimpleDocTemplate(
    'guia_proyecto.pdf',
    pagesize=A4,
    leftMargin=2 * cm, rightMargin=2 * cm,
    topMargin=2 * cm, bottomMargin=2 * cm,
    title='SecureMail Shield - Guía del proyecto',
    author='SecureMail Shield',
)
doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
print('OK: guia_proyecto.pdf generado')

import os
print('Tamaño:', os.path.getsize('guia_proyecto.pdf'), 'bytes')
