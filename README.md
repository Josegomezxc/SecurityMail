# DockerShield

Sistema de correos electrónicos temporales (alias desechables) con análisis sandbox de amenazas en tiempo real. Los alias protegen tu correo real de spam, phishing y malware. Cada adjunto se analiza automáticamente en un contenedor Docker aislado.

---

## Stack

| Capa | Tecnología |
|------|-----------|
| Backend | Django 5.2 + PostgreSQL |
| Frontend | HTML templates + CSS vanilla + JS vanilla |
| Emails | Resend API (envío) + Resend Inbound (recepción) |
| Sandbox | Docker (`--network none --read-only`), YARA, oletools, PEfile, strace |
| IA | Groq (Llama) para generación de alias y veredictos de amenazas |
| Auth | django.contrib.auth + single-session + rate limiting |

---

## Primeros pasos

### Requisitos

- Python 3.12+
- PostgreSQL
- Docker (para el sandbox)
- Cuenta en [Resend](https://resend.com) (API key + dominio verificado)
- (Opcional) Cuenta en [Groq](https://groq.com) para generación de alias con IA

### Configuración `.env`

```env
DEBUG=True
SECRET_KEY=tu-secret-key
ALLOWED_HOSTS=localhost,127.0.0.1

MAIL_DOMAIN=tu-dominio.com

DB_NAME=db_email_seguro
DB_USER=postgres
DB_PASSWORD=tu-password
DB_HOST=localhost
DB_PORT=5432

GROQ_API_KEY=gsk_...                          # Opcional: para alias con IA
RESEND_API_KEY=re_...                          # Obligatorio: envío de correos

SITE_URL=http://127.0.0.1:8000                 # URL pública del sitio
```

### Instalación

```powershell
# 1. Clonar e instalar dependencias
pip install -r requirements.txt

# 2. Base de datos
python manage.py migrate

# 3. Construir imagen del sandbox
docker build -t email_seguro_sandbox -f Dockerfile.sandbox .

# 4. Crear admin (opcional)
python manage.py createsuperuser

# 5. Ejecutar
python manage.py runserver
```

### Docker Compose

```powershell
docker compose up --build
```

### Recibir correos (webhook)

1. En Resend → **Inbound**, configura tu dominio para que reenvíe los correos a:
   - `https://tudominio.com/webhook/inbound/`
   - En desarrollo: usa ngrok para exponer tu localhost
2. Configura `SITE_URL` en `.env` con la URL de ngrok
3. Cualquier correo enviado a `*@tudominio.com` llega a la bandeja del alias correspondiente

---

## Módulos

### accounts
Autenticación, registro con verificación por código, perfil, cambio de contraseña, eliminación de cuenta (hard-delete con confirmación por email), recuperación de cuenta bloqueada, rate limiting por IP (5 intentos → bloqueo 10 min).

### aliases
Alias desechables tipo `tigre-plateado_x7k2m@dominio.com`. Cupo limitado por usuario (5 por defecto). Solicitud de cupo extra al admin. Generación con IA (Groq Llama) o fallback a banco local en inglés.

### mail
Dashboard, bandeja de entrada, enviados, borradores (autosave), papelera (30 días de retención). Vista HTML segura de correos (links/imágenes neutralizados). Autenticación SPF/DKIM/DMARC.

### sandbox
Análisis automático de adjuntos vía Docker aislado:

| Tipo | Analizador |
|------|-----------|
| `.exe`, `.dll`, `.scr` | PE (APIs sospechosas, empaquetadores, entropía, firmas) |
| `.docx`, `.xlsm`, etc. | Office (macros VBA, auto-ejecución, Shell/PS) |
| `.pdf` | PDF (JS embebido, acciones automáticas, XFA) |
| `.zip`, `.rar`, `.7z` | Archive (extracción recursiva, zip-bomb, password) |
| `.sh`, `.ps1`, `.bat`, `.vbs`, `.js`, `.hta`, `.lnk` | Script (decenas de patrones maliciosos) |
| Cuerpo del correo | URLs, link spoofing, phishing, suplantación |
| URLs | Acortadores, IDN homográficos, TLDs peligrosos |
| — | YARA (13 reglas: loaders, base64, reverse shells, ransomware) |

Ejecución dinámica real con `strace` para scripts `.sh`/`.py`: captura conexiones de red, procesos hijo, fork bombs, accesos a `/etc/shadow`.

### notifications
Campana de notificaciones con toasts globales. Tipos: alertas de amenaza, solicitudes de reenvío, notificaciones de sistema. Admins reciben notificación cuando un usuario pide cupo de alias.

### core (admin panel)
Panel global con estadísticas del sistema, gestión de usuarios (promover/degradar admin), ajuste de cupo de alias, alias ilimitados, solicitudes de cupo (aprobar/rechazar), solicitudes de recuperación de cuenta, tabla de amenazas globales, tabla de alias globales. Búsqueda en tiempo real en todas las tablas.

---

---

## Funcionalidades clave

### Alias con IA
Groq (Llama 3.1 8B) genera etiquetas en español (`TigrePlateado`, `LoboCosmico`). Fallback automático a banco local en inglés si la API falla. Cada alias tiene un sufijo aleatorio de 6 caracteres.

### Sandbox aislado
Cada adjunto se analiza en un contenedor Docker sin red (`--network none`), con sistema de archivos de solo lectura, límite de 256MB RAM y 1 CPU, timeout de 25s. Ejecución dinámica real de scripts con `strace`.

### Seguridad
- Rate limiting: 5 intentos de login fallidos → bloqueo 10 min por IP
- Single-session: un usuario solo puede tener una sesión activa
- Hard-delete: eliminación de cuenta borra todos los datos (alias, correos, archivos)
- Contraseñas: validación estricta (mayúscula, minúscula, número, símbolo, sin patrones de teclado, sin contraseñas comunes)
- Correos desechables bloqueados en registro (18 dominios)
- SPF/DKIM/DMARC verificados en cada correo entrante
- HTML de correos neutralizado (sin links ni imágenes activas)

### UI/UX
- Toast notifications globales
- Sidebar con scroll persistente entre páginas
- Botón "Nuevo correo" global en sidebar

---

## Estructura del proyecto

```
config/
  settings/
    base.py          Configuración común
    development.py   Desarrollo
    production.py    Producción
    testing.py       Tests
  urls.py            Router raíz
  wsgi.py / asgi.py

apps/
  accounts/          Autenticación, perfil, usuarios
  aliases/           Alias desechables + cupo + solicitudes
  core/              Dashboard admin, utilidades
  mail/              Bandeja, enviados, borradores, papelera, webhook
  notifications/     Campana de notificaciones + toasts
  sandbox/           Análisis sandbox (YARA, estático, dinámico)

templates/           Templates HTML por módulo
static/              CSS/JS por módulo

Dockerfile           Imagen Django
Dockerfile.sandbox   Imagen del sandbox
docker-compose.yml   Orquestación
requirements.txt     Dependencias Python
```

---

## Licencia

Uso académico — Proyecto de titulación.
