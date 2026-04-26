# 📋 Cambios realizados en SecureMail Shield

Resumen de **todo lo que se añadió o mejoró** en el proyecto, contado de manera sencilla.

---

## 📑 Índice

1. [🎨 Mejoras visuales de pantallas](#1--mejoras-visuales-de-pantallas)
2. [🔬 Sandbox Docker mucho más potente](#2--sandbox-docker-mucho-más-potente)
3. [📊 Reporte de análisis rediseñado](#3--reporte-de-análisis-rediseñado)
4. [⚡ Actualización automática sin recargar](#4--actualización-automática-sin-recargar)
5. [📎 Soporte para varios adjuntos en un correo](#5--soporte-para-varios-adjuntos-en-un-correo)
6. [👥 Sistema de roles (usuario / administrador)](#6--sistema-de-roles-usuario--administrador)
7. [🛡️ Validaciones profesionales en formularios](#7-️-validaciones-profesionales-en-formularios)
8. [✏️ Edición de perfil mejorada](#8-️-edición-de-perfil-mejorada)
9. [✔️ Checkbox "Aceptar todo" en el registro](#9-️-checkbox-aceptar-todo-en-el-registro)
10. [💬 Mensajes de error profesionales](#10--mensajes-de-error-profesionales)
11. [📬 Correos se marcan como leídos](#11--correos-se-marcan-como-leídos)
12. [🧪 Kit de pruebas automáticas](#12--kit-de-pruebas-automáticas)
13. [🐛 Bugs que arreglamos por el camino](#13--bugs-que-arreglamos-por-el-camino)
14. [📁 Archivos creados y modificados](#14--archivos-creados-y-modificados)
15. [🚀 Cómo poner todo en marcha](#15--cómo-poner-todo-en-marcha)
16. [🏗️ Reestructura MVC profesional](#16-️-reestructura-mvc-profesional-arquitectura-limpia)

---

## 1. 🎨 Mejoras visuales de pantallas

Se rediseñaron varias pantallas para que se vean más profesionales, intuitivas y modernas.

### 🔑 Login y Registro
- **Layout de 2 columnas**: panel izquierdo con información de beneficios + formulario a la derecha.
- **Iconos dentro de los campos** (sobre para email, candado para contraseña) que cambian de color al seleccionar el campo.
- **Botón para mostrar/ocultar la contraseña** (el ojito que se tacha cuando ocultas).
- **Aviso de Bloq Mayús** mientras escribes la contraseña.
- **Medidor de fortaleza de contraseña** (barra que cambia de rojo a verde).
- **Checklist de requisitos** (mayúscula, número, símbolo...) que se van marcando en verde.
- **Indicador en vivo** de si las dos contraseñas coinciden.
- **Spinner** al enviar el formulario para que sepas que está procesando.

### 📝 Recuperar contraseña
- Mismo diseño moderno de 2 columnas que login/registro.
- Panel con 3 pasos explicativos: "Indícanos tu correo → Recibe enlace → Crea nueva contraseña".

### 📄 Términos y Privacidad
- **Título grande con icono flotante** (animación sutil).
- **Resumen TL;DR** al principio con los 4 puntos clave (para que no tengas que leer todo).
- **Barra de progreso de lectura** en la parte superior.
- **Índice lateral** (TOC) que se queda pegado y resalta la sección actual mientras haces scroll.
- **Cada sección con un icono de color diferente** (morado, naranja, verde, rojo, azul).
- **Cajas de aviso con colores** (info azul, advertencia naranja, éxito verde).
- **"Minutos de lectura"** en el hero (ej: "5 min de lectura").
- **Animación fade-in** cuando cada sección entra en la pantalla.
- Privacidad tiene una **tabla de datos** con badges "Nunca" en verde.

### 🏠 Dashboard
- **Tendencias 24 horas** en las estadísticas (flecha verde/roja con "+3 vs ayer").
- **Tasa de bloqueo** en porcentaje.
- **Sección "Amenazas recientes"** en cards rojas destacadas que aparece solo cuando hay amenazas.

### 📥 Bandeja de entrada
- **Correos agrupados por fecha**: "Hoy", "Ayer", "Esta semana", "Anteriores".
- **Botón "reporte"** que aparece al pasar el mouse sobre un correo con análisis.
- **Animación de entrada** cuando llegan correos nuevos.
- **Chip "en vivo"** en la esquina inferior que parpadea mientras está buscando correos nuevos.

### 🎭 Alias
- **Estadísticas globales** en la cabecera: cuántos activos, cuántos correos, cuántas amenazas bloqueadas.
- **Barra de búsqueda** para encontrar alias por etiqueta o dirección.
- **Filtros**: Todos / Activos / Destruidos.
- **Mini-estadísticas en cada alias**: chip morado con "5 correos", chip rojo con "2 amenazas" si aplica.

### 🛡️ Lista de Sandbox
- **Barra de búsqueda + filtros por severidad**: Todos / Malware / Alto riesgo / Sospechoso / Seguro.
- **Cada análisis muestra**: categoría (Ejecutable, Office, PDF...), número de indicadores detectados, YARA matches, URLs encontradas.
- **Badge rojo "SPOOF"** si la extensión del archivo no coincide con su tipo real.

---

## 2. 🔬 Sandbox Docker mucho más potente

El sandbox es la parte que analiza los archivos adjuntos sospechosos en un contenedor aislado. **Antes solo detectaba cosas muy obvias** (como ejecutables por su extensión). **Ahora detecta muchísimo más**.

### Qué significa cada tipo de análisis

- **Análisis estático**: revisa el archivo "por fuera" (lee su contenido sin ejecutarlo).
- **Análisis dinámico**: **ejecuta el archivo de verdad** dentro del contenedor aislado y observa qué intenta hacer.

### Lo que ahora puede analizar

| Tipo de archivo | Qué detecta |
|---|---|
| **Ejecutables Windows** (`.exe`, `.dll`, `.scr`) | APIs sospechosas (inyección de procesos, keyloggers), empaquetadores tipo UPX/Themida, entropía anormal (señal de cifrado/empaquetado), si está firmado digitalmente |
| **Ejecutables Linux** (ELF) | Cadenas peligrosas como `/etc/shadow`, `reverse_shell`, `/dev/tcp` |
| **Documentos Office** (`.docx`, `.xlsm`, etc.) | **Macros VBA maliciosas**: auto-ejecución al abrir, llamadas a Shell/PowerShell/cmd, descargas de archivos, URLs sospechosas dentro de las macros |
| **PDF** | JavaScript embebido, acciones automáticas (`/OpenAction`, `/Launch`), formularios XFA (vector clásico de exploits), incluso los busca dentro de streams comprimidos |
| **Archivos ZIP/RAR/7z** | **Los extrae** en carpeta temporal y analiza cada archivo de dentro. Detecta "zip-bombs" (archivos que al descomprimir se expanden enormemente) y archivos protegidos con contraseña (técnica común para evadir antivirus) |
| **Scripts** (`.sh`, `.ps1`, `.bat`, `.vbs`, `.js`, `.hta`, `.lnk`) | Decenas de patrones maliciosos por cada tipo: PowerShell con `IEX(DownloadString())`, reverse shells con `nc -e`, LOLBAS (abuso de `certutil`, `bitsadmin`, `mshta`), persistencia en registro, desactivación de Windows Defender, etc. |

### 🎯 Reglas YARA (antivirus tipo "firma")

Añadí **13 reglas YARA** que son como "firmas" de familias de malware. Detectan:
- Loaders de PowerShell (patrón `IEX + DownloadString`).
- Comandos codificados en Base64 (`-EncodedCommand`).
- Reverse shells (bash `/dev/tcp` y netcat).
- Macros de Office maliciosas.
- Técnicas LOLBAS.
- Intentos de desactivar Windows Defender.
- Persistencia en registro o tareas programadas.
- Ejecutables Windows embebidos en base64 (cabecera `TVqQ`).
- Indicadores de ransomware.
- PDFs con JavaScript + acciones automáticas.
- Formularios HTML que roban credenciales.

### 🏃 Ejecución dinámica REAL (¡esto es nuevo!)

Para scripts compatibles con Linux (`.sh`, `.bash`, `.py`), el sandbox ahora **realmente los ejecuta** dentro del contenedor aislado y usa **`strace`** para capturar exactamente qué hace:

- **Conexiones de red** que intenta abrir → registra IP + puerto, aunque la red está bloqueada.
- **Procesos hijos** que lanza (ej: llamadas a `nc`, `curl`, `wget`, `ssh`).
- **Fork bombs**: si crea más de 15 procesos, lo marca como sospechoso (score 90).
- **Accesos a archivos sensibles**: `/etc/shadow`, `/etc/passwd`, `~/.ssh/`, `crontab`.
- **Eliminación de archivos** (`unlink`).
- **Cambios de permisos peligrosos** (`chmod 777`).

**Importante**: los ejecutables `.exe` de Windows **no se pueden ejecutar en Linux** (imposible sin una máquina virtual completa). Eso explica por qué solo se hace análisis estático profundo de los `.exe`, como hace Gmail o Outlook.

### 🔒 Garantías de seguridad del sandbox

El contenedor Docker está configurado con:
- `--network none` → **sin internet** (el malware no puede descargar más código ni contactar servidores C&C).
- `--read-only` → **no puede escribir en el disco del servidor**, solo en `/tmp` que se borra al terminar.
- `--memory 256m` + `--cpus 1.0` → límites de recursos.
- Usuario sin privilegios (no es root).
- Timeout de 25 segundos por archivo.

### 📧 Análisis del cuerpo del correo

Ahora también analiza **el texto y HTML del correo**, no solo los adjuntos:
- **URLs sospechosas**: acortadores (bit.ly), IDN homográficos (caracteres no-ASCII), TLDs peligrosos (.tk, .click, .zip), URLs con IP en vez de dominio.
- **Link spoofing**: cuando un enlace dice "paypal.com" pero apunta a otro sitio distinto.
- **Formularios de credenciales** dentro del correo (phishing clásico).
- **Frases típicas de phishing**: "verifica tu cuenta urgente", "cuenta suspendida", "haz clic aquí".
- **Suplantación del remitente**: si el "De:" menciona "PayPal" pero el dominio real es otro.
- **Reply-To distinto al From** (truco clásico de phishing).

---

## 3. 📊 Reporte de análisis rediseñado

La página que muestra el resultado del sandbox (`/sandbox/reporte/<id>/`) ahora tiene mucha más información.

### Lo que verás ahora
1. **Banner grande** arriba (verde si es seguro, rojo si es amenaza).
2. **Anillo circular con el score** (0-100).
3. **Identificación del archivo**: MIME real, extensión, tamaño, hashes SHA-256 y MD5, categoría.
4. **Lista de evidencia** — la sección estrella. Cada indicador con:
   - Pill de severidad (CRÍTICO / ALTO / MEDIO / BAJO / INFO) con color.
   - Detalle legible ("PowerShell IEX — ejecución dinámica").
   - Tag técnico (`script_pattern`, `yara_loader`, etc.).
5. **Reglas YARA coincidentes** si las hay.
6. **IOCs (Indicadores de Compromiso)**: URLs, IPs, dominios con botón "copiar".
7. **Análisis del cuerpo del correo** (solo si tiene score).
8. **Analizadores ejecutados** como chips con check verde.
9. **Si el correo tiene varios adjuntos**, aparece una lista con el score individual de cada uno.
10. **Veredicto IA** de Groq al final con explicación y recomendación.

---

## 4. ⚡ Actualización automática sin recargar

**Antes**: tenías que recargar la página para ver correos nuevos.
**Ahora**: todo se actualiza solo cada 15 segundos.

### Bandeja de entrada
- **Chip "en vivo"** en la esquina inferior que parpadea al consultar.
- Si llegan correos nuevos, aparece un **banner morado** arriba: *"3 correos nuevos · click para ver"*.
- Al hacer clic, los correos se insertan al inicio con animación, **dentro del grupo "Hoy"**.
- Si abres otra pestaña, el polling se pausa para ahorrar datos.
- Puedes pausar manualmente haciendo clic en el chip.

### Dashboard
- Mismo sistema: chip "en vivo" + banner de novedades.
- Los **números de las tarjetas** se animan cuando cambian (tipo "bump" + contador ascendente).

### Endpoints creados
- `/bandeja/nuevos/?after=<id>` — devuelve los correos con ID mayor al último visto.
- `/dashboard/live/` — devuelve las estadísticas actualizadas.

---

## 5. 📎 Soporte para varios adjuntos en un correo

**Antes**: si un correo traía 2 o 3 archivos, solo se analizaba el primero.
**Ahora**: el sistema procesa **todos** los adjuntos (hasta 15 por correo).

- Cada adjunto se analiza **individualmente** en el sandbox.
- Se guarda un reporte por cada uno en un nuevo campo `attachments_reports`.
- El veredicto final toma el **peor score** de todos.
- Todas las URLs encontradas (en el cuerpo + en todos los adjuntos) se juntan y se analizan juntas.
- En el reporte aparece una **lista de todos los adjuntos con su score individual**.

---

## 6. 👥 Sistema de roles (usuario / administrador)

Se agregó diferenciación entre usuarios normales y administradores.

### Cómo funciona
- Los usuarios que se registran desde la web son **usuarios normales**.
- Un administrador se crea con el comando de Django: `python manage.py createsuperuser`.
- El rol se guarda en el campo `is_staff` que ya viene en Django (no requiere migración).

### Qué puede hacer cada rol

| Acción | Usuario | Administrador |
|---|---|---|
| Ver sus propios correos | ✅ | ✅ |
| Crear/gestionar sus alias | ✅ | ✅ |
| Ver panel global del sistema | ❌ | ✅ |
| Ver todos los usuarios | ❌ | ✅ |
| Ver detalle de cualquier usuario | ❌ | ✅ |
| Promover/degradar a otros | ❌ | ✅ |

### Panel de administración (solo admin)

Accesible desde la sidebar cuando eres admin:

1. **Panel global** (`/admin-panel/`): estadísticas de todo el sistema.
   - Total de usuarios, alias, correos, amenazas bloqueadas.
   - Correos nuevos en 24h y 7 días.
   - Top 5 usuarios más activos.
   - Amenazas recientes del sistema entero.

2. **Usuarios** (`/admin-panel/usuarios/`): tabla con todos los usuarios.
   - Búsqueda por correo o nombre.
   - Muestra cuántos alias, correos y amenazas tiene cada uno.
   - Botones para **promover** (usuario → admin) o **degradar** (admin → usuario).

3. **Detalle de usuario**: aliases de ese usuario, últimos correos, mini-stats.

### Detalles visuales
- **Badge "ADMIN"** naranja junto al nombre en la sidebar.
- **Sección "ADMINISTRACIÓN"** en la sidebar solo aparece si eres admin.
- Si un usuario normal intenta acceder a una URL de admin → **error 403** con mensaje claro.

---

## 7. 🛡️ Validaciones profesionales en formularios

Antes los formularios aceptaban casi cualquier cosa. Ahora todo se valida de forma estricta.

### Módulo centralizado `app/validators.py`

Archivo nuevo que contiene todas las reglas de validación reutilizables. Separa la lógica para que el backend y el frontend las compartan.

### 📛 Nombre de usuario (antes "nombre completo")

**Antes**: podías escribir "j o s e" o "jos      e" y se aceptaba.
**Ahora**:
- Se llama **"Nombre de usuario"** (1 sola palabra).
- **Se eliminan todos los espacios** mientras escribes (si pegas `"jos e"` queda `"jose"`).
- Longitud entre 2 y 30 caracteres.
- Solo letras (con acentos), números, `_` y `-`.
- Debe empezar con letra.
- Nombres reservados bloqueados: `admin`, `root`, `api`, `www`, `support`, `securemail`, etc.
- No puede ser solo números.

### 📧 Email

- **Trim + minúsculas** automáticas (no importa cómo lo escribas).
- Formato RFC válido (con regex estricta).
- Longitud máxima 254 caracteres.
- Sin puntos dobles, sin empezar/terminar con punto.
- **Bloquea correos desechables**: tempmail, mailinator, 10minutemail, guerrillamail, etc. (18 dominios en total).

### 🔑 Contraseña

Reglas:
- Mínimo 8 caracteres, máximo 128.
- Debe tener mayúscula, minúscula, número y símbolo.
- **No puede ser una contraseña común** (password, qwerty123, admin123...).
- **No puede contener secuencias de teclado**: qwerty, 123456, asdfgh, zxcvbn.
- **No puede repetir el mismo carácter 6+ veces** (aaaaaa).
- **No puede ser igual al correo** ni contener parte del correo.
- **No puede contener el nombre del usuario** (comparación insensible a acentos: "gomez" en contraseña bloquea aunque el nombre sea "Gómez").
- No puede tener espacios al inicio o final.

### 🔒 Rate limiting en login (anti fuerza bruta)

**Antes**: podías intentar infinitas veces una contraseña incorrecta.
**Ahora**: tras 5 intentos fallidos desde la misma IP, se bloquea durante 10 minutos.

Te muestra cuenta regresiva:
- *"Correo o contraseña incorrectos. Te quedan 4 intentos."*
- *"Correo o contraseña incorrectos. Te queda 1 intento antes del bloqueo."*
- *"Demasiados intentos fallidos. Acceso bloqueado por 10 minutos."*

Se resetea cuando hay un login correcto.

### 🎯 Feedback inmediato al usuario

- Mientras escribes, **los errores aparecen debajo del campo** con borde rojo.
- El botón "Crear cuenta" se queda **deshabilitado** hasta que todo es válido.
- Al enviar el form con errores, **los campos NO se borran** — solo ves los errores junto al campo que falla.
- La contraseña **nunca** se preserva (por seguridad).

---

## 8. ✏️ Edición de perfil mejorada

### Pantalla de perfil
- Muestra el nombre de usuario con badge de rol (ADMIN naranja / USUARIO morado).
- **"Tipo de cuenta"** con diseño destacado: *Administrador · ACCESO TOTAL* o *Usuario · ESTÁNDAR*.
- Formulario editable para cambiar el nombre de usuario (con las mismas validaciones del registro).
- Sección separada para cambiar la contraseña con toggle de mostrar/ocultar.
- Fecha de registro ("Miembro desde") visible.
- Medidor de "Nivel de seguridad" basado en cuántos alias activos tienes.

### Aceptar/editar nombre
- Mismas reglas que en el registro.
- Los espacios se eliminan mientras escribes (no puedes tener `"jos e"`).
- Validación en vivo con caja roja bajo el campo.

---

## 9. ✔️ Checkbox "Aceptar todo" en el registro

Antes tenías que marcar los 3 consentimientos uno por uno (Términos, Privacidad, Alertas).

**Ahora** hay un checkbox grande arriba que dice **"Aceptar todo"**:
- Al marcarlo, se marcan los 3 automáticamente.
- Si desmarcas cualquiera de los 3, el master se desmarca solo.
- Estado "indeterminado" (línea gris) cuando tienes algunos pero no todos.
- Diseño destacado con borde morado y texto explicativo.

---

## 10. 💬 Mensajes de error profesionales

**Antes** los errores salían en una caja gris apenas visible entre el título y los campos.

**Ahora** salen como **cajas rojas profesionales** con:
- Icono circular rojo con una ❌ blanca.
- **Borde lateral rojo** (3px) para que lo veas al instante.
- **Título en negrita** ("No pudimos iniciar sesión") + mensaje detallado debajo.
- Animación de entrada suave (fade + slide).
- 3 variantes: rojo (error), verde (éxito), morado (info).

**Ubicación inteligente**: los errores aparecen **justo arriba del botón**, no en la cabecera. Esto es el patrón estándar de Gmail, GitHub, Stripe... porque es donde el usuario está mirando cuando hace click.

Aplicado en: login, registro, recuperar contraseña.

---

## 11. 📬 Correos se marcan como leídos

**Antes**: al abrir un correo, el punto morado de "no leído" se quitaba visualmente pero al recargar volvía a aparecer.

**Ahora**:
- Al abrir un correo, se marca como leído **inmediatamente en la pantalla** (feedback visual al instante).
- En paralelo, se **guarda en la base de datos** vía una petición POST al servidor.
- Al recargar la página, sigue marcado como leído ✓.
- El contador de "Sin leer" se actualiza solo.

---

## 12. 🧪 Kit de pruebas automáticas

Se creó una carpeta `test_samples/` con un script para probar todo el sistema sin tener que enviar correos reales.

### Qué hace
El script `run_tests.py` genera **archivos inocuos** (que no hacen daño real, solo contienen los strings que los analizadores reconocen como sospechosos) y los envía al webhook como si fueran correos reales.

### 14 casos de prueba diferentes

| Test | Qué simula |
|---|---|
| 1 | PowerShell loader con `IEX + DownloadString` |
| 2 | Reverse shell bash con `/dev/tcp` |
| 3 | Batch con comandos LOLBAS (certutil, bitsadmin) |
| 4 | PDF con JavaScript embebido |
| 5 | Archivo llamado `factura.pdf.exe` (doble extensión engañosa) |
| 6 | Archivo limpio (debe salir seguro) |
| 7 | HTML con formulario de phishing |
| 8 | ZIP con un `.exe` dentro |
| 9 | Documento con macro VBA maliciosa |
| 10 | `.lnk` que apunta a PowerShell |
| 11 | Solo cuerpo de phishing (sin adjunto) |
| 12 | 2 adjuntos maliciosos en el mismo correo |
| 13 | 3 URLs sospechosas diferentes en el cuerpo |
| 14 | 3 adjuntos maliciosos a la vez |

### Cómo usarlo
```powershell
# Todos los tests
python test_samples/run_tests.py --alias TU_ALIAS@securemail.com

# Solo uno (útil para debug)
python test_samples/run_tests.py --alias TU_ALIAS --only 2
```

---

## 13. 🐛 Bugs que arreglamos por el camino

### Django template syntax error en alias
- **Problema**: usar `_email_count` (con guion bajo) como nombre de variable hacía crash el template.
- **Fix**: renombrados a `emails_total` y `threats_total`.

### Error en URL analyzer
- **Problema**: `dict.fromkeys(urls)[:30]` no funciona porque `dict_keys` no soporta slicing.
- **Fix**: envolver en `list()`.

### `threat_name` demasiado largo
- **Problema**: cuando había 3 adjuntos maliciosos, el texto concatenado excedía los 200 caracteres del campo y PostgreSQL lo rechazaba.
- **Fix**: truncar a 197 caracteres con "…" al final.

### Wrapper del webhook fallaba
- **Problema**: `except HttpResponseBadRequest` tiraba TypeError porque no es una excepción (es una respuesta HTTP).
- **Fix**: quitar ese except erróneo.

### Login del superuser no funcionaba
- **Problema**: al hacer `createsuperuser`, el username y el email son distintos. El login solo autenticaba por username.
- **Fix**: ahora el login intenta primero por username y si falla, busca el usuario por email y autentica con su username real.

### Auto-refresh de bandeja no arrancaba
- **Problema**: el listener de `DOMContentLoaded` se registraba después de que el evento ya había disparado.
- **Fix**: iniciar el polling inmediatamente sin esperar el evento.

### Polling no detectaba cambios
- **Problema**: se intentaba marcar el correo como leído con un click, pero solo visualmente.
- **Fix**: endpoint `POST /bandeja/<id>/leido/` que lo guarda en la base de datos.

---

## 14. 📁 Archivos creados y modificados

### 📂 Archivos nuevos creados

| Archivo | Para qué sirve |
|---|---|
| `app/validators.py` | Todas las funciones de validación (nombre, email, contraseña) |
| `app/sandbox/body_analyzer.py` | Analiza el texto y HTML del correo (URLs, phishing) |
| `app/sandbox/analyzers/__init__.py` | Paquete de analizadores |
| `app/sandbox/analyzers/base.py` | Estructura común de los reportes |
| `app/sandbox/analyzers/executable_analyzer.py` | Analiza ejecutables PE/ELF |
| `app/sandbox/analyzers/office_analyzer.py` | Analiza documentos Office con macros |
| `app/sandbox/analyzers/pdf_analyzer.py` | Analiza PDFs con JavaScript |
| `app/sandbox/analyzers/archive_analyzer.py` | Extrae y analiza archivos ZIP/RAR/7z |
| `app/sandbox/analyzers/script_analyzer.py` | Analiza scripts (ps1, vbs, bat, sh...) |
| `app/sandbox/analyzers/url_analyzer.py` | Analiza URLs sospechosas |
| `app/sandbox/analyzers/yara_analyzer.py` | Motor de reglas YARA |
| `app/sandbox/analyzers/dynamic_executor.py` | Ejecución real de scripts con strace |
| `app/sandbox/analyzers/rules/malware.yar` | 13 reglas YARA anti-malware |
| `app/migrations/0002_sandbox_extended.py` | Campos nuevos en SandboxAnalysis |
| `app/migrations/0003_sandbox_multi_attachments.py` | Campo `attachments_reports` |
| `app/templates/admin_dashboard.html` | Panel global del admin |
| `app/templates/admin_users.html` | Lista de usuarios del admin |
| `app/templates/admin_user_detail.html` | Detalle de un usuario |
| `test_samples/run_tests.py` | Script de pruebas automáticas |
| `test_samples/README.md` | Instrucciones de las pruebas |

### ✏️ Archivos modificados (cambios principales)

| Archivo | Qué se cambió |
|---|---|
| `Dockerfile.sandbox` | Se instalaron librerías: oletools, pefile, yara, py7zr, rarfile, strace |
| `app/models.py` | Se amplió `SandboxAnalysis` con evidencia, IOCs, reportes por adjunto |
| `app/urls.py` | Rutas nuevas: dashboard live, bandeja live, panel admin, marcar leído |
| `app/views.py` | Vistas nuevas: `dashboard_live_api`, `inbox_new_api`, `mark_email_read_api`, `admin_*`. Reescritas: `login_view`, `registro_view`, `perfil_view` con validaciones |
| `app/webhook.py` | Procesa múltiples adjuntos, manejo robusto de errores |
| `app/sandbox/service.py` | Timeout reducido, dict vacío como fallback |
| `app/sandbox/run_analysis.py` | Orquestador completo (detecta tipo y llama al analyzer) |
| `app/templates/base.html` | Sidebar con sección admin + badge del rol |
| `app/templates/login.html` | Rediseño completo + validaciones + alerts pro |
| `app/templates/register.html` | Rediseño completo + username + aceptar todo + alerts |
| `app/templates/recuperar.html` | Rediseño con split layout + alerts pro |
| `app/templates/terminos.html` | Rediseño profesional con animaciones |
| `app/templates/privacidad.html` | Rediseño profesional con tabla + pasos |
| `app/templates/dashboard.html` | Auto-refresh + tendencias + amenazas recientes |
| `app/templates/inbox.html` | Auto-refresh + agrupación por fecha + quick actions |
| `app/templates/alias.html` | Búsqueda + filtros + stats por alias |
| `app/templates/perfil.html` | Nombre de usuario editable + tipo de cuenta |
| `app/templates/sandbox_report.html` | Reporte rico con evidencia categorizada, IOCs, YARA, adjuntos múltiples |
| `app/templates/sandbox_list.html` | Filtros por severidad + métricas por análisis |

---

## 15. 🚀 Cómo poner todo en marcha

### Primera vez (setup inicial)

```powershell
# 1. Aplicar las migraciones nuevas de la base de datos
python manage.py migrate

# 2. Reconstruir la imagen Docker del sandbox con las librerías nuevas
docker build -t email_seguro_sandbox -f Dockerfile.sandbox .

# 3. Instalar la librería de requests para el script de pruebas
pip install requests

# 4. Crear un administrador (opcional, si no tienes uno)
python manage.py createsuperuser
```

### Día a día

```powershell
# Arrancar el servidor Django
python manage.py runserver
```

Abre http://127.0.0.1:8000/ en el navegador.

### Probar todo el sistema

En otra terminal, con el servidor corriendo:

```powershell
# 1. Crea un alias en la web: http://127.0.0.1:8000/alias/
# 2. Copia la dirección del alias
# 3. Lanza los 14 tests de golpe
python test_samples/run_tests.py --alias TU_ALIAS@securemail.com

# O uno solo para probar
python test_samples/run_tests.py --alias TU_ALIAS --only 2
```

Después abre:
- `http://127.0.0.1:8000/bandeja/` → verás los correos llegar solos
- `http://127.0.0.1:8000/sandbox/` → los análisis con filtros
- Click en cualquier análisis → reporte completo

### Convertir a un usuario en administrador

Si ya tienes un usuario registrado y quieres hacerlo admin:

```powershell
python manage.py shell -c "from django.contrib.auth.models import User; u = User.objects.get(email='TU_EMAIL'); u.is_staff = True; u.save(); print('OK')"
```

O desde el panel admin una vez que tengas un admin, puedes promover a otros con un click.

### Si algo falla

1. **El webhook da error 500**: mira la consola del servidor, ahora todos los errores se loguean con stack trace detallado.
2. **Los tests dan 200 pero no se ven resultados**: verifica que el Docker esté corriendo (`docker ps`).
3. **"Sandbox falló (strace: command not found)"**: necesitas rebuild de la imagen Docker.
4. **"no such column: attachments_reports"**: necesitas aplicar las migraciones (`python manage.py migrate`).

---

## 16. 🏗️ Reestructura MVC profesional (arquitectura limpia)

El proyecto tenía **todo en un solo `views.py` de 814 líneas** — todo mezclado (auth, dashboard, admin, APIs, IA, etc.). Se reorganizó siguiendo el patrón **MVC** (Model-View-Controller) adaptado al sistema **MVT** de Django.

### Cómo mapea MVC a Django

| MVC tradicional | Equivalente en Django |
|---|---|
| **Model** | `models.py` (las tablas de la BD) |
| **Controller** (la lógica) | `views.py` (vistas) + `services/` (lógica de negocio) |
| **View** (lo que se muestra) | `templates/` (HTML) |

### Estructura anterior vs nueva

**Antes** (todo junto en una sola carpeta):
```
app/
├── views.py          ← 814 líneas con TODO mezclado
├── models.py
├── validators.py
├── urls.py
└── templates/
```

**Ahora** (organizado por responsabilidad):
```
app/
├── models.py                    # Tablas de BD (Model)
├── validators.py                # Reglas de validación reutilizables
├── webhook.py                   # Endpoint de correos entrantes
├── Forms.py                     # Formularios Django
├── urls.py                      # Rutas URL
│
├── services/                    # ─── LÓGICA DE NEGOCIO ───
│   ├── __init__.py
│   ├── stats_service.py         # Cálculos de estadísticas (dashboard, admin, perfil)
│   ├── auth_service.py          # Rate limiting, login flexible, decorator admin
│   └── alias_service.py         # Generación de direcciones únicas
│
├── views/                       # ─── VIEWS (controllers) ───
│   ├── __init__.py              # Re-exporta todo para compatibilidad
│   ├── auth_views.py            # login, registro, logout, recuperar, cambiar_password
│   ├── dashboard_views.py       # dashboard + API live
│   ├── inbox_views.py           # bandeja + APIs de polling y marcar leído
│   ├── alias_views.py           # CRUD de alias
│   ├── sandbox_views.py         # lista y reporte del sandbox
│   ├── perfil_views.py          # perfil de usuario
│   ├── admin_views.py           # panel administrador
│   └── ai_views.py              # integración Groq
│
├── sandbox/                     # Análisis de malware (ya estaba modular)
│   ├── analyzers/
│   ├── service.py
│   ├── run_analysis.py
│   └── body_analyzer.py
│
└── templates/                   # ─── HTML (Vistas en MVC) ───
```

### Qué hace cada capa

#### 🧱 `models.py` — la base de datos
Define las tablas: `Alias`, `EmailMessage`, `SandboxAnalysis`. **No cambia**.

#### 🔧 `services/` — la lógica de negocio (nuevo)
Son funciones reutilizables. Por ejemplo:
- `dashboard_stats(user)` calcula las 9 métricas del dashboard en una sola llamada.
- `authenticate_flexible(request, identifier, password)` intenta login por username y por email.
- `generate_alias_address("Amazon")` devuelve `"amazon_x7k2m1@securemail.com"`.
- `login_is_locked(ip)` responde si la IP está bloqueada por fuerza bruta.

**Beneficio**: la misma lógica se usa desde el dashboard, la API JSON y el perfil sin duplicar código.

#### 🎛️ `views/` — los controladores (nuevo)
Cada archivo agrupa vistas de un mismo dominio. Por ejemplo:
- `auth_views.py` tiene **solo** login/registro/logout → 180 líneas, fácil de leer.
- `admin_views.py` tiene **solo** el panel admin → claro de dónde viene cada ruta.
- `inbox_views.py` tiene **solo** bandeja + sus 2 APIs.

**Beneficio**: abres `auth_views.py` y sabes exactamente que ahí está TODO lo de autenticación. No más buscar en un archivo de 800 líneas.

#### 🎨 `templates/` — las vistas (HTML)
No se tocaron. Siguen en la misma carpeta.

### Compatibilidad: `urls.py` no necesitó cambios

El archivo `views/__init__.py` **re-exporta todas las vistas**, así que `urls.py` sigue escribiendo:

```python
from . import views

path('dashboard/', views.dashboard_view, name='dashboard')
```

...y funciona exactamente igual. Internamente Python resuelve `views.dashboard_view` buscándolo en el paquete → lo encuentra en `dashboard_views.py` → lo sirve. **Cero rutas rotas**.

### Principios aplicados

1. **Una responsabilidad por archivo**: cada archivo de `views/` maneja un solo dominio.
2. **Separación views / servicios**: las vistas son delgadas (reciben request, llaman servicios, rinden template). Los servicios contienen la lógica.
3. **Don't Repeat Yourself (DRY)**: `dashboard_stats()` se usa desde 2 sitios (GET y API JSON) sin duplicación.
4. **Retrocompatibilidad**: `views/__init__.py` re-exporta todo para que no se rompan las URLs existentes.
5. **Legibilidad**: archivos cortos (100-200 líneas) vs el antiguo views.py de 814 líneas.

### Métricas

| Métrica | Antes | Ahora |
|---|---|---|
| Archivos de vistas | 1 | 8 |
| Líneas del archivo más grande | 814 | 180 |
| Servicios centralizados | 0 | 3 (`stats_service`, `auth_service`, `alias_service`) |
| Código duplicado | Alto (`_dashboard_stats`, `_timesince_short`, validación, etc.) | Eliminado |
| Tiempo para encontrar una función | "buscar en 814 líneas" | "ir al archivo de su dominio" |

### Qué NO se cambió (intencional)

- **Ningún modelo** → cero migraciones de BD, cero riesgo de perder datos.
- **Ninguna URL** → todas las rutas siguen funcionando.
- **Ningún template** → el HTML y el CSS quedan intactos.
- **Ningún endpoint** → el webhook y las APIs JSON siguen igual.
- **Los datos de prueba** que ya tenías siguen ahí.

### Verificación

Tras la reestructuración:
- ✅ `python manage.py check` → sin errores.
- ✅ Las 23 vistas importables desde `app.views`.
- ✅ Todas las URLs resuelven (`login`, `dashboard`, `inbox`, `alias_list`, `sandbox_list`, `perfil`, `admin_dashboard`, `admin_users`, `cambiar_password`).
- ✅ Todos los archivos Python compilan sin errores.

---

## 🎯 Resumen ejecutivo

En esta sesión de trabajo:

- 🎨 **9 pantallas** rediseñadas con estilo moderno y profesional.
- 🔬 **Sandbox completo** con 6 analizadores especializados + ejecución dinámica real con strace + 13 reglas YARA.
- ⚡ **Auto-refresh** en bandeja y dashboard (sin recargar).
- 📎 **Múltiples adjuntos** procesados individualmente.
- 👥 **Sistema de roles** con panel de administración completo.
- 🛡️ **Validaciones profesionales** con rate limiting anti fuerza bruta.
- 🧪 **Kit de 14 tests** automáticos.
- 🐛 **7 bugs** corregidos.
- 💬 **Mensajes de error pro** en todos los formularios.
- 🏗️ **Arquitectura MVC profesional**: vistas divididas por dominio + capa de servicios de lógica de negocio.

El proyecto está listo para presentarse como trabajo de titulación con:
- Diseño visual moderno
- Análisis de malware serio (comparable a herramientas profesionales)
- Seguridad real (sandbox aislado + validaciones + rate limiting)
- Arquitectura limpia y modular
- Panel de administración funcional

---

*Última actualización: Abril 2026*
