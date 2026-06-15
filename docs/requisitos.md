# Requisitos del Sistema — DockerShield

> Sistema de correo seguro con alias desechables y sandbox de análisis de amenazas.

---

## 1. Requisitos Funcionales

---

Requisito Funcional
ID
R.F. 01
Nombre
Autenticación
Descripción
El sistema debe permitir registro con verificación diferida (código 6 dígitos vía email), inicio de sesión por email o username, bloqueo por IP (3 fallos → 60s) y por usuario (3 fallos → bloqueo temporal 3 min → 1 fallo más → bloqueo permanente), sesión única por usuario, cierre de sesión, y recordar sesión por 30 días.
Requerimientos No Funcionales
R.N.F. 01, R.N.F. 03, R.N.F. 08
Importancia
Alta

---

Requisito Funcional
ID
R.F. 02
Nombre
Recuperación de Cuenta y Contraseña
Descripción
El sistema debe permitir recuperación de contraseña vía token de 24h con rate limit de 5/hora, y recuperación de cuenta bloqueada permanentemente mediante solicitud al administrador con aprobación/rechazo y notificación.
Requerimientos No Funcionales
R.N.F. 01, R.N.F. 03, R.N.F. 08
Importancia
Alta

---

Requisito Funcional
ID
R.F. 03
Nombre
Perfil de Usuario
Descripción
El sistema debe permitir al usuario editar su nombre, cambiar contraseña, subir/eliminar avatar (2 MB max, JPG/PNG/WebP/GIF), activar/desactivar reenvío automático de correos seguros, y eliminar su cuenta en 2 pasos (contraseña + código email) con soft-delete y resumen enviado por email.
Requerimientos No Funcionales
R.N.F. 01, R.N.F. 09
Importancia
Media

---

Requisito Funcional
ID
R.F. 04
Nombre
Gestión de Alias Desechables
Descripción
El sistema debe permitir crear alias con etiqueta creativa generada por IA (Groq Llama) con fallback local, listar alias con estadísticas por alias y por usuario, destruir alias (soft-delete), y enviar correos desde un alias con validación de destinatarios y adjuntos (10 archivos, 25 MB, 50 destinatarios, programación 1 min–72 h). Cuota base de 5 alias por usuario, ampliable por solicitud al admin.
Requerimientos No Funcionales
R.N.F. 13
Importancia
Alta

---

Requisito Funcional
ID
R.F. 05
Nombre
Bandeja de Entrada
Descripción
El sistema debe mostrar correos recibidos paginados con filtros (todos/no leídos/amenazas/seguros), búsqueda por texto, marcar como leído, visualizar HTML neutralizado (enlaces bloqueados, imágenes externas reemplazadas), y mover a papelera individual o por lote (leídos/amenazas/seguros/todos).
Requerimientos No Funcionales
R.N.F. 02, R.N.F. 06, R.N.F. 07
Importancia
Alta

---

Requisito Funcional
ID
R.F. 06
Nombre
Correos Enviados
Descripción
El sistema debe listar correos enviados agrupados por fecha (hoy/ayer/esta semana/anteriores) con carga progresiva, vaciar todos, y mover a papelera individualmente.
Requerimientos No Funcionales
R.N.F. 02, R.N.F. 07
Importancia
Media

---

Requisito Funcional
ID
R.F. 07
Nombre
Borradores
Descripción
El sistema debe permitir guardar borradores con detección de duplicados, listar con carga progresiva y contadores (sin destinatario, programados), obtener borrador por ID para editar, eliminar (hard o soft a papelera), y vaciar todos.
Requerimientos No Funcionales
R.N.F. 07
Importancia
Media

---

Requisito Funcional
ID
R.F. 08
Nombre
Papelera
Descripción
El sistema debe mostrar elementos mezclados (entrada/enviados/borradores) con caducidad a 30 días, restaurar individualmente, eliminar permanentemente, y vaciar todo.
Requerimientos No Funcionales
R.N.F. 07
Importancia
Media

---

Requisito Funcional
ID
R.F. 09
Nombre
Recepción de Correo (Webhook Resend)
Descripción
El sistema debe recibir correos vía webhook de Resend Inbound, obtener contenido completo mediante API de Resend, extraer autenticación SPF/DKIM/DMARC del header Authentication-Results, resolver alias destino, neutralizar HTML, analizar cuerpo (phishing, URLs, suplantación), analizar adjuntos en sandbox Docker aislado (YARA, oletools, PE, PDF, archivos comprimidos, 25 s timeout), combinar puntuaciones (adjunto = MAX, cuerpo+URL ajustado por veredicto auth), y crear notificaciones según nivel de riesgo.
Requerimientos No Funcionales
R.N.F. 04, R.N.F. 05, R.N.F. 13
Importancia
Alta

---

Requisito Funcional
ID
R.F. 10
Nombre
Sandbox de Análisis
Descripción
El sistema debe ejecutar análisis de adjuntos en contenedor Docker aislado (sin red, solo lectura, 256 MB RAM, 1 CPU, usuario no root, timeout 25 s) con analizadores YARA, oletools, PE, PDF, scripts y clasificación por categoría. Debe generar reporte con score 0–100, evidencias, IOCs (URLs/IPs/dominios/hashes), y nombre de amenaza. Debe funcionar con respaldo local cuando Docker no está disponible.
Requerimientos No Funcionales
R.N.F. 04, R.N.F. 07, R.N.F. 13
Importancia
Alta

---

Requisito Funcional
ID
R.F. 11
Nombre
Análisis IA Bajo Demanda
Descripción
El sistema debe permitir al usuario solicitar análisis por IA (Groq Llama 3.3-70B) del reporte completo del sandbox, devolviendo veredicto (MALICIOSO / SOSPECHOSO / SEGURO), explicación y recomendación en español, con caché persistente.
Requerimientos No Funcionales
R.N.F. 13
Importancia
Media

---

Requisito Funcional
ID
R.F. 12
Nombre
Notificaciones
Descripción
El sistema debe mostrar notificaciones con carga progresiva y filtros (todas/no leídas/pendientes/reenviadas/descartadas), marcar como leídas individual o masivamente, sincronizar estado entre dispositivos (toast marker), limpiar por lote, y permitir al usuario aprobar/descartar solicitudes de reenvío de correo seguro (forward_request), ejecutando el reenvío vía Resend al aprobar. Tipos: forward_request, forwarded, threat_alert, system.
Requerimientos No Funcionales
R.N.F. 02, R.N.F. 06
Importancia
Alta

---

Requisito Funcional
ID
R.F. 13
Nombre
Dashboard de Usuario
Descripción
El sistema debe mostrar un dashboard con métricas del usuario: total correos, amenazas bloqueadas, alertas, alias activos, tendencias a 14 días, distribución de riesgo en donut, últimos 5 alias, últimos 20 correos, últimos 3 análisis sandbox, y últimas 3 amenazas.
Requerimientos No Funcionales
R.N.F. 07
Importancia
Media

---

Requisito Funcional
ID
R.F. 14
Nombre
Panel de Administración
Descripción
El sistema debe proveer un panel administrativo completo (sin Django Admin) con dashboard global (usuarios, alias, correos, amenazas, actividad 7 días, top dominios atacantes), gestión de usuarios (buscar, filtrar, ver detalle, promover/revocar admin, ajustar cuota alias, conceder alias ilimitados), gestión global de alias (ver/buscar, activar/desactivar), vista de amenazas (score ≥ 61, filtrar por nivel crítico/alto), gestión de solicitudes de cuota alias (aprobar/rechazar con nota y cantidad), y gestión de solicitudes de recuperación de cuenta (aprobar/rechazar con reactivación automática y email de notificación).
Requerimientos No Funcionales
R.N.F. 02
Importancia
Alta

---

Requisito Funcional
ID
R.F. 15
Nombre
Envío de Correos Transaccionales
Descripción
El sistema debe enviar correos vía Resend API para: verificación de registro (código 6 dígitos), verificación de eliminación de cuenta (código 6 dígitos), recuperación de contraseña (token), alerta de amenaza bloqueada (score ≥ 61), reenvío de correo seguro aprobado, resumen de cuenta eliminada, notificación de reactivación de cuenta, notificación de cambio de cuota alias, y alerta de cuenta bloqueada permanentemente.
Requerimientos No Funcionales
R.N.F. 05
Importancia
Alta

---

Requisito Funcional
ID
R.F. 16
Nombre
Páginas Legales y Errores
Descripción
El sistema debe mostrar páginas de Términos y Condiciones, Política de Privacidad, y páginas personalizadas de error 404 y 500 con diseño acorde al tema del sistema.
Requerimientos No Funcionales
—
Importancia
Baja

---

## 2. Requisitos No Funcionales

---

Requerimiento No Funcional
ID
R.N.F. 01
Nombre
Seguridad de Contraseñas
Descripción
Las contraseñas deben tener 8–128 caracteres, mayúscula, minúscula, dígito y símbolo. No deben estar en lista negra (common passwords, secuencias de teclado, 6+ repeticiones), ni contener el username o email.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 02
Nombre
Protección de URLs
Descripción
Todas las URLs que expongan IDs de modelo deben usar el converter sid (base36 + HMAC firmado con SECRET_KEY) para prevenir enumeración de IDs secuenciales y forjado de tokens.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 03
Nombre
Sesión Única
Descripción
El sistema debe garantizar una sola sesión activa por usuario mediante middleware SingleSessionMiddleware, invalidando la sesión anterior al iniciar sesión en otro dispositivo. Sesiones inactivas por más de 7 minutos se consideran abandonadas.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 04
Nombre
Aislamiento del Sandbox
Descripción
El análisis de adjuntos debe ejecutarse en contenedor Docker con red deshabilitada (--network none), filesystem de solo lectura (--read-only), memoria limitada (256 MB), CPU limitada (1.0), usuario no root, timeout de 25 segundos, y /tmp efímero (64 MB tmpfs).
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 05
Nombre
Resiliencia del Webhook
Descripción
El endpoint del webhook debe devolver siempre HTTP 200 aunque falle el análisis interno, para evitar que Resend reintente en bucle. Debe intentar guardado mínimo del correo incluso si todo el pipeline falla, y cada etapa del análisis debe estar envuelta en try/except individual para que un fallo no detenga las siguientes.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 06
Nombre
No Caché en Páginas Autenticadas
Descripción
Las páginas HTML autenticadas deben incluir headers Cache-Control: no-cache, no-store, must-revalidate para evitar que el botón "atrás" del navegador muestre contenido de sesiones cerradas.
Importancia
Media

---

Requerimiento No Funcional
ID
R.N.F. 07
Nombre
Rendimiento de Carga
Descripción
Las listas principales (bandeja, enviados, borradores, papelera, notificaciones, alias, sandbox) deben usar carga progresiva (load-more) con lotes pequeños. El HTML neutralizado de correos debe cachearse por 1 día. El análisis sandbox individual debe tener timeout máximo de 25 segundos.
Importancia
Media

---

Requerimiento No Funcional
ID
R.N.F. 08
Nombre
Rate Limiting
Descripción
El sistema debe aplicar límites de tasa: 3 fallos de login por IP (bloqueo 60s), 3 fallos por usuario (bloqueo temporal 3 min, luego permanente), 6 envíos de código de verificación por hora, 60 s de reintento entre envíos de código, y 5 solicitudes de reset de contraseña por hora.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 09
Nombre
Privacidad y Consentimiento
Descripción
El registro debe requerir aceptación explícita de 3 casillas: Términos y Condiciones, Política de Privacidad, y consentimiento para alertas de seguridad. La eliminación de cuenta debe ser soft-delete (is_active=False, is_deleted=True) con datos preservados. El sistema debe detectar y rechazar emails temporales/desechables en el registro.
Importancia
Alta

---

Requerimiento No Funcional
ID
R.N.F. 10
Nombre
Idioma
Descripción
Toda la interfaz de usuario, notificaciones, reportes de análisis, mensajes de error, y correos transaccionales deben estar en español. Los reportes de amenazas y análisis de IA deben generar contenido en español.
Importancia
Media

---

Requerimiento No Funcional
ID
R.N.F. 11
Nombre
Tema Visual
Descripción
El sistema debe soportar tema oscuro por defecto con un tema alternativo "carbon", almacenado en localStorage, con diseño responsivo, tipografía JetBrains Mono (código) y DM Sans (lectura), paleta morada (#7c3aed como color principal), y barra lateral con secciones SEGURIDAD y CORREO.
Importancia
Baja

---

Requerimiento No Funcional
ID
R.N.F. 12
Nombre
Mantenibilidad
Descripción
La lógica de negocio debe estar separada en servicios (services/) por cada app, con modelos, vistas y URLs claramente diferenciados. Los analizadores del sandbox deben ser módulos independientes y reemplazables. El webhook debe tener una arquitectura de pipeline con etapas claras (parse → auth → analyze → combine → persist → notify).
Importancia
Media

---

Requerimiento No Funcional
ID
R.N.F. 13
Nombre
Disponibilidad de Análisis
Descripción
El análisis sandbox debe tener respaldo local cuando Docker no esté disponible en el sistema. La generación de etiquetas de alias debe tener respaldo local (word banks en inglés) cuando Groq no responda (timeout 4 s). El envío de correos transaccionales debe tener fallback a consola cuando no hay credenciales SMTP.
Importancia
Media

---

## 3. Matriz de Trazabilidad

| ID | Nombre | RNF | HU |
|----|--------|-----|----|
| R.F. 01 | Autenticación | RNF.01, RNF.03, RNF.08 | HU1, HU2, HU3 |
| R.F. 02 | Recuperación de Cuenta y Contraseña | RNF.01, RNF.03, RNF.08 | HU3, HU29 |
| R.F. 03 | Perfil de Usuario | RNF.01, RNF.09 | HU4, HU5 |
| R.F. 04 | Gestión de Alias Desechables | RNF.13 | HU6, HU7, HU8, HU11 |
| R.F. 05 | Bandeja de Entrada | RNF.02, RNF.06, RNF.07 | HU10 |
| R.F. 06 | Correos Enviados | RNF.02, RNF.07 | HU11 |
| R.F. 07 | Borradores | RNF.07 | HU12 |
| R.F. 08 | Papelera | RNF.07 | HU13 |
| R.F. 09 | Recepción de Correo (Webhook Resend) | RNF.04, RNF.05, RNF.13 | HU9, HU22 |
| R.F. 10 | Sandbox de Análisis | RNF.04, RNF.07, RNF.13 | HU15, HU16, HU17, HU18, HU19, HU20, HU21, HU24, HU25 |
| R.F. 11 | Análisis IA Bajo Demanda | RNF.13 | HU23 |
| R.F. 12 | Notificaciones | RNF.02, RNF.06 | HU14, HU32, HU33 |
| R.F. 13 | Dashboard de Usuario | RNF.07 | — |
| R.F. 14 | Panel de Administración | RNF.02 | HU26, HU27, HU28, HU29, HU30, HU31 |
| R.F. 15 | Envío de Correos Transaccionales | RNF.05 | HU14 |
| R.F. 16 | Páginas Legales y Errores | — | — |
