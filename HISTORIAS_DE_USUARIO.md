# Historias de Usuario

## Historia de Usuario HU1

**Nombre:** Registro con verificación de correo

**Usuario:** Usuario no registrado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario no registrado, quiero registrarme con verificación por correo electrónico para activar mi cuenta de forma segura.

**Criterios de Aceptación:**
- Registro en dos pasos de formulario a código de verificación por correo y activación.
- Validación progresiva del formulario.
- Envío de código de verificación al correo ingresado.
- Tiempo de espera para reenvío de código de verificación.

**Tareas técnicas:**
- Implementar modelo PendingRegistration y VerificationCode.
- Crear servicio de envío de correos de verificación.
- Implementar validación de contraseñas.
- Configurar rate limiting para reenvío de códigos.

**Entregable:**
Registro funcional con verificación por correo y validación de seguridad.

---

## Historia de Usuario HU2

**Nombre:** Inicio de sesión con anti-fuerza bruta

**Usuario:** Usuario registrado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario registrado, quiero iniciar sesión con protección anti-fuerza bruta para proteger mi cuenta de accesos no autorizados.

**Criterios de Aceptación:**
- Bloqueo temporal por IP tras 3 intentos fallidos, tiempo de espera 1 minuto.
- Bloqueo permanente de cuenta tras fallar los 3 intentos de bloqueo temporal.
- Una sola sesión activa por usuario.
- Middleware que impide acceso a páginas autenticadas tras cerrar sesión.

**Tareas técnicas:**
- Implementar servicio de bloqueo por IP y por cuenta.
- Implementar SingleSessionMiddleware.
- Implementar NoCacheAuthMiddleware.
- Configurar rate limiting por IP en vista de login.

**Entregable:**
Inicio de sesión seguro con bloqueo por intentos fallidos y sesión única.

---

## Historia de Usuario HU3

**Nombre:** Recuperación de contraseña

**Usuario:** Usuario registrado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como usuario registrado, quiero recuperar mi contraseña mediante un token enviado por correo para restablecer el acceso si la olvido.

**Criterios de Aceptación:**
- Solicitud de restablecimiento con correo electrónico.
- Generación de token único y temporal.
- Envío de enlace de restablecimiento por correo.
- Formulario seguro para establecer nueva contraseña.
- Token de un solo uso con expiración.

**Tareas técnicas:**
- Implementar password_reset_service con generación de tokens.
- Crear vistas de solicitud y restablecimiento.
- Implementar envío de correo transaccional.
- Validar expiración y unicidad del token.

**Entregable:**
Flujo completo de recuperación de contraseña por correo.

---

## Historia de Usuario HU4

**Nombre:** Dashboard de actividad y métricas

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Baja

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 2

**Descripción:**
Como usuario autenticado, quiero ver un dashboard al iniciar sesión con métricas clave de mi actividad para tener una visión general rápida del estado de mi bandeja y la seguridad de mis alias.

**Criterios de Aceptación:**
- Saludo personalizado con el nombre del usuario y resumen del día (no leídos, amenazas bloqueadas hoy).
- Cuatro tarjetas de métricas: correos recibidos, sin leer, amenazas bloqueadas, alias activos.
- Gráfico de actividad de correos con selector de período (diario/semanal/mensual/anual).
- Gráfico donut de distribución de riesgo (seguros/sospechosos/amenazas).
- Tarjeta de perfil con avatar, nombre, email y estadísticas personales.
- Lista de últimas 3 amenazas recientes con remitente, asunto y score.
- Lista de hasta 5 alias activos con acceso rápido a gestión.
- Lista de últimos 3 análisis sandbox con enlace al reporte completo.
- Estados vacíos con call-to-action cuando no hay datos en cada sección.

**Tareas técnicas:**
- Implementar dashboard_view con consultas agregadas de stats.
- Implementar dashboard_stats() en stats_service.py.
- Crear template dashboard.html con layout responsivo.
- Integrar Chart.js para gráficos de actividad y distribución.
- Implementar selector de período con recarga de datos.

**Entregable:**
Dashboard funcional con métricas, gráficos, listas de actividad reciente y acceso rápido a las secciones principales.

---

## Historia de Usuario HU5

**Nombre:** Personalización de apariencia con temas visuales

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Baja

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 2

**Descripción:**
Como usuario autenticado, quiero elegir entre distintos temas visuales (claro, oscuro, carbón) para personalizar la apariencia de la aplicación.

**Criterios de Aceptación:**
- Modal de selección de temas accesible desde el sidebar.
- Tres temas disponibles: Claro, Oscuro y Carbón.
- Vista previa visual de cada tema con preview en miniatura.
- Cambio instantáneo sin recargar la página completa.
- Persistencia del tema seleccionado entre sesiones (localStorage).
- Tema oscuro como predeterminado.

**Tareas técnicas:**
- Definir variables CSS por tema en properties/base.css con [data-theme].
- Implementar modal de selección en base.html.
- Implementar selectThemeCard() en JavaScript con persistencia en localStorage.
- Agregar botón de acceso "Apariencia" en el sidebar.
- Aplicar tema al cargar la página antes del renderizado.

**Entregable:**
Selector de temas funcional con 3 modos visuales, preview y persistencia.

---

## Historia de Usuario HU6

**Nombre:** Gestión de perfil

**Usuario:** Usuario registrado

**Iteración asignada:** Iteración 1

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Baja

**Puntos Estimados:** 2

**Descripción:**
Como usuario, quiero gestionar mi perfil cambiando foto de perfil, nombre de usuario y contraseña para mantener mis datos actualizados.

**Criterios de Aceptación:**
- Edición de nombre de usuario.
- Subida y cambio de foto de perfil.
- Cambio de contraseña con validación de seguridad.
- Activar/desactivar reenvío automático de correos seguros.

**Tareas técnicas:**
- Implementar profile_service para gestión de avatar.
- Crear formulario CambiarPasswordForm.
- Implementar vista de perfil con edición.
- Validar tamaño y tipo de imagen de avatar.

**Entregable:**
Página de perfil funcional con avatar y cambio de contraseña.

---

## Historia de Usuario HU7

**Nombre:** Eliminación de cuenta en dos pasos

**Usuario:** Usuario registrado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario, quiero eliminar mi cuenta en dos pasos con confirmación por correo para borrar mis datos de forma segura.

**Criterios de Aceptación:**
- Solicitud de eliminación desde el perfil.
- Envío de código de confirmación al correo.
- Confirmación con código para eliminar definitivamente.
- Eliminación física de todos los datos asociados.

**Tareas técnicas:**
- Implementar account_deletion_service.
- Crear modelo de solicitud de eliminación.
- Implementar envío de código de confirmación.

**Entregable:**
Eliminación segura de cuenta en dos pasos.

---

## Historia de Usuario HU8

**Nombre:** Creación de alias temporales

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero crear alias de correo temporales para proteger mi dirección real al registrarme en servicios externos.

**Criterios de Aceptación:**
- Generación de alias con etiqueta aleatoria + dominio.
- Cuota máxima de 5 alias por usuario por defecto.
- Vista con listado de alias y su estado.
- Copia rápida de dirección de alias al portapapeles.
- Estadísticas por alias con correos recibidos y amenazas detectadas.

**Tareas técnicas:**
- Implementar modelo Alias con campos de estado y metadatos.
- Implementar alias_service con generación de etiquetas.
- Crear vistas CRUD para alias.
- Implementar paginación y filtros en listado.

**Entregable:**
Sistema de creación y gestión de alias temporales con cuota.

---

## Historia de Usuario HU9

**Nombre:** Generación de alias con IA

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Alta

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero que los alias se generen con inteligencia artificial en español para obtener etiquetas creativas y memorables.

**Criterios de Aceptación:**
- Integración con Groq API (Llama 3.1-8b-instant).
- Generación de etiquetas en español.
- Fallback automático a generación en español si la API falla.
- La etiqueta debe ser única dentro del sistema.

**Tareas técnicas:**
- Integrar llamada a API de Groq para generación de etiquetas.
- Implementar lógica de reintento y fallback.
- Manejar errores de conexión y respuestas inválidas.
- Validar la unicidad de la etiqueta generada.

**Entregable:**
Generación automática de alias con IA y fallback inteligente.

---

## Historia de Usuario HU10

**Nombre:** Destrucción de Alias

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 2

**Descripción:**
Como usuario autenticado, quiero destruir un alias para eliminar direcciones que ya no uso.

**Criterios de Aceptación:**
- Botón de destruir en cada alias del listado.
- Confirmación con modal de peligro antes de destruir.
- Soft-delete del alias.
- "Destruido" visible en el listado tras la destrucción.
- La dirección queda bloqueada permanentemente (no se puede reusar).
- Los correos recibidos no se eliminan, solo el alias deja de recibir nuevos.

**Tareas técnicas:**
- Implementar alias_destroy_view con soft-delete.
- Agregar confirmDialog de peligro en JavaScript.
- Implementar alias.html para mostrar estado destruido sin botones de acción.
- Mostrar mensaje de éxito con toast.

**Entregable:**
Destrucción de alias con confirmación, soft-delete y actualización visual del listado.

---

## Historia de Usuario HU11

**Nombre:** Solicitud de aumento de cuota de alias

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 2

**Descripción:**
Como usuario autenticado, quiero solicitar más cuota de alias al administrador para ampliar mi límite cuando lo necesite.

**Criterios de Aceptación:**
- Formulario de solicitud con justificación.
- Notificación al administrador de nueva solicitud.
- Seguimiento del estado de la solicitud (pendiente, aprobada, rechazada).
- Límite máximo configurable por administrador.

**Tareas técnicas:**
- Implementar modelo AliasQuotaRequest.
- Crear vista de solicitud de cuota.
- Integrar notificación al administrador.

**Entregable:**
Sistema de solicitud y aprobación de aumento de cuota.

---

## Historia de Usuario HU12

**Nombre:** Recepción de correos en alias con Cloudflare Email Routing

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alta

**Puntos Estimados:** 8

**Descripción:**
Como usuario autenticado, quiero recibir correos enviados a mis alias a través de Cloudflare Email Routing para leerlos sin exponer mi dirección real.

**Criterios de Aceptación:**
- Integración con Cloudflare Email Routing mediante un Cloudflare Worker que reenvíe el correo en formato raw MIME (RFC 822) al endpoint de la aplicación.
- Recepción de correos con adjuntos extraídos del cuerpo MIME.
- Almacenamiento seguro de metadatos (From, To, Subject, Message-ID) y contenido.
- Enlace del correo al alias destino correcto.
- Manejo de errores en el parsing y logging.
- Criterios de neutralización HTML, body_analyzer, score combinado, pipeline de 3 niveles de riesgo (Seguro, Sospechoso, Amenaza).

**Tareas técnicas:**
- Implementar endpoint de webhook `/webhook/inbound/cloudflare/` en Django.
- Configurar e implementar un Cloudflare Worker (`cloudflare-worker.js`) para capturar correos entrantes y reenviarlos mediante POST en formato raw MIME (`message/rfc822`).
- Parsear el formato raw MIME de forma segura extrayendo From, To, Subject, cuerpo (HTML y texto plano) y adjuntos.
- Almacenar `EmailMessage` y `EmailAttachment` en la base de datos.
- Desencadenar análisis sandbox automáticamente sobre los adjuntos procesados.
- Configurar el tamaño máximo de carga en `settings.py` (`DATA_UPLOAD_MAX_MEMORY_SIZE`) para soportar correos con archivos adjuntos grandes enviados vía MIME.

**Entregable:**
Recepción funcional de correos entrantes vía webhook de Cloudflare y Cloudflare Worker.

---

## Historia de Usuario HU13

**Nombre:** Bandeja de entrada

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero ver mi bandeja de entrada paginada y agrupada por fecha para leer los correos recibidos en mis alias.

**Criterios de Aceptación:**
- Listado paginado con 6 correos por página.
- Filtros en tiempo real, búsqueda por texto, timestamp compacto, badge sincronizado.
- Vista de detalle con HTML renderizado y enlaces neutralizados.
- Imágenes reemplazadas por placeholders por seguridad.

**Tareas técnicas:**
- Implementar vista de inbox con paginación y agrupación.
- Neutralizar enlaces en la vista de detalle.
- Reemplazar imágenes embebidas por placeholders.

**Entregable:**
Bandeja de entrada funcional con seguridad de contenido.

---

## Historia de Usuario HU14

**Nombre:** Redacción y envío de correos

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero redactar y enviar correos desde un alias para responder sin exponer mi dirección real.

**Criterios de Aceptación:**
- Modal de redacción con editor HTML.
- Selección de alias remitente.
- Adjuntar archivos.
- Autocompletado de contactos basado en correos previos.
- Envío a través de Resend API.
- Sanitización HTML saliente, footer de alias, validación completa.

**Tareas técnicas:**
- Implementar compose_modal con editor HTML.
- Integrar envío con Resend API.
- Implementar autocompletado de contactos.
- Validar adjuntos (tamaño, tipo, número).

**Entregable:**
Composición y envío de correos desde alias.

---

## Historia de Usuario HU15

**Nombre:** Bandeja de correos enviados

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero ver el historial de correos enviados desde mis alias para dar seguimiento a mis comunicaciones.

**Criterios de Aceptación:**
- Listado paginado con 6 correos por página y botón "Ver más".
- Agrupación por fecha (Hoy, Ayer, Esta semana, Anteriores).
- Filtros por pestaña: Todos / Con adjuntos / Programados.
- Búsqueda en tiempo real por destinatario, asunto o alias.
- Cada fila muestra destinatario, asunto, alias remitente, timestamp, adjuntos.
- Botón de mover a papelera en cada correo.
- Indicador visual de alias desde el que se envió.

**Tareas técnicas:**
- Implementar sent_view con paginación tipo "load more".
- Crear template sent.html y _sent_row.html.
- Implementar filtros y búsqueda en JavaScript.
- Integrar trash para mover a papelera.

**Entregable:**
Bandeja de enviados con paginación, filtros, búsqueda y agrupación por fecha.

---

## Historia de Usuario HU16

**Nombre:** Vista de detalle de correo

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero abrir un panel lateral con el detalle completo de un correo para leer su contenido, ver adjuntos y acceder al análisis de seguridad.

**Criterios de Aceptación:**
- Panel lateral deslizable al hacer clic en un correo de la bandeja.
- Visualización de: asunto, remitente, fecha, alias destino.
- Score de amenaza con barra visual y badge (Seguro/Sospechoso/Bloqueado).
- Cuerpo del correo renderizado en iframe sandboxed (HTML neutralizado).
- Botón para alternar entre vista HTML y texto plano.
- Sección de adjuntos con nombre y badge "BLOQUEADO".
- Enlace al reporte de análisis sandbox.
- Botones de acción: responder, mover a papelera.

**Tareas técnicas:**
- Implementar panel lateral en inbox.html.
- Implementar openEmail() en inbox.js para poblar el panel.
- Implementar body_html sanitizado.
- Renderizar HTML en iframe sandboxed para seguridad.
- Mostrar score, adjuntos y enlace a sandbox condicionalmente.

**Entregable:**
Panel de detalle de correo con renderizado seguro, score de amenaza e integración con sandbox.

---

## Historia de Usuario HU17

**Nombre:** Escaneo automático de adjuntos antes de enviar correos

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 8

**Descripción:**
Como usuario autenticado, quiero que cada archivo que adjunto a un correo sea escaneado automáticamente por el sandbox al adjuntarlo, para asegurarme de que no envío malware sin saberlo. Además, si el archivo está protegido con contraseña, quiero poder desbloquearlo para que sea analizado correctamente.

**Criterios de Aceptación:**
- Al hacer clic en "Adjuntar", el archivo se envía a /alias/attachment-scan/ para su análisis.
- Mientras se analiza, el chip del adjunto muestra un spinner con el texto "Analizando adjunto con DockerShield, espera por favor...".
- El botón "Enviar" está deshabilitado mientras haya escaneos pendientes o archivos protegidos sin desbloquear.
- Si el archivo es seguro (score ≤ 30), aparece "Listo" en el chip y se puede enviar normalmente.
- Si el archivo es sospechoso (score 31-60), se muestra toast de warning y el archivo se rechaza.
- Si el archivo es malicioso (score ≥ 61) sin contraseña: 1er intento advertencia modal; 2do intento cuenta bloqueada + notificación admin.
- Con contraseña el archivo se rechaza sin penalizar al usuario (no cuenta como intento malicioso).
- Si el archivo está protegido con contraseña el chip muestra "Protegido" y un botón "Desbloquear".
- Aparece un toast informativo "Archivo Protegido. Haz clic en 'Desbloquear' para analizarlo".
- Al hacer clic en "Desbloquear", se abre un modal overlay para ingresar la contraseña.
- El modal tiene botón toggle para mostrar/ocultar la contraseña.
- Al enviar la contraseña, el chip muestra spinner mientras se re-analiza con run_sandbox_with_password().
- Si la contraseña es correcta y el contenido es seguro, el archivo se agrega como adjunto válido.
- Si la contraseña es incorrecta, se muestra toast de error y se puede reintentar hasta 3 veces en 10 minutos.
- Si la contraseña es correcta pero el contenido es malicioso, se rechaza sin penalización.
- Si el usuario cancela el modal, el chip permanece con botón "Desbloquear" y el botón Enviar sigue deshabilitado.
- Cada adjunto se escanea una sola vez al adjuntar (no hay scan redundante al hacer submit).
- El contenedor de adjuntos tiene scroll para más de 2 chips.
- Si el sandbox no está disponible, se muestra toast de error y se rechaza el archivo.

**Tareas técnicas:**
- Implementar /alias/attachment-scan/ con soporte para escaneo normal y re-análisis con contraseña.
- Integrar run_sandbox_with_password() de sandbox/service.py para desbloquear comprimidos protegidos.
- Implementar rate limiting de 3 intentos/10 min por archivo para desbloqueos.
- Agregar flag skip_malicious_counter para evitar penalización en desbloqueos.
- Implementar pendingUnlock[] array en JS para gestionar archivos pendientes de desbloqueo.
- Implementar modal overlay con toggle de visibilidad de contraseña.
- Implementar spinner de carga en CSS (.scan-spinner).
- Implementar scroll si pasa de 2 adjuntos.

**Entregable:**
Scanner de adjuntos funcional con feedback visual por archivo, desbloqueo de archivos protegidos con contraseña mediante modal overlay, sin bloqueo del envío cuando todos los archivos están aprobados.

---

## Historia de Usuario HU18

**Nombre:** Advertencia por archivo adjunto sospechoso

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero que si adjunto un archivo con elementos sospechosos (score entre >31 y <60) reciba una advertencia visual sin consecuencias, pero eliminando el adjunto del correo por seguridad.

**Criterios de Aceptación:**
- Se muestra un toast naranja "Archivo Sospechoso" con el detalle de la amenaza.
- El archivo es rechazado y no se adjunta.
- No se incrementa el contador de advertencias.
- No se envía notificación al administrador.
- No hay ninguna consecuencia para la cuenta del usuario.

**Tareas técnicas:**
- En attachment_scan_api (apps/aliases/views.py) agregar bloque if is_warning después de la validación del sandbox que retorne el json correspondiente sin tocar malicious_attachment_attempts.
- En compose_attachment_scanner.js: en el .then() del fetch, agregar else if (r.data && r.data.warning) que muestre showToast type: 'warning' con el mensaje del servidor, asigne el error a errAtt.textContent y no llame a api.addFile(file) para que el archivo no se adjunte.
- Verificar que risk_level == 'warning' no active _notify_admin_attachment_abuse ni incremente contadores.

**Entregable:**
Los archivos adjuntos sospechosos (score 31-60) se rechazan silenciosamente con un toast naranja, sin afectar la cuenta del usuario ni notificar al administrador.

---

## Historia de Usuario HU19

**Nombre:** Bloqueo progresivo por malware (1ª ofensa)

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero que si intento adjuntar un archivo malicioso reciba una advertencia clara y se registre el intento, para saber que mi próxima infracción resultará en bloqueo permanente de cuenta.

**Criterios de Aceptación:**
- Se muestra un modal de confirmación con el nombre del archivo y la amenaza detectada.
- El modal usa texto plano sin HTML escapado.
- El modal tiene solo botón "Entendido".
- El modal advierte: "Si vuelves a intentarlo, tu cuenta será bloqueada permanentemente".
- El archivo es rechazado y no se adjunta.
- El contador se incrementa a 1.
- No se envía notificación al administrador.

**Tareas técnicas:**
- Manejar respuesta con attempts == 1 en scanner frontend.
- Mostrar modal de advertencia con botón de Entendido.
- Implementar lógica del contador de advertencia.

**Entregable:**
Advertencia clara con registro del primer intento.

---

## Historia de Usuario HU20

**Nombre:** Bloqueo permanente de cuenta (2ª ofensa)

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 8

**Descripción:**
Como usuario autenticado, quiero que si intento adjuntar malware por segunda vez mi cuenta sea bloqueada automáticamente y se me notifique con un modal de cuenta regresiva, para entender que perdí el acceso y debo contactar al administrador.

**Criterios de Aceptación:**
- user.is_active se desactiva.
- Se asigna el bloqueo describiendo el motivo.
- La sesión activa se cierra.
- Se muestra el modal con countdown de 1 minuto.
- El mensaje incluye: motivo, nombre del archivo, amenaza, score.
- Si el usuario recarga durante el countdown, el modal reaparece con el tiempo restante o redirige automáticamente al login.
- Al expirar el countdown, redirige a /.
- Al intentar login, detecta el bloqueo y muestra modal de recuperación.
- El modal de recuperación no cuenta como intento fallido de login.
- El administrador puede reactivar la cuenta vía solicitud al admin.
- Una vez aprobada la solicitud por el admin resetea el contador a 0.

**Tareas técnicas:**
- Implementar bloqueo del usuario por actividad maliciosa.
- Implementar modal de bloqueo.
- Implementar persistencia en localStorage con countdown.
- Cargar malware_blocked_modal.js en base.html.
- Agregar manejo de redirección a /.

**Entregable:**
Bloqueo automático con experiencia de usuario guiada (modal → countdown → redirect → recuperación).

---

## Historia de Usuario HU21

**Nombre:** Borradores automáticos

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Baja

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero guardar borradores automáticamente para no perder mensajes en progreso.

**Criterios de Aceptación:**
- Guardado automático periódico del contenido del modal.
- Listado de borradores con paginación "cargar más".
- Continuar redacción desde un borrador guardado.
- Eliminación de borradores.

**Tareas técnicas:**
- Implementar auto-save con JavaScript (setInterval + ajax).
- Crear modelo Draft y vistas asociadas.
- Implementar paginación tipo "load more".

**Entregable:**
Sistema de borradores con guardado automático.

---

## Historia de Usuario HU22

**Nombre:** Papelera con retención temporal

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Baja

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero acceder a la papelera con retención de 30 días para recuperar correos eliminados por error.

**Criterios de Aceptación:**
- Vista unificada de papelera (entrantes + enviados + borradores).
- Eliminación lógica (soft-delete) con fecha de expiración.
- Recuperación de correos desde la papelera.
- Vaciar papelera manualmente.
- Purga automática tras 30 días.

**Tareas técnicas:**
- Implementar soft-delete en modelos de correo.
- Crear vista de papelera con acciones de recuperar/vaciar.
- Implementar tarea programada para purga automática.

**Entregable:**
Papelera funcional con recuperación y purga automática.

---

## Historia de Usuario HU23

**Nombre:** Reenvío de correos seguros a bandeja real

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero decidir si reenviar un correo analizado a mi bandeja real para solo recibir los que considere seguros.

**Criterios de Aceptación:**
- Notificación al usuario cuando un correo esté analizado.
- Opción "reenviar" o "descartar" en la notificación.
- Reenvío del correo original al correo real del usuario.
- Registro de la decisión del usuario.

**Tareas técnicas:**
- Implementar lógica de reenvío.
- Integrar notificación con acción de reenvío.
- Reconstruir correo original para reenvío.

**Entregable:**
Sistema de reenvío selectivo de correos analizados.

---

## Historia de Usuario HU24

**Nombre:** Análisis de archivos adjuntos en contenedor aislado

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 13

**Descripción:**
Como sistema de seguridad, quiero analizar los archivos adjuntos en un contenedor Docker aislado para detectar malware sin riesgo de contaminación.

**Criterios de Aceptación:**
- Análisis en contenedor con --network none.
- Sistema de archivos de solo lectura.
- Límites de recursos (CPU, memoria, disco).
- Timeout de análisis por archivo.
- Resultados almacenados en base de datos.

**Tareas técnicas:**
- Implementar DockerSandboxService.
- Configurar Dockerfile.sandbox.
- Implementar timeouts y límites de recursos.
- Manejar errores de contenedor (OOM, timeout, crash).

**Entregable:**
Sandbox funcional con análisis aislado en contenedor Docker.

---

## Historia de Usuario HU25

**Nombre:** Análisis de ejecutables (PE/ELF)

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 8

**Descripción:**
Como sistema de seguridad, quiero analizar archivos ejecutables para detectar packers, ofuscación y APIs sospechosas.

**Criterios de Aceptación:**
- Detección de packers (UPX, Themida, ASPack).
- Análisis de entropía y secciones sospechosas.
- Extracción de cadenas y llamadas a API.
- Verificación de firmas digitales.
- Detección de ofuscación y cifrado.

**Tareas técnicas:**
- Implementar executable_analyzer con pefile y elftools.
- Detectar packers por firma y heurística.
- Calcular entropía por sección.
- Extraer imports, exports y recursos.

**Entregable:**
Analizador de ejecutables PE/ELF con detección de packers, secciones anómalas y extracción de indicadores de compromiso.

---

## Historia de Usuario HU26

**Nombre:** Análisis de documentos Office

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero analizar documentos Office en busca de macros maliciosas para detectar malware ofimático.

**Criterios de Aceptación:**
- Extracción y análisis de macros VBA.
- Detección de AutoOpen/AutoExec.
- Detección de llamadas a Shell/PowerShell desde macros.
- Extracción de URLs embebidas en macros.
- Análisis de fórmulas y DDE.

**Tareas técnicas:**
- Implementar office_analyzer con oletools.
- Analizar VBA en busca de patrones maliciosos.
- Detectar ejecución automática de macros.

**Entregable:**
Analizador de documentos Office con detección de macros maliciosas.

---

## Historia de Usuario HU27

**Nombre:** Análisis de PDFs

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero analizar archivos PDF en busca de JavaScript embebido y acciones automáticas para detectar documentos PDF peligrosos.

**Criterios de Aceptación:**
- Extracción de JavaScript embebido.
- Detección de /OpenAction, /Launch y /URI actions.
- Análisis de formularios XFA.
- Detección de streams comprimidos sospechosos.
- Extracción de URLs embebidas.

**Tareas técnicas:**
- Implementar pdf_analyzer con extracción de objetos PDF.
- Analizar acciones automáticas y JavaScript.
- Descomprimir y analizar streams.

**Entregable:**
Analizador de PDF con detección de JavaScript y acciones automáticas.

---

## Historia de Usuario HU28

**Nombre:** Análisis de archivos comprimidos

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero analizar archivos comprimidos (ZIP/RAR/7z) recursivamente para detectar contenido malicioso anidado.

**Criterios de Aceptación:**
- Extracción recursiva de ZIP, RAR, 7z.
- Detección de zip-bombs (archivos demasiado comprimidos).
- Detección de archivos protegidos con contraseña.
- Análisis de cada archivo extraído individualmente.
- Límite de profundidad y número de archivos.

**Tareas técnicas:**
- Implementar archive_analyzer con soporte multi-formato.
- Detectar zip-bombs por ratio de compresión.
- Implementar límites de recursión.

**Entregable:**
Analizador de archivos comprimidos con extracción recursiva.

---

## Historia de Usuario HU29

**Nombre:** Análisis de scripts maliciosos

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 8

**Descripción:**
Como sistema de seguridad, quiero analizar scripts (.ps1, .bat, .vbs, .sh, .js, .htaccess, .py) que llegan como adjuntos para detectar patrones de malware, ofuscación y comportamientos sospechosos antes de que lleguen al usuario.

**Criterios de Aceptación:**
- Detección de patrones maliciosos por tipo de script (.ps1, .vbs, .js, .bat, .sh).
- Análisis de ofuscación (encoding, variables ofuscadas, líneas extralargas).
- Detección de descargas desde URLs en scripts.
- Detección de persistencia y escalado de privilegios.
- Ejecución dinámica con strace para scripts .sh y .py.
- Cobertura para scripts .htaccess y .py en análisis estático.

**Tareas técnicas:**
- Implementar script_analyzer.py con detectores regex por extensión (.ps1, .vbs, .js, .bat, .sh, .hta, .lnk, .reg, .htaccess, .py).
- Implementar heurística de ofuscación (longitud de línea >800 chars, relación/caracteres).
- Implementar extracción de IOCs (URLs, IPs) mediante regex en el cuerpo del script.
- Integrar ejecución dinámica con strace -f en contenedor Docker para scripts .sh y .py, analizando syscalls (socket, clone, chmod, open).
- Integrar reglas YARA existentes (malware.yar, loaders.yar) como etapa complementaria.
- Generar reporte unificado con evidencias, risk_score y tipo de script detectado.

**Entregable:**
Analizador de scripts con detección estática por extensión, heurística de ofuscación, extracción de IOCs y ejecución dinámica con strace.

---

## Historia de Usuario HU30

**Nombre:** Análisis de cuerpo de correo (phishing)

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero analizar el cuerpo del correo en busca de phishing y suplantación para proteger al usuario de engaños.

**Criterios de Aceptación:**
- Detección de formularios de robo de credenciales.
- Detección de suplantación de marcas conocidas.
- Análisis de URLs sospechosas en el cuerpo.
- Detección de mismatch Reply-To vs From.
- Detección de lenguaje urgente o amenazante.

**Tareas técnicas:**
- Implementar body_analyzer con heurísticas de phishing.
- Analizar HTML del correo en busca de formularios.
- Detectar patrones de ingeniería social.

**Entregable:**
Analizador de cuerpo de correo con detección de phishing.

---

## Historia de Usuario HU31

**Nombre:** Verificación SPF/DKIM/DMARC

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como sistema de seguridad, quiero verificar SPF, DKIM y DMARC del remitente a partir del correo MIME crudo para validar la autenticidad del remitente.

**Criterios de Aceptación:**
- Verificación de registro SPF del dominio remitente usando los encabezados de Cloudflare.
- Verificación de firma DKIM directamente en los bytes del mensaje usando la clave pública DNS del emisor.
- Verificación de alineación de dominios para comprobar spoofing de remitente.
- Almacenamiento del veredicto final en `EmailAuthVerdict`.

**Tareas técnicas:**
- Extraer y verificar las firmas DKIM usando la biblioteca `dkim`.
- Parsear y evaluar los resultados de SPF y DMARC a partir de las cabeceras `Received-SPF` y `Authentication-Results` agregadas por Cloudflare durante el enrutamiento.
- Implementar la lógica de alineación de dominios (`dkim_domain` vs `sender_domain`) para determinar la legitimidad del remitente.
- Calcular el veredicto de autenticación (`verified`, `spoofed`, `unverified`) y almacenar los resultados en `EmailAuthVerdict`.

**Entregable:**
Verificación de autenticación de correo (SPF/DKIM/DMARC) procesada localmente sobre correos crudos.

---

## Historia de Usuario HU32

**Nombre:** Veredicto final con IA

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero un veredicto final con IA (Groq/Llama) que explique la amenaza para entender si debo confiar en el correo.

**Criterios de Aceptación:**
- Generación de explicación en lenguaje natural.
- Recomendación de acción (confiar/no confiar/revisar).
- Resumen de hallazgos del análisis.
- Fallback si la API de IA no responde.

**Tareas técnicas:**
- Integrar IA verdict en run_analysis.py.
- Construir prompt con todos los hallazgos del análisis.
- Procesar respuesta de la IA y almacenar en IAResult.
- Implementar fallback para cuando la API falla.

**Entregable:**
Veredicto final con explicación generada por IA.

---

## Historia de Usuario HU33

**Nombre:** Reporte visual de análisis

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como usuario autenticado, quiero ver un reporte visual completo con puntuación, evidencia agrupada por archivo, desbloqueo de ZIP protegidos, adjuntos colapsables ordenados por riesgo y análisis IA para revisar el análisis detallado de cada archivo.

**Criterios de Aceptación:**
- Puntuación de amenaza en anillo (score ring).
- Score card con filename que muestra hasta 2 adjuntos del score más alto (separados por coma si empatan) y "y N más".
- Listado de adjuntos ordenados de mayor a menor risk_score.
- Si hay más de 4 adjuntos, se muestran de a 4 con botón "Ver más"/"Ver menos".
- Grupos de evidencia en los archivos con password_protected aparecen primero, luego el resto en orden alfabético dentro de cada categoría.
- Botón "Desbloquear" en el file-group-header de cada archivo protegido.
- Modal para ingresar contraseña con toggle ojo/ocultar.
- Máximo 3 intentos de desbloqueo por sesión, expira a los 10 min.
- Si la contraseña es correcta se recarga completo el reporte con toast de éxito (django.contrib.messages) y se regenera el análisis IA.
- Listado de coincidencias YARA con detalles.
- Indicadores de compromiso (IOCs) extraídos.
- Análisis de Inteligencia Artificial con veredicto, confianza y consejo del analista.

**Tareas técnicas:**
- Implementar vista sandbox_report.html con diseño visual completo.
- Renderizar score ring con CSS/SVG.
- Implementar {% regroup %} para score card (top 2 + "y N más").
- Agregar dictsortreversed:"risk_score" en listado de adjuntos.
- Implementar collapsible-list JS con data-show="4" data-step="4".
- Modificar _group_evidence() para ordenar password_protected primero.
- Agregar botón "Desbloquear" + modal con toggle contraseña.
- Implementar sandbox_unlock_view() con rate limiting y re-análisis Docker.
- Integrar mensajes flash con django.contrib.messages y location.reload().
- Listar YARA matches con descripción y severidad.
- Integrar análisis IA con polling cada 3s.

**Entregable:**
Reporte visual completo de análisis sandbox con desbloqueo de comprimidos protegidos, adjuntos colapsables ordenados por riesgo y análisis de inteligencia artificial.

---

## Historia de Usuario HU34

**Nombre:** Coincidencia de reglas YARA

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero aplicar reglas YARA (malware, loaders, maldocs, exploits, webshells, ransomware, credstealers) a todos los archivos para detectar amenazas conocidas.

**Criterios de Aceptación:**
- 7 archivos de reglas YARA temáticos.
- Aplicación de todas las reglas a cada archivo.
- Reporte de coincidencias con metadatos.
- Reglas actualizables sin modificar código.

**Tareas técnicas:**
- Implementar yara_analyzer con compilación de reglas.
- Organizar reglas en archivos temáticos.
- Integrar con pipeline de análisis.

**Entregable:**
Motor YARA funcional con 7 categorías de reglas.

---

## Historia de Usuario HU35

**Nombre:** Descarga y análisis de archivos desde enlaces de Cloud Storage (Google Drive / Dropbox)

**Usuario:** Sistema (automático)

**Iteración asignada:** Iteración 3

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Alto

**Puntos Estimados:** 5

**Descripción:**
Como sistema de seguridad, quiero detectar y descargar automáticamente los archivos compartidos a través de enlaces de Google Drive o Dropbox en el cuerpo del correo, para analizarlos en el sandbox y evitar que se eluda la seguridad mediante enlaces externos.

**Criterios de Aceptación:**
- Detección de patrones de URLs de Google Drive (ej. `drive.google.com/file/d/...`) y Dropbox en el cuerpo del correo.
- Descarga automática de archivos mediante la API de Google Drive v3 (utilizando una Service Account configurada con la variable de entorno `GOOGLE_DRIVE_SERVICE_ACCOUNT`).
- Descarga de archivos de Dropbox mediante descarga directa.
- Límite máximo de tamaño de archivo a descargar (250 MB) para proteger recursos del sistema.
- Integración de los archivos descargados al pipeline de análisis de la Sandbox de la misma forma que los archivos adjuntos tradicionales.
- Prefijar el nombre del archivo descargado con `[cloud]_` para diferenciarlo en los reportes de análisis de la Sandbox.

**Tareas técnicas:**
- Implementar el módulo `cloud_downloader.py` para la detección de URLs y descarga de archivos.
- Configurar la autenticación OAuth2 de Google con Service Account para el cliente `google-api-python-client`.
- Agregar expresiones regulares para identificar enlaces de Google Drive y Dropbox.
- Modificar el flujo de recepción de correos para que, tras analizar el cuerpo con `body_analyzer`, invoque el descargador de URLs en la nube.
- Añadir los archivos descargados a la lista de adjuntos temporales analizados por `run_sandbox_analysis`.

**Entregable:**
Descarga e integración automática en el sandbox de archivos compartidos por enlaces de Google Drive y Dropbox detectados en el cuerpo del correo.

---

## Historia de Usuario HU36

**Nombre:** Dashboard de administración

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como administrador, quiero ver un dashboard con estadísticas globales del sistema para monitorear la plataforma.

**Criterios de Aceptación:**
- Número total de usuarios, alias, correos y amenazas.
- Gráficos de tendencias (nuevos usuarios, amenazas por día).
- Distribución de tipos de amenazas.
- Últimas actividades del sistema.

**Tareas técnicas:**
- Implementar stats_service con consultas agregadas.
- Crear vista admin_dashboard.html con gráficos.
- Implementar JavaScript para renderizar gráficos.

**Entregable:**
Dashboard administrativo con estadísticas y gráficos.

---

## Historia de Usuario HU37

**Nombre:** Gestión de usuario

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como administrador, quiero gestionar usuarios (listar, buscar, promover/revocar admins) para administrar el acceso al sistema.

**Criterios de Aceptación:**
- Listado paginado de todos los usuarios.
- Búsqueda por nombre de usuario o correo.
- Promoción de usuario a administrador.
- Revocación de permisos de administrador.
- Vista de detalle de usuario con sus alias y estadísticas.

**Tareas técnicas:**
- Implementar vistas admin_users.html y admin_user_detail.html.
- Implementar lógica de promoción/revocación en views.py.
- Agregar paginación y búsqueda.

**Entregable:**
Panel de gestión de usuarios con promoción/revocación de admins.

---

## Historia de Usuario HU38

**Nombre:** Moderación de aumento de cuota de alias

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como administrador, quiero moderar solicitudes de aumento de cuota de alias con un stepper para aprobar o rechazar peticiones.

**Criterios de Aceptación:**
- Listado de solicitudes pendientes.
- Interfaz tipo stepper para revisar solicitudes una por una.
- Aprobación con nuevo límite configurable.
- Rechazo con motivo opcional.
- Notificación al usuario del resultado.

**Tareas técnicas:**
- Implementar vista admin_alias_requests.html con stepper.
- Implementar lógica de aprobación/rechazo.
- Enviar notificación al usuario.

**Entregable:**
Moderación de solicitudes de cuota con interfaz stepper.

---

## Historia de Usuario HU39

**Nombre:** Gestión de solicitudes de recuperación de cuenta

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como administrador, quiero gestionar solicitudes de recuperación de cuenta para restablecer el acceso a usuarios legítimos.

**Criterios de Aceptación:**
- Listado de solicitudes de recuperación.
- Validación de identidad del solicitante.
- Aprobación o rechazo de la solicitud.
- Notificación al usuario del resultado.

**Tareas técnicas:**
- Implementar vista admin_account_recovery_requests.html.
- Verificar la identidad del solicitante.
- Implementar lógica de aprobación/rechazo.

**Entregable:**
Gestión de solicitudes de recuperación de cuenta.

---

## Historia de Usuario HU40

**Nombre:** Visión global de amenazas

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 5

**Descripción:**
Como administrador, quiero ver todas las amenazas del sistema con búsqueda y filtros para auditar la seguridad global.

**Criterios de Aceptación:**
- Listado paginado de todas las amenazas del sistema.
- Búsqueda por alias, tipo de amenaza, severidad.
- Filtros por estado y fecha.
- Vista de detalle de cada amenaza.
- Exportación de datos.

**Tareas técnicas:**
- Implementar vista admin_threats.html con filtros y búsqueda.
- Implementar consultas optimizadas con índices.

**Entregable:**
Panel global de amenazas con búsqueda y filtros.

---

## Historia de Usuario HU41

**Nombre:** Visión global de alias

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como administrador, quiero ver todos los alias del sistema con filtros de estado para auditar el uso de la plataforma.

**Criterios de Aceptación:**
- Listado paginado de todos los alias del sistema.
- Filtros por estado (activo, inactivo, eliminado).
- Búsqueda por etiqueta o usuario propietario.
- Estadísticas de uso por alias.

**Tareas técnicas:**
- Implementar vista admin_aliases.html con filtros.
- Agregar estadísticas de uso por alias.

**Entregable:**
Panel global de alias con filtros y estadísticas.

---

## Historia de Usuario HU42

**Nombre:** Panel de notificaciones

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 2

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 3

**Descripción:**
Como usuario autenticado, quiero recibir notificaciones en un panel de campana para estar al tanto de alertas y solicitudes.

**Criterios de Aceptación:**
- Icono de campana con contador de no leídas.
- Panel desplegable con últimas notificaciones.
- Listado completo de notificaciones paginado.
- Marcar como leída/no leída.
- Tipos de notificación: alertas, amenazas, solicitudes.

**Tareas técnicas:**
- Implementar modelo Notification con tipos.
- Implementar notificaciones.
- Crear panel desplegable con JavaScript.

**Entregable:**
Sistema de notificaciones con campana y listado completo.

---

## Historia de Usuario HU43

**Nombre:** Notificaciones toast del sistema

**Usuario:** Usuario autenticado

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Media

**Riesgo de Desarrollo:** Bajo

**Puntos Estimados:** 2

**Descripción:**
Como usuario autenticado, quiero ver notificaciones toast para mensajes del sistema para recibir feedback inmediato de mis acciones.

**Criterios de Aceptación:**
- Toast con animación de entrada/salida.
- Diferentes tipos: éxito, error, advertencia, información.
- Auto-dismiss después de tiempo configurable.
- Integración con mensajes de Django.

**Tareas técnicas:**
- Implementar sistema de toasts en JavaScript.
- Integrar con django_messages_toasts.js.
- Estilizar con CSS.

**Entregable:**
Sistema de toasts integrado con mensajes de Django.

---

## Historia de Usuario HU44

**Nombre:** Notificación única al administrador al bloquear cuenta

**Usuario:** Administrador

**Iteración asignada:** Iteración 4

**Prioridad en Negocio:** Alta

**Riesgo de Desarrollo:** Medio

**Puntos Estimados:** 3

**Descripción:**
Como administrador, quiero recibir una sola notificación cuando un usuario es bloqueado por intentos repetidos de malware, con el detalle completo de ambos intentos, para tener un registro completo del incidente sin notificaciones redundantes.

**Criterios de Aceptación:**
- No se envía notificación en la 1ª ofensa, solo advertencia al usuario.
- En la 2ª ofensa, el bloqueo se envía una notificación al administrador.
- La notificación incluye el detalle de ambos intentos, advertencia y detalle del bloqueo de la cuenta.
- El título de la notificación es "Cuenta bloqueada por intento de adjuntar malware".
- La notificación es de tipo system, status pending.
- La notificación describe los datos del primer intento y el segundo.
- Al desbloquear al usuario, se limpian sus intentos.

**Tareas técnicas:**
- Modificar _notify_admin_attachment_abuse para recibir y formatear ambos intentos.
- Guardar datos del 1er intento en malicious_attempt_data.
- Al aceptar el desbloqueo limpiar los intentos del usuario.

**Entregable:**
Una notificación por incidente con trazabilidad completa de ambos intentos.
