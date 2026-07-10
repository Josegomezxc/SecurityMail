# Requisitos

## Requisitos Funcionales

### R.F. 01

**Nombre:** Gestión de Registro, Autenticación, Perfiles, Temas Visuales y Estado de Cuenta

**Descripción:**
El sistema debe permitir el registro seguro de usuarios mediante verificación en dos pasos (código temporal enviado por correo electrónico con rate limiting). Soportará el inicio de sesión con protección anti-fuerza bruta basado en bloqueos de IP (tras 3 intentos fallidos) y control estricto de sesión única activa. Proveerá un mecanismo autónomo de recuperación de contraseña mediante un token temporal, la administración avanzada del perfil del usuario (edición de contraseña, avatar y configuración de correo real) y el proceso de eliminación definitiva de la cuenta validado bajo el flujo de dos pasos. Adicionalmente, el sistema permitirá personalizar la apariencia de la interfaz seleccionando diferentes temas visuales (Claro, Oscuro, Carbón) persistidos localmente. El backend aplicará un middleware que evaluará el estado de la cuenta, impidiendo el inicio de sesión o destruyendo las sesiones de forma inmediata si el usuario es desactivado por reincidencia en malware.

**Requerimientos No Funcionales:** R.N.F. 01, R.N.F. 04

**Importancia:** Alta

---

### R.F. 02

**Nombre:** Gestión, Ciclo de Vida y Destrucción de Alias con IA

**Descripción:**
El sistema debe permitir la creación de alias de correo electrónico temporales limitados inicialmente a una cuota máxima predefinida por defecto de 5. Incorporará un asistente de inteligencia artificial (API de Groq) para la generación de nombres contextuales y creativos basados en un prompt introducido por el usuario en español, con un mecanismo de fallback automático al idioma inglés. Adicionalmente, el usuario tendrá la capacidad de destruir de forma definitiva los alias creados aplicando un borrado lógico (soft-delete), lo cual cesará inmediatamente la recepción de tráfico hacia ellos y mantendrá bloqueada la dirección para evitar reusos. Permitirá también enviar solicitudes formales de incremento de cuota al administrador.

**Requerimientos No Funcionales:** R.N.F. 03, R.N.F. 04, R.N.F. 05

**Importancia:** Alta

---

### R.F. 03

**Nombre:** Core de Mensajería, Navegación de Bandejas, Reenvío y Control de Adjuntos

**Descripción:**
El sistema capturará de forma automatizada los correos entrantes a través de un webhook alimentado por Cloudflare Email Routing y un Cloudflare Worker que transferirá el mensaje crudo en formato raw MIME (RFC 822), mientras que el envío de correos salientes se gestionará a través de la API de Resend. El backend sanitizará estrictamente el HTML del correo (removiendo enlaces, scripts e inyecciones de código) para renderizarlos en una vista de lectura segura dentro de un iframe aislado. Clasificará los mensajes en una bandeja de entrada paginada y gestionará interfaces de detalle de correo, elementos enviados, borradores automáticos en edición y una papelera con retención física temporal de 30 días. Soportará la redacción y envío de mensajes salientes con archivos adjuntos y la configuración de reenvío seguro hacia la dirección de correo real. Durante la carga de archivos adjuntos en el cliente, el sistema interceptará síncronamente el archivo enviándolo al endpoint de escaneo; deshabilitará el botón de envío y mostrará indicadores visuales dinámicos de carga hasta resolver su estado.

**Requerimientos No Funcionales:** R.N.F. 01, R.N.F. 04, R.N.F. 05

**Importancia:** Alta

---

### R.F. 04

**Nombre:** Infraestructura de Sandbox y Mitigación Progresiva de Ofensas

**Descripción:**
El sistema orquestará las políticas de mitigación perimetral de amenazas basándose estrictamente en el score de riesgo arrojado por el entorno aislado de pruebas. Si el archivo es evaluado como sospechoso (score > 30 y score < 60), interrumpirá la carga de forma pasiva, rechazando el adjunto y notificando al usuario mediante un toast de advertencia. Si representa una primera ofensa maliciosa (score > 60), desplegará un modal crítico de advertencia, bloqueará el archivo e incrementará el contador persistente de ofensas a 1. Ante una segunda ofensa maliciosa (score > 60), desactivará automáticamente la cuenta de usuario (user.is_active = False), registrará la marca de tiempo del baneo definitivo, destruirá la sesión activa y bloqueará la interfaz de forma persistente con un modal que mostrará un countdown de 1 minuto antes de redirigir.

**Requerimientos No Funcionales:** R.N.F. 01

**Importancia:** Alta

---

### R.F. 05

**Nombre:** Pipeline de Análisis Heurístico y Multiformato de Malware de Sandbox

**Descripción:**
El backend instanciará de forma automatizada entornos aislados (contenedores Docker) de solo lectura y sin acceso a la red interna o externa (--network none) para procesar archivos adjuntos sospechosos. Adicionalmente, el sistema analizará el cuerpo de los correos buscando enlaces a proveedores de Cloud Storage (Google Drive y Dropbox), y descargará automáticamente los archivos correspondientes (usando la API de Google Drive v3 con Service Account o descarga directa de Dropbox) para someterlos al mismo pipeline. El pipeline ejecutará análisis estáticos y heurísticos multiformato: calculará índices de entropía y detectará packers sobre ejecutables binarios (PE/ELF); auditará y extraerá macros embebidas o scripts VBA en documentos de Microsoft Office; descomprimirá streams internos y localizará JavaScript interactivo o acciones automáticas sospechosas en archivos PDF. Incluirá rutinas de extracción recursiva de archivos comprimidos (.zip, .rar) controlando de forma estricta los límites de profundidad y ratios de descompresión para neutralizar ataques zip-bomb. Asimismo, rastreará scripts de automatización (.ps1, .sh, .bat) mediante herramientas de análisis dinámico controlado (strace) en el entorno de pruebas.

**Requerimientos No Funcionales:** R.N.F. 01

**Importancia:** Alta

---

### R.F. 06

**Nombre:** Auditoría de Red, Cabeceras y Motor de Firmas YARA

**Descripción:**
El sistema debe inspeccionar el cuerpo de los mensajes aplicando analizadores heurísticos avanzados para identificar lenguaje urgente, enlaces maliciosos e ingeniería social enfocada al phishing. Asimismo, parseará las cabeceras de red del correo entrante (incluyendo las cabeceras inyectadas por Cloudflare) para auditar las firmas y autenticaciones criptográficas del remitente original, validando la firma DKIM localmente sobre los bytes del mensaje y verificando rigurosamente los registros SPF, DKIM y DMARC. Adicionalmente, el sistema compilará localmente 7 archivos temáticos de reglas YARA para contrastar firmas de malware conocido sobre los archivos adjuntos analizados en el pipeline.

**Requerimientos No Funcionales:** R.N.F. 01, R.N.F. 02

**Importancia:** Alta

---

### R.F. 07

**Nombre:** Orquestación de Veredictos por IA y Reportes de Compromiso

**Descripción:**
El sistema agrupará los hallazgos técnicos estructurados y los logs generados por todos los motores de análisis y los someterá a prompts optimizados en la API de Groq (Llama) para generar un veredicto final contextualizado, comprensible, legible y traducido al español, sugiriendo acciones recomendadas y activando un fallback local en caso de error de conexión. El resultado final del análisis y el desglose de los Indicadores de Compromiso (IOCs) se maquetarán para el usuario en una interfaz de reporte visual gráfico, animado e interactivo con anillos de puntuación SVG y líneas de tiempo del incidente.

**Requerimientos No Funcionales:** R.N.F. 03, R.N.F. 05

**Importancia:** Media

---

### R.F. 08

**Nombre:** Panel de Administración, Moderación, Telemetría y Soporte de Cuentas

**Descripción:**
Suministrar un panel administrativo centralizado con métricas y gráficos interactivos que muestren el volumen total de amenazas interceptadas, su distribución diaria y el uso globalizado de los alias en la plataforma. Incluirá herramientas operativas para gestionar usuarios (buscar, listar, suspender y promover/revocar roles de administrador). Proveerá una interfaz en formato stepper dinámico para evaluar, aprobar o denegar las solicitudes de ampliación de cuotas de alias, así como un flujo de soporte técnico exclusivo para procesar solicitudes de recuperación de cuentas bloqueadas, validando la identidad del usuario para restablecer los contadores de reincidencia de malware y limpiar su historial de intentos de abuso.

**Requerimientos No Funcionales:** R.N.F. 01, R.N.F. 04, R.N.F. 05

**Importancia:** Alta

---

### R.F. 09

**Nombre:** Centro Operativo de Notificaciones, Alertas Forenses y Toasts

**Descripción:**
El sistema centralizará las notificaciones internas de los usuarios en tiempo real mediante un panel desplegable integrado bajo un icono de campana con burbuja de contadores reactiva. Incluirá un componente transversal de mensajes emergentes inmediatos (notificaciones toast) vinculados a los mensajes del sistema para otorgar feedback animado ante el éxito, error o advertencia de las acciones realizadas. Además, proveerá al administrador un centro global de auditoría para buscar y filtrar amenazas y alias creados mediante interfaces paginadas con carga eficiente. Ante un baneo definitivo por segunda ofensa en DockerShield, el backend interceptará el evento e inyectará automáticamente una notificación forense única de tipo system con estado pending en el panel de todos los administradores activos, consolidando cronológicamente el nombre de los archivos, scores y amenazas de ambos intentos en una única alerta consolidada sin duplicar notificaciones.

**Requerimientos No Funcionales:** R.N.F. 04, R.N.F. 05

**Importancia:** Media

---

## Requisitos No Funcionales

### R.N.F. 01

**Nombre:** Seguridad de la Información y Aislamiento de Red

**Descripción:**
Toda ejecución de archivos sospechosos debe ocurrir dentro de contenedores estricta y lógicamente separados de la red de producción, con el aislamiento absoluto de red (--network none) e inmutabilidad de archivos habilitados. Los datos sensibles del usuario (sesiones y contraseñas) deben encriptarse empleando algoritmos de derivación de claves robustos de Django.

**Importancia:** Alta

---

### R.N.F. 02

**Nombre:** Tolerancia a Fallos ante Errores de Sintaxis en Reglas Locales

**Descripción:**
El pipeline de análisis del sistema debe poseer alta tolerancia a fallos de configuración interna. Si alguna de las reglas YARA locales almacenadas en el servidor presenta un error de sintaxis, corrupción de archivo o fallo de inicialización en desarrollo o producción, el sistema debe aislar el error, omitir la regla defectuosa y continuar con la ejecución del resto del análisis. Bajo ninguna circunstancia un fallo de sintaxis local provocará una excepción no controlada (crash) que interrumpa la estabilidad del servidor web.

**Importancia:** Alta

---

### R.N.F. 03

**Nombre:** Disponibilidad, Tolerancia a Fallos y Mecanismos de Fallback de la IA

**Descripción:**
El consumo de las APIs externas (Groq, Resend, Google Drive) debe incorporar políticas estrictas de tolerancia a fallos. Si el servicio de inteligencia artificial, de mensajería o de descarga en la nube no responde en un tiempo límite o falla su disponibilidad, el sistema activará un fallback automático local (veredictos estáticos estructurados o heurísticas idiomáticas alternativas) para asegurar la continuidad del servicio.

**Importancia:** Alta

---

### R.N.F. 04

**Nombre:** Usabilidad, Diseño Responsivo y UX Seguro (Anti-XSS)

**Descripción:**
La interfaz de usuario debe desarrollarse siguiendo principios de diseño limpio, responsivo y seguro. La renderización de correos electrónicos bajo formato HTML debe ser neutralizada y sanitizada estrictamente en el backend para prevenir de raíz vulnerabilidades de Cross-Site Scripting (XSS) u otras inyecciones de código antes de pintarse de forma aislada en el navegador.

**Importancia:** Alta

---

### R.N.F. 05

**Nombre:** Concurrencia y Optimización de Consultas de Datos

**Descripción:**
El sistema estará optimizado a nivel de índices y restricciones en la base de datos para manejar volúmenes masivos de registros de logs de amenazas, incidentes de DockerShield y alias creados. Esto permitirá que las consultas de telemetría, filtrados del administrador y las notificaciones en tiempo real del usuario se completen en tiempos mínimos sin degradar el rendimiento del servidor.

**Importancia:** Media
