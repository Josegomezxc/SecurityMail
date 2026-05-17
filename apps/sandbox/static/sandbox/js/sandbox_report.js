/* ══════════════════════════════════════════════════════════════════════
   SISTEMA DE AYUDA "¿QUÉ ES?"
   Cada botón <button class="help-btn" data-help="key"> abre un modal con
   una explicación en lenguaje claro de qué significa lo que se detectó.
   ══════════════════════════════════════════════════════════════════════ */

const HELP_TEXTS = {
    // ── Campos de identificación del archivo ────────────────────────
    mime_real: {
        title: 'Tipo MIME real',
        body: 'El tipo MIME real es el formato verdadero del archivo, detectado leyendo sus primeros bytes (su "firma"), NO la extensión. Esto es importante porque los atacantes a veces ponen una extensión falsa (ej: factura.pdf) a un archivo que en realidad es de otro tipo (ej: un ejecutable .exe). Si la extensión y el MIME real no coinciden, el correo es muy sospechoso.'
    },
    extension: {
        title: 'Extensión del archivo',
        body: 'La extensión es la parte final del nombre del archivo (.pdf, .exe, .zip, etc.) que indica qué tipo de archivo es. Algunas extensiones como .exe, .scr, .bat o .vbs son siempre peligrosas porque pueden ejecutar código. Otras como .pdf o .docx son normales pero pueden contener exploits si vienen de fuentes no confiables.'
    },
    size: {
        title: 'Tamaño del archivo',
        body: 'El tamaño en bytes del archivo. Es un indicador útil: archivos muy chicos (< 1 KB) con extensión ejecutable suelen ser droppers (descargan malware más grande). Archivos sospechosamente grandes (> 50 MB) pueden ser intentos de evadir antivirus que omiten archivos enormes.'
    },
    sha256: {
        title: 'Hash SHA-256',
        body: 'El hash SHA-256 es como una "huella digital" única del archivo. Si dos archivos tienen el mismo SHA-256, son idénticos byte por byte. Sirve para identificar amenazas conocidas: si este hash coincide con uno reportado en bases públicas como VirusTotal, significa que ya alguien analizó este mismo archivo antes y lo identificó como malicioso.'
    },
    md5: {
        title: 'Hash MD5',
        body: 'El hash MD5 es similar al SHA-256 pero más corto y más viejo. Se incluye por compatibilidad con bases de datos antiguas de antivirus. Para verificación de seguridad real se prefiere el SHA-256.'
    },

    // ── Secciones generales ────────────────────────────────────────
    evidence_section: {
        title: 'Evidencia detectada',
        body: 'Lista de TODO lo que el sandbox encontró sospechoso en el archivo y el correo. Cada item tiene un nivel de severidad (CRÍTICO, ALTO, MEDIO, BAJO o INFO) y un score numérico. El score más alto define el nivel de riesgo total del correo.'
    },
    iocs: {
        title: 'Indicadores de Compromiso (IOCs)',
        body: 'Los IOCs son evidencias técnicas extraídas del análisis que pueden compartirse con otros equipos de seguridad. Incluyen URLs, dominios, direcciones IP y hashes que aparecieron dentro del archivo o del correo. Si alguno aparece en listas negras públicas, es evidencia fuerte de amenaza. Son útiles para investigaciones forenses.'
    },
    iocs_urls: {
        title: 'URLs detectadas',
        body: 'Todas las direcciones web que aparecen en el correo o sus adjuntos. URLs sospechosas pueden llevar a páginas de phishing (que imitan login de bancos, Gmail, etc.) o a sitios que descargan malware automáticamente al visitarlas.'
    },
    iocs_ips: {
        title: 'Direcciones IP detectadas',
        body: 'Direcciones IP (números que identifican servidores en Internet) encontradas en el correo. Aparecer una IP directa en lugar de un dominio normal (ej: http://192.168.x.x/login) es muy sospechoso — las empresas legítimas casi siempre usan dominios con nombre.'
    },
    iocs_domains: {
        title: 'Dominios detectados',
        body: 'Los dominios (sin la parte de la URL) extraídos del correo. Útil para verificar reputación: dominios recién registrados o con typo-squatting (ej: paypa1.com en lugar de paypal.com) son banderas rojas.'
    },
    iocs_hashes: {
        title: 'Hashes detectados',
        body: 'Identificadores únicos de archivos analizados. Si compartís estos hashes con un equipo de seguridad o los buscás en VirusTotal, podrías encontrar reportes de otros incidentes con el mismo archivo.'
    },
    body_analysis: {
        title: 'Análisis del cuerpo del correo',
        body: 'Análisis del contenido del correo (el HTML/texto del mensaje, no los adjuntos). Detecta: URLs ofuscadas, HTML peligroso (formularios falsos, iframes ocultos), lenguaje de phishing ("URGENTE", "verifique su cuenta"), pixels de tracking, y headers manipulados.'
    },
    yara_matches: {
        title: 'Coincidencias con reglas YARA',
        body: 'YARA es un motor de detección que busca patrones específicos en archivos. Las reglas las escribió nuestro equipo y la comunidad de seguridad para identificar familias conocidas de malware. Si tu archivo coincide con una regla, significa que se parece técnicamente a alguna amenaza ya documentada.'
    },

    // ── Tipos de evidencia (ev.type del modelo) ────────────────────
    // Los más comunes en correo
    url_excessive_length: {
        title: 'URL muy larga',
        body: 'Una URL legítima rara vez supera los 100 caracteres. URLs muy largas (300+ caracteres) son usadas por atacantes para esconder el dominio real: meten cientos de subdominios falsos o codifican datos extra. También se usan para que el usuario no vea bien a dónde va al pasar el cursor por encima.'
    },
    url_ip_address: {
        title: 'URL con IP directa',
        body: 'La URL apunta a una dirección IP cruda (ej: http://192.168.x.x) en lugar de un dominio (ej: tienda.com). Las empresas legítimas SIEMPRE usan dominios con nombre. Una IP directa es típica de servidores comprometidos o de infraestructura de atacantes que cambia constantemente.'
    },
    url_suspicious_tld: {
        title: 'Dominio con TLD raro',
        body: 'El dominio termina en un TLD (sufijo) sospechoso: .tk, .ml, .ga, .cf, .top, .xyz son gratis o muy baratos, así que los usan masivamente para campañas de phishing. Empresas serias casi siempre usan .com, .org, .net o el país (.es, .ar, .mx, etc.).'
    },
    html_tracking_pixel: {
        title: 'Pixel de seguimiento (tracking pixel)',
        body: 'Es una imagen invisible de 1x1 píxel embebida en el HTML del correo. Cuando abrís el correo, tu cliente descarga la imagen y el remitente se entera de que lo abriste (y desde qué IP, dispositivo, hora). Lo usan marketers para spam y también atacantes para confirmar que el correo es válido antes de seguir atacándote.'
    },
    html_form: {
        title: 'Formulario embebido en HTML',
        body: 'El correo contiene un formulario (<form>) dentro del HTML. Los correos legítimos casi nunca incluyen formularios — te llevan a una página web aparte. Un formulario embebido suele ser intento de robar credenciales: te pide usuario/clave directamente en el correo y manda los datos a un servidor del atacante.'
    },
    html_iframe: {
        title: 'iframe oculto',
        body: 'El correo tiene un <iframe>: una "ventana" dentro del HTML que carga contenido de otro sitio. Los iframes ocultos (con tamaño 0 o estilo display:none) cargan exploits silenciosamente cuando abrís el correo, sin que vos veas nada.'
    },
    phishing_language: {
        title: 'Lenguaje típico de phishing',
        body: 'El cuerpo del correo contiene frases que aparecen casi exclusivamente en correos de estafa: "URGENTE", "verifique su cuenta antes de 24 horas", "su cuenta será suspendida", "haga clic aquí para evitar el bloqueo", etc. Esto crea presión psicológica para que actúes sin pensar.'
    },
    auth_verified: {
        title: 'Autenticación DKIM/SPF/DMARC verificada',
        body: 'El correo pasó las verificaciones técnicas de autenticidad (DKIM, SPF y/o DMARC). Esto significa que REALMENTE viene del dominio que dice ser y nadie lo falsificó. Es una señal positiva, así que reducimos el score de amenaza. Igual el dominio en sí podría ser malicioso (no significa "seguro", solo "no falsificado").'
    },
    auth_failed: {
        title: 'Autenticación DKIM/SPF/DMARC fallida',
        body: 'El correo NO pasó las verificaciones de autenticidad. Esto suele significar spoofing: alguien está mandando un correo haciéndose pasar por otro dominio (típicamente bancos, redes sociales, jefes, etc.). Es una señal muy fuerte de phishing.'
    },

    // ── Tipos YARA ────────────────────────────────────────────────
    yara_test_signature: {
        title: 'Firma YARA: archivo de prueba (EICAR)',
        body: 'Coincide con la firma EICAR, un archivo estándar de pruebas usado por la industria de antivirus. NO es malicioso, pero está diseñado para ser detectado por TODO motor de seguridad como validación de que funciona. Si ves esto, probablemente alguien envió EICAR a propósito para probar el sandbox.'
    },
    yara_loader: {
        title: 'Firma YARA: loader/dropper',
        body: 'El archivo coincide con patrones típicos de un loader (cargador): un programa pequeño cuya única función es descargar y ejecutar OTRO malware más grande desde Internet. Los loaders son comunes en campañas porque son fáciles de adaptar a diferentes payloads.'
    },
    yara_ransomware: {
        title: 'Firma YARA: ransomware',
        body: 'El archivo coincide con patrones de ransomware (programa que cifra tus archivos y pide rescate para devolvértelos). Las firmas detectan funciones de cifrado en bulk, generación de notas de rescate, comunicación con servidores C&C, etc.'
    },
    yara_webshell: {
        title: 'Firma YARA: webshell',
        body: 'Coincide con patrones de webshell (script malicioso que se sube a un servidor web comprometido). Una vez instalado, el atacante puede ejecutar comandos en ese servidor como si tuviera SSH. Si llegó por correo, probablemente alguien intenta convencer a un admin de subirlo a su servidor.'
    },
    yara_phish: {
        title: 'Firma YARA: phishing',
        body: 'El archivo coincide con patrones usados en kits de phishing (páginas falsas de login). Suelen aparecer como HTML adjunto que imita Gmail, Office 365, bancos, etc. Cuando el usuario "inicia sesión", las credenciales se mandan al atacante.'
    },

    // ── Macros y exploits Office ──────────────────────────────────
    vba_macro: {
        title: 'Macro VBA detectada',
        body: 'El documento Office (Word, Excel, etc.) contiene macros: código VBA que se ejecuta automáticamente al abrir el archivo. Las macros legítimas existen, pero los atacantes las usan para descargar e instalar malware. Por defecto Microsoft Office bloquea macros de archivos descargados, pero muchos usuarios habilitan "Editar contenido" sin darse cuenta del riesgo.'
    },
    vba_autoexec: {
        title: 'Macro con auto-ejecución',
        body: 'La macro VBA se ejecuta SOLA al abrir el documento (sin que el usuario haga nada). Funciones como AutoOpen, Document_Open o Workbook_Open son las usadas. Esto es prácticamente exclusivo de malware: un documento legítimo rara vez necesita ejecutar código apenas se abre.'
    },
    vba_shellexec: {
        title: 'Macro que ejecuta procesos del sistema',
        body: 'La macro VBA llama a Shell(), CreateObject("WScript.Shell"), o equivalentes — todas son APIs para ejecutar programas del sistema operativo desde el documento. Es exactamente lo que hace un dropper: el documento sirve como "carcasa", la macro descarga el malware real y lo ejecuta.'
    },
    dde_in_office: {
        title: 'DDE en documento Office',
        body: 'DDE (Dynamic Data Exchange) es una técnica vieja de Office que permite ejecutar comandos sin macros. Microsoft lo desactivó por defecto en 2017 porque se usaba para malware, pero documentos viejos o usuarios con configuraciones laxas siguen siendo vulnerables.'
    },
    follina: {
        title: 'Exploit Follina (CVE-2022-30190)',
        body: 'Coincide con patrones del exploit Follina: una vulnerabilidad en MS Office que permite ejecutar código solo con que el usuario vea el preview del documento (sin abrirlo). Es una de las técnicas más peligrosas de los últimos años. Si tu Office está actualizado estás protegido, pero igual conviene NO abrir el archivo.'
    },

    // ── Hashes / extensión / análisis estructural ─────────────────
    double_extension: {
        title: 'Doble extensión engañosa',
        body: 'El archivo tiene dos extensiones: "factura.pdf.exe", "foto.jpg.scr", etc. El truco es que Windows oculta la extensión final por defecto, así que ves solo "factura.pdf" y pensás que es un PDF. En realidad es un ejecutable que correrá al abrirlo. Es uno de los engaños más viejos y efectivos del phishing.'
    },
    extension_spoof: {
        title: 'Extensión engañosa',
        body: 'La extensión del archivo NO coincide con su tipo real. Por ejemplo: "informe.pdf" que en realidad es un .exe (ejecutable) o un .html (página web). El sandbox detecta esto leyendo los primeros bytes del archivo, no confiando en la extensión.'
    },
    dangerous_extension: {
        title: 'Extensión siempre peligrosa',
        body: 'La extensión del archivo (.exe, .scr, .vbs, .bat, .ps1, .hta, etc.) es de las que ejecutan código directamente. Casi nunca debería llegarte por correo desde un remitente legítimo. Si lo recibís de alguien conocido, confirmá por otro canal antes de abrirlo (su cuenta podría estar comprometida).'
    },

    // ── Análisis dinámico (strace dentro del contenedor) ─────────
    dynamic_network: {
        title: 'Conexión de red durante ejecución',
        body: 'El archivo intentó conectarse a un servidor remoto al ejecutarse en el sandbox. Software legítimo a veces lo hace (chequear actualizaciones, telemetría), pero también es la forma en que malware se comunica con su servidor de control (C&C) para recibir órdenes o exfiltrar datos.'
    },
    dynamic_process: {
        title: 'Proceso lanzado durante ejecución',
        body: 'El archivo lanzó otro proceso (programa) durante su ejecución. Comunes en malware: lanzar PowerShell, cmd.exe, wscript.exe o conhost.exe son banderas. El sandbox capturó la llamada usando strace dentro del contenedor aislado.'
    },
    dynamic_file_write: {
        title: 'Escritura de archivo durante ejecución',
        body: 'El archivo escribió otro archivo en disco al ejecutarse. Comportamiento típico de droppers: ellos mismos son pequeños y "sueltan" el malware real cuando se ejecutan. El sandbox lo captura via strace.'
    },
    dynamic_chmod: {
        title: 'Cambio de permisos durante ejecución',
        body: 'El archivo modificó los permisos (chmod) de otro archivo, típicamente para hacerlo ejecutable. Es uno de los pasos clave del flujo "descargar → marcar como ejecutable → correr" de muchos malware.'
    },

    // ── Errores ───────────────────────────────────────────────────
    analyzer_error: {
        title: 'Error en un analizador',
        body: 'Uno de los componentes del sandbox falló (no pudo analizar este aspecto). No es una amenaza por sí mismo, pero significa que ese análisis específico no se completó. El score global considera solo los análisis exitosos.'
    },
    hash_error: {
        title: 'Error calculando el hash',
        body: 'No se pudo calcular el hash del archivo (probablemente está corrupto o vacío). Sin hash no podemos comparar con bases de datos de amenazas conocidas, pero los otros análisis igual se ejecutan.'
    },
};

// SVG icons usados dentro del modal (sin emojis)
const _ICON_FOUND = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
const _ICON_MEANS = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M2 12a10 10 0 1 1 20 0c0 3.5-2 5-3 7H5c-1-2-3-3.5-3-7z"/></svg>';
const _ICON_AI    = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';

// Estado del modal — para prevenir clicks múltiples
const _HELP_STATE = {
    isLoading: false,        // ¿hay una petición en vuelo?
    activeKey: null,         // qué key se está mostrando ahora
    currentAbort: null,      // controller para cancelar fetch si cerrás el modal
};

function _csrfToken() {
    const m = document.cookie.match(/csrftoken=([^;]+)/);
    return m ? m[1] : '';
}

function _ensureHelpModal() {
    let modal = document.getElementById('helpModal');
    if (modal) return modal;
    modal = document.createElement('div');
    modal.id = 'helpModal';
    modal.className = 'help-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-hidden', 'true');
    modal.innerHTML = `
        <div class="help-modal-card">
            <header class="help-modal-head">
                <div class="help-modal-icon" aria-hidden="true">?</div>
                <h3 class="help-modal-title" id="helpModalTitle"></h3>
                <span class="help-modal-source" id="helpModalSource" hidden></span>
                <button type="button" class="help-modal-close" id="helpModalClose" aria-label="Cerrar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                    </svg>
                </button>
            </header>
            <div class="help-modal-body" id="helpModalBody"></div>
        </div>
    `;
    document.body.appendChild(modal);

    // Close handlers
    modal.querySelector('#helpModalClose').addEventListener('click', _closeHelpModal);
    modal.addEventListener('click', function (e) {
        if (e.target === modal) _closeHelpModal();
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && modal.classList.contains('visible')) _closeHelpModal();
    });
    return modal;
}

function _renderHelpStatic(title, body) {
    const titleEl  = document.getElementById('helpModalTitle');
    const bodyEl   = document.getElementById('helpModalBody');
    const sourceEl = document.getElementById('helpModalSource');
    titleEl.textContent = title;
    sourceEl.hidden = true;
    sourceEl.textContent = '';
    bodyEl.innerHTML = `
        <div class="help-section">
            <div class="help-section-icon">${_ICON_MEANS}</div>
            <div class="help-section-text">${_escapeHtml(body)}</div>
        </div>
    `;
}

function _renderHelpLoading(title) {
    const titleEl  = document.getElementById('helpModalTitle');
    const bodyEl   = document.getElementById('helpModalBody');
    const sourceEl = document.getElementById('helpModalSource');
    titleEl.textContent = title;
    sourceEl.hidden = true;
    bodyEl.innerHTML = `
        <div class="help-loading">
            <div class="help-spinner" aria-hidden="true"></div>
            <div class="help-loading-text">Generando explicación para este indicador…</div>
        </div>
    `;
}

function _renderHelpDynamic(title, found, means, source) {
    const titleEl  = document.getElementById('helpModalTitle');
    const bodyEl   = document.getElementById('helpModalBody');
    const sourceEl = document.getElementById('helpModalSource');
    titleEl.textContent = title;

    // Badge "IA" cuando vino de Groq, sin badge cuando es cache (al usuario
    // no le importa si fue cache o no, pero igual marcamos que es IA).
    sourceEl.hidden = false;
    sourceEl.innerHTML = _ICON_AI + '<span>Explicado por IA</span>';

    const parts = [];
    if (found) {
        parts.push(`
            <div class="help-section help-section--found">
                <div class="help-section-icon">${_ICON_FOUND}</div>
                <div class="help-section-text">
                    <div class="help-section-label">Qué encontró en este correo</div>
                    <div class="help-section-body">${_escapeHtml(found)}</div>
                </div>
            </div>
        `);
    }
    if (means) {
        parts.push(`
            <div class="help-section">
                <div class="help-section-icon">${_ICON_MEANS}</div>
                <div class="help-section-text">
                    <div class="help-section-label">Qué significa</div>
                    <div class="help-section-body">${_escapeHtml(means)}</div>
                </div>
            </div>
        `);
    }
    if (!parts.length) {
        parts.push('<div class="help-section-text">La IA no pudo generar una explicación. Probá de nuevo en un momento.</div>');
    }
    bodyEl.innerHTML = parts.join('');
}

function _renderHelpError(title, message) {
    const titleEl  = document.getElementById('helpModalTitle');
    const bodyEl   = document.getElementById('helpModalBody');
    const sourceEl = document.getElementById('helpModalSource');
    titleEl.textContent = title;
    sourceEl.hidden = true;
    bodyEl.innerHTML = `
        <div class="help-error">${_escapeHtml(message)}</div>
    `;
}

function _escapeHtml(s) {
    return String(s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function _fetchExplanation(key, detail, signal) {
    const resp = await fetch('/sandbox/api/explain/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken':  _csrfToken(),
            'Accept':       'application/json',
        },
        body: JSON.stringify({ type: key, detail: detail || '' }),
        signal: signal,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
        const msg = data.error || `Error ${resp.status} al pedir la explicación`;
        throw new Error(msg);
    }
    return data;
}

function _openHelpModal(key, contextDetail) {
    // Si ya se está mostrando ESTA misma key, no hacemos nada
    if (_HELP_STATE.activeKey === key && _HELP_STATE.isLoading) return;
    if (_HELP_STATE.activeKey === key) {
        // Mismo key pero ya cargado: solo reabrir si está cerrado
        const m = document.getElementById('helpModal');
        if (m && m.classList.contains('visible')) return;
    }
    // Cancelar petición previa si hay
    if (_HELP_STATE.currentAbort) {
        try { _HELP_STATE.currentAbort.abort(); } catch (e) {}
        _HELP_STATE.currentAbort = null;
    }

    const modal = _ensureHelpModal();
    _HELP_STATE.activeKey = key;
    modal.setAttribute('aria-hidden', 'false');
    requestAnimationFrame(function () { modal.classList.add('visible'); });
    document.body.style.overflow = 'hidden';

    // 1. Caso diccionario fijo → respuesta INSTANTÁNEA, sin llamada de red
    if (HELP_TEXTS[key]) {
        _renderHelpStatic(HELP_TEXTS[key].title, HELP_TEXTS[key].body);
        return;
    }

    // 2. Caso fallback IA → loading + fetch
    const niceTitle = (key || 'indicador').replace(/_/g, ' ');
    _renderHelpLoading(niceTitle);

    _HELP_STATE.isLoading = true;
    const ctrl = new AbortController();
    _HELP_STATE.currentAbort = ctrl;

    _fetchExplanation(key, contextDetail, ctrl.signal)
        .then(function (data) {
            // Verificamos que el usuario no haya cerrado el modal y abierto otro
            if (_HELP_STATE.activeKey !== key) return;
            _renderHelpDynamic(niceTitle, data.found, data.means, data.source);
        })
        .catch(function (err) {
            if (err.name === 'AbortError') return;
            if (_HELP_STATE.activeKey !== key) return;
            _renderHelpError(niceTitle, err.message || 'No se pudo cargar la explicación.');
        })
        .finally(function () {
            if (_HELP_STATE.currentAbort === ctrl) {
                _HELP_STATE.currentAbort = null;
                _HELP_STATE.isLoading = false;
            }
        });
}

function _closeHelpModal() {
    const modal = document.getElementById('helpModal');
    if (!modal) return;
    modal.classList.remove('visible');
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    _HELP_STATE.activeKey = null;
    if (_HELP_STATE.currentAbort) {
        try { _HELP_STATE.currentAbort.abort(); } catch (e) {}
        _HELP_STATE.currentAbort = null;
    }
    _HELP_STATE.isLoading = false;
}

// Resuelve el contexto del evidence si el ? está dentro de un evidence-item
function _resolveContext(btn) {
    const parent = btn.closest('.evidence-item, .yara-rule');
    if (!parent) return '';
    const detailEl = parent.querySelector('.evidence-detail, .yara-rule-cat');
    return detailEl ? detailEl.textContent.trim() : '';
}

// Delegación global de clicks en .help-btn
document.addEventListener('click', function (e) {
    const btn = e.target.closest('.help-btn');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    // Bloqueo anti-spam: si el botón ya disparó algo hace menos de 600ms, ignorar
    const now = Date.now();
    if (btn._lastClick && (now - btn._lastClick) < 600) return;
    btn._lastClick = now;
    const key = btn.dataset.help || '';
    if (!key) return;
    const ctx = _resolveContext(btn);
    _openHelpModal(key, ctx);
});

// ── Botones "copiar" en la lista de IOCs ─────────────────────────────
document.querySelectorAll('.ioc-copy-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      const original = btn.textContent;
      btn.textContent = 'copiado';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
    } catch (e) { console.warn('clipboard failed', e); }
  });
});

// ── Listas colapsables: "Ver más / Ver menos" automatic ───────────────
// Cualquier .collapsible-list con data-show="N" y más de N hijos
// recibe un botón de toggle.
document.querySelectorAll('.collapsible-list').forEach(wrap => {
  const show  = parseInt(wrap.dataset.show, 10) || 5;
  const label = wrap.dataset.label || 'elementos';
  const items = Array.from(wrap.children);
  if (items.length <= show) return;

  // Marca los items que sobran como ocultos
  const hidden = items.length - show;
  for (let i = show; i < items.length; i++) {
    items[i].classList.add('collapsible-hidden');
  }
  wrap.classList.add('has-hidden');

  // Crea el botón con chevron + contador
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'collapsible-toggle';
  const chev = '<svg class="toggle-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>';
  btn.innerHTML = `Ver <span class="toggle-count">${hidden}</span> ${label} más ${chev}`;

  btn.addEventListener('click', () => {
    const expanded = wrap.classList.toggle('expanded');
    btn.classList.toggle('is-expanded', expanded);
    wrap.classList.toggle('has-hidden', !expanded);
    btn.innerHTML = expanded
      ? `Ver menos ${chev}`
      : `Ver <span class="toggle-count">${hidden}</span> ${label} más ${chev}`;
  });

  // Inserta el botón justo después de la lista
  wrap.parentNode.insertBefore(btn, wrap.nextSibling);
});

(async function() {
  const __SBC = window.__SANDBOX_CTX__ || {};
  const filename     = __SBC.filename;
  const mimeType     = __SBC.mimeType;
  const extension    = __SBC.extension;
  const extSpoof     = __SBC.extSpoof;
  const category     = __SBC.category;
  const riskScore    = __SBC.riskScore;
  const threatName   = __SBC.threatName;
  const evidence     = __SBC.evidence;
  const iocs         = __SBC.iocs;
  const yaraMatches  = __SBC.yaraMatches;
  const bodyScore    = __SBC.bodyScore;
  const bodyThreat   = __SBC.bodyThreat;
  const analyzersRun = __SBC.analyzersRun;

  // Top 6 evidencias por severidad para no inflar el prompt
  const topEvidence = (evidence || [])
    .slice()
    .sort((a, b) => (b.severity || 0) - (a.severity || 0))
    .slice(0, 6)
    .map(e => `• [${e.severity}/100] ${e.detail}`)
    .join("\n");

  const iocSummary = [];
  if (iocs?.urls?.length)    iocSummary.push(`URLs: ${iocs.urls.slice(0, 5).join(", ")}`);
  if (iocs?.ips?.length)     iocSummary.push(`IPs: ${iocs.ips.slice(0, 5).join(", ")}`);
  if (iocs?.domains?.length) iocSummary.push(`Dominios: ${iocs.domains.slice(0, 5).join(", ")}`);

  const yaraSummary = (yaraMatches || [])
    .map(m => typeof m === "string" ? m : (m.rule || ""))
    .filter(Boolean)
    .join(", ");

  // Animate steps
  const stepIds = ['step-1','step-2','step-3','step-4'];
  let si = 0;
  const stepInt = setInterval(() => {
    if (si > 0) {
      const prev = document.getElementById(stepIds[si-1]);
      if (prev) { prev.classList.remove('active'); prev.classList.add('done');
        prev.querySelector('.ai-step-indicator').textContent = '✓';
      }
    }
    if (si < stepIds.length) {
      document.getElementById(stepIds[si])?.classList.add('active');
      si++;
    }
  }, 700);

  const prompt = `Eres un analista senior de ciberseguridad escribiendo para un USUARIO FINAL sin conocimientos técnicos. Estás revisando el reporte de un sandbox que analizó un archivo o correo recibido en DockerShield (sistema de alias desechables anti-phishing).

Tu objetivo es que el usuario entienda QUÉ pasó, POR QUÉ es importante, QUÉ pudo pasarle, y QUÉ debe hacer ahora. Escribe en español claro, sin jerga técnica sin explicar.

═══ DATOS DEL ANÁLISIS ═══
Archivo:           ${filename}
Tipo MIME real:    ${mimeType || "desconocido"}
Extensión:         ${extension || "—"}${extSpoof ? "  ← ¡no coincide con MIME real!" : ""}
Categoría:         ${category}
Score de riesgo:   ${riskScore}/100
Amenaza detectada: ${threatName || "ninguna"}
Analizadores que corrieron: ${(analyzersRun || []).join(", ") || "ninguno"}

═══ EVIDENCIA TOP (por severidad) ═══
${topEvidence || "Sin indicadores específicos"}

═══ IOCs EXTRAÍDOS ═══
${iocSummary.join("\n") || "Sin IOCs"}

═══ COINCIDENCIAS YARA ═══
${yaraSummary || "Ninguna"}

═══ CUERPO DEL CORREO ═══
Score body: ${bodyScore}/100${bodyThreat ? "  ·  " + bodyThreat : ""}

═══ REGLAS OBLIGATORIAS ═══

1. VEREDICTO atado al score técnico (no reinterpretes):
   · Score 81-100 → MALICIOSO
   · Score 31-80  → SOSPECHOSO
   · Score 0-30   → SEGURO

2. Si hay match YARA o analizador que detectó amenaza, RESPETA esa detección aunque el
   archivo sea inerte por sí solo. Ejemplo: EICAR es un archivo de prueba estándar de
   antivirus — su detección ES la respuesta correcta del sandbox (VEREDICTO MALICIOSO,
   explicar que el sistema lo bloqueó como debía).

3. SIEMPRE define los términos técnicos la primera vez que los uses, entre paréntesis y
   en lenguaje sencillo. Ejemplos:
   · "YARA (un sistema que busca patrones conocidos de código malicioso)"
   · "macro VBA (mini-programa dentro de un documento Office que se ejecuta al abrirlo)"
   · "PowerShell encoded command (comando oculto en base64 para evadir antivirus)"
   · "loader (programa pequeño cuyo único trabajo es descargar más malware)"
   · "exfiltración (envío secreto de tus datos a un servidor del atacante)"
   · "C2 / command-and-control (servidor desde donde el atacante controla el malware)"
   · "persistencia (técnica para que el malware sobreviva reinicios)"
   · "MIME (tipo real del archivo, distinto de su extensión)"
   · "IOC (indicador de compromiso: URL, IP o hash que delata al atacante)"

4. EXPLICACION debe tener 4-6 frases COMPLETAS organizadas así:
   (a) Qué es el archivo en términos simples.
   (b) Qué patrones específicos detectó el sandbox y QUÉ SIGNIFICAN para el usuario.
   (c) Qué pasaría si el usuario hubiera abierto el archivo (impacto real, sin dramatizar).
   (d) Por qué el sistema lo bloqueó (o por qué se considera seguro).

5. RECOMENDACION debe sonar como un amigo que te asesora — conversacional, en 2-3 párrafos
   cortos, sin headers en mayúsculas, sin viñetas, sin estructura formal. Cubre estas ideas
   pero entrelazadas en lenguaje natural:
   - Qué deberías hacer con este correo/alias ahora mismo.
   - Algo práctico para que reconozcas correos parecidos la próxima vez.
   - Cuándo vale la pena reportarlo a alguien (si aplica).
   Usa "tú", evita el imperativo seco ("destruye el alias" → mejor "yo destruiría el alias",
   "te recomendaría", "lo mejor sería", "si fuera tú..."). Cero sermón, cero alarma.
   Ejemplo de tono: "Lo más sensato es que destruyas este alias en cuanto puedas, porque
   ya quedó en alguna lista de spam. Para la próxima, fíjate en si el remitente termina
   en un dominio raro tipo .xyz o .top — son red flag clásicas..."

6. Tono general: directo, sin alarmismo, sin jerga, didáctico. Como si le explicaras a un amigo.

═══ FORMATO DE RESPUESTA ═══

Responde EXACTAMENTE con estas 4 etiquetas en este orden, sin Markdown, sin asteriscos:

VEREDICTO: [MALICIOSO / SOSPECHOSO / SEGURO]
TIPO DE AMENAZA: [Phishing / Malware / Ransomware / Backdoor / Loader / Spyware / Robo de credenciales / Test de seguridad / No aplica]
EXPLICACION: [4-6 oraciones siguiendo la estructura del punto 4. Puede ocupar varios párrafos.]
RECOMENDACION: [2-3 párrafos cortos en tono conversacional, como un amigo que te asesora. SIN headers en mayúsculas, SIN viñetas, SIN estructura formal. Que cubra qué hacer ahora, cómo reconocer similares, y cuándo reportar — pero todo entrelazado naturalmente.]`;

  /* Parser multi-línea: captura todo el contenido desde KEY: hasta la siguiente KEY:
     Permite que EXPLICACION y RECOMENDACION ocupen varios párrafos. */
  const KEYS = ["VEREDICTO", "TIPO DE AMENAZA", "EXPLICACION", "RECOMENDACION"];
  const get = (text, key) => {
    const lines = text.split("\n");
    const startIdx = lines.findIndex(l => l.trim().startsWith(key + ":"));
    if (startIdx === -1) return "";
    let endIdx = lines.length;
    for (let i = startIdx + 1; i < lines.length; i++) {
      const t = lines[i].trim();
      if (KEYS.some(k => k !== key && t.startsWith(k + ":"))) {
        endIdx = i;
        break;
      }
    }
    const block = lines.slice(startIdx, endIdx).join("\n");
    // Quita "KEY:" del inicio
    return block.replace(new RegExp("^\\s*" + key.replace(/ /g, "\\s+") + "\\s*:\\s*"), "").trim();
  };

  const csrfToken = document.cookie.split(';')
    .find(c => c.trim().startsWith('csrftoken='))?.split('=')[1] || '';

  try {
    const res  = await fetch("/ai-analysis/", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      body: JSON.stringify({ prompt }),
    });
    const data = await res.json();
    const text = data.result;
    if (!text) throw new Error("Sin respuesta");

    clearInterval(stepInt);

    const v  = get(text, "VEREDICTO").toUpperCase();
    const t  = get(text, "TIPO DE AMENAZA");
    const ex = get(text, "EXPLICACION");
    const rc = get(text, "RECOMENDACION");

    // Veredicto
    const vClass = v === "MALICIOSO" ? "verdict-malicioso" : v === "SOSPECHOSO" ? "verdict-sospechoso" : "verdict-seguro";
    const vIcon  = v === "MALICIOSO"
      ? `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
      : v === "SOSPECHOSO"
      ? `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`
      : `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;

    document.getElementById("ai-verdict-el").innerHTML =
      `<span class="ai-verdict-badge ${vClass}">${vIcon} ${v}</span>`;

    // Confidence
    const conf = v === "MALICIOSO" ? 94 : v === "SOSPECHOSO" ? 71 : 97;
    const confColor = v === "MALICIOSO" ? "var(--danger)" : v === "SOSPECHOSO" ? "var(--warning)" : "var(--success)";
    document.getElementById("ai-conf-pct").textContent = conf + "%";
    document.getElementById("ai-conf-pct").style.color = confColor;
    const fill = document.getElementById("ai-conf-fill");
    fill.style.background = confColor;
    setTimeout(() => { fill.style.width = conf + "%"; }, 150);

    // Threat chip
    const isSafe = !t || t.toLowerCase().includes("no aplica");
    const tIcon = isSafe
      ? `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`
      : `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`;
    document.getElementById("ai-threat-el").innerHTML =
      `<span class="ai-threat-chip ${isSafe ? 'good' : 'bad'}">${tIcon} ${t || "No aplica"}</span>`;

    // Timestamp
    document.getElementById("ai-time-el").textContent =
      `analizado · ${new Date().toLocaleTimeString('es-EC',{hour:'2-digit',minute:'2-digit'})}`;

    // Texts
    document.getElementById("ai-expl-el").textContent = ex || "Sin información.";
    document.getElementById("ai-rec-el").textContent  = rc || "Sin recomendación.";

    // Show
    document.getElementById("ai-loading").style.display = "none";
    document.getElementById("ai-content").style.display = "block";

  } catch(e) {
    clearInterval(stepInt);
    document.getElementById("ai-loading").style.display = "none";
    const errWrap = document.getElementById("ai-error");
    errWrap.style.display = "flex";
    document.getElementById("ai-error-msg").textContent = "Análisis IA no disponible: " + e.message;
  }
})();
