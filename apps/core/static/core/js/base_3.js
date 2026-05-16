/* ════════════════════════════════════════════════════════════════════
   SISTEMA DE TOASTS GLOBAL — con persistencia entre navegaciones
   Uso:
     showToast({ type:'info', title:'Hola', message:'opcional', href:'/url', duration:5500 })
   Tipos: info (morado) · success (verde) · warning (amarillo) · danger (rojo)

   Persistencia: cada toast se guarda en sessionStorage con su tiempo de
   creación. Al cargar cualquier página, se restauran los toasts que aún
   no expiraron, con el tiempo restante.
   ════════════════════════════════════════════════════════════════════ */
(function () {
    var STORAGE_KEY = 'sms_active_toasts';

    var TOAST_ICONS = {
        info:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        danger:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    };

    function escapeHtml(s) {
        return String(s || '').replace(/[&<>"']/g, function (c) {
            return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c];
        });
    }

    /* ─── Helpers de sessionStorage ─── */
    function loadStored() {
        try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '[]'); }
        catch (e) { return []; }
    }
    function saveStored(arr) {
        try { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(arr)); }
        catch (e) {}
    }
    function addStored(t) {
        var arr = loadStored();
        arr.push(t);
        saveStored(arr);
    }
    function removeStored(id) {
        saveStored(loadStored().filter(function (t) { return t.id !== id; }));
    }

    function genId() {
        return 't_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    }

    /* ─── Sonido suave de notificación (Web Audio, sin archivos) ───
       Acorde mayor (C6 + E6 + G6) con envelope corto y reverb sutil.
       Pleasant, agudo pero NO estridente — pensado para escritorio. */
    var _audioCtx = null;
    function _getAudioCtx() {
        if (_audioCtx) return _audioCtx;
        try {
            var Ctx = window.AudioContext || window.webkitAudioContext;
            if (!Ctx) return null;
            _audioCtx = new Ctx();
        } catch (e) { return null; }
        return _audioCtx;
    }
    function playNotificationSound(opts) {
        opts = opts || {};
        var ctx = _getAudioCtx();
        if (!ctx) return;
        // Si el usuario aún no interactuó con la página, AudioContext está suspendido
        if (ctx.state === 'suspended') { try { ctx.resume(); } catch (e) {} }

        var now = ctx.currentTime;
        // Tres notas de un acorde mayor (Do mayor 6ª octava): C6, E6, G6
        // Variantes por tipo: danger usa intervalo menor (más serio)
        var notes;
        if (opts.type === 'danger') {
            notes = [ {f: 880.00, t: 0.00}, {f: 1046.50, t: 0.05} ];   // A5 + C6 (menor)
        } else if (opts.type === 'warning') {
            notes = [ {f: 987.77, t: 0.00}, {f: 1318.51, t: 0.06} ];   // B5 + E6
        } else {
            notes = [ {f: 1046.50, t: 0.00}, {f: 1318.51, t: 0.05}, {f: 1567.98, t: 0.10} ];  // C6 + E6 + G6
        }

        var master = ctx.createGain();
        master.gain.setValueAtTime(0.0001, now);
        master.gain.exponentialRampToValueAtTime(0.18, now + 0.012);   // attack rápido
        master.gain.exponentialRampToValueAtTime(0.0001, now + 0.55);  // decay suave
        master.connect(ctx.destination);

        notes.forEach(function (n) {
            var osc = ctx.createOscillator();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(n.f, now + n.t);
            // Pequeña inflexión hacia abajo al final → sensación "campanita"
            osc.frequency.exponentialRampToValueAtTime(n.f * 0.985, now + n.t + 0.45);

            var g = ctx.createGain();
            g.gain.setValueAtTime(0.0001, now + n.t);
            g.gain.exponentialRampToValueAtTime(0.9, now + n.t + 0.015);
            g.gain.exponentialRampToValueAtTime(0.0001, now + n.t + 0.5);

            osc.connect(g);
            g.connect(master);
            osc.start(now + n.t);
            osc.stop(now + n.t + 0.55);
        });
    }
    window.playNotificationSound = playNotificationSound;

    /* ─── Renderizador (interno) — crea el DOM del toast ─── */
    function renderToast(opts) {
        var container = document.getElementById('toast-container');
        if (!container) return null;

        var id        = opts.id || genId();
        var type      = opts.type || 'info';
        var title     = opts.title || '';
        var message   = opts.message || '';
        var href      = opts.href || null;
        var duration  = Math.max(opts.duration || 7500, 1000);   // mínimo 1s

        var tag = href ? 'a' : 'div';
        var toast = document.createElement(tag);
        toast.className = 't-' + type + ' toast';
        toast.dataset.toastId = id;
        if (href) toast.href = href;

        toast.innerHTML =
            '<div class="toast-icon">' + (TOAST_ICONS[type] || TOAST_ICONS.info) + '</div>' +
            '<div class="toast-body">' +
                '<div class="toast-title">' + escapeHtml(title) + '</div>' +
                (message ? '<div class="toast-msg">' + escapeHtml(message) + '</div>' : '') +
            '</div>' +
            '<button type="button" class="toast-close" aria-label="Cerrar">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">' +
                    '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' +
                '</svg>' +
            '</button>' +
            '<div class="toast-progress" style="animation-duration:' + duration + 'ms"></div>';

        container.appendChild(toast);

        function dismiss() {
            if (toast.classList.contains('removing')) return;
            toast.classList.add('removing');
            removeStored(id);
            setTimeout(function () { toast.remove(); }, 320);
        }

        var timer = setTimeout(dismiss, duration);
        toast.addEventListener('mouseenter', function () { clearTimeout(timer); });
        toast.addEventListener('mouseleave', function () {
            timer = setTimeout(dismiss, 2500);
        });
        toast.querySelector('.toast-close').addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            dismiss();
        });
        // Click en el cuerpo (cuando es link) también lo cierra antes de navegar
        if (href) {
            toast.addEventListener('click', function () {
                removeStored(id);   // se va de la storage al navegar
            });
        }

        return { id: id, toast: toast };
    }

    /* ─── API pública: showToast ─── */
    window.showToast = function (opts) {
        opts = opts || {};
        var rendered = renderToast(opts);
        if (!rendered) return null;

        // Persistir en sessionStorage para que sobreviva navegaciones
        addStored({
            id:        rendered.id,
            type:      opts.type || 'info',
            title:     opts.title || '',
            message:   opts.message || '',
            href:      opts.href || null,
            createdAt: Date.now(),
            duration:  opts.duration || 7500,
        });

        // Sonido (puedes desactivarlo con { silent: true })
        if (!opts.silent) {
            try { playNotificationSound({ type: opts.type || 'info' }); } catch (e) {}
        }

        return rendered.toast;
    };

    /* ═══════════════════════════════════════════════════════════════
       confirmDialog(opts) → Promise<boolean>
       Reemplazo bonito de window.confirm() — modal con animación,
       overlay con blur y botones temáticos (danger en rojo).
       ═══════════════════════════════════════════════════════════════ */
    var CD_ICONS = {
        warning:   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        trash:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
        info:      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        question:  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    };

    var _cdState = { resolve: null, prevFocus: null };

    function _cdEls() {
        return {
            overlay: document.getElementById('cd-overlay'),
            modal:   document.getElementById('cd-modal'),
            icon:    document.getElementById('cd-icon'),
            title:   document.getElementById('cd-title'),
            message: document.getElementById('cd-message'),
            cancel:  document.getElementById('cd-cancel'),
            confirm: document.getElementById('cd-confirm'),
        };
    }

    function _cdClose(result) {
        var els = _cdEls();
        if (!els.overlay) return;
        els.overlay.classList.remove('visible');
        els.overlay.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
        if (_cdState.prevFocus && _cdState.prevFocus.focus) {
            try { _cdState.prevFocus.focus(); } catch (e) {}
        }
        var resolve = _cdState.resolve;
        _cdState.resolve = null;
        if (resolve) resolve(!!result);
    }

    window.confirmDialog = function (opts) {
        opts = opts || {};
        var els = _cdEls();
        if (!els.overlay) {
            // Fallback al confirm nativo si por algún motivo no está el modal montado
            return Promise.resolve(window.confirm(opts.message || '¿Estás seguro?'));
        }

        // Si ya hay uno abierto, lo cerramos cancelando su promesa antes de abrir el nuevo
        if (_cdState.resolve) _cdClose(false);

        var icon       = opts.icon || (opts.danger ? 'trash' : 'question');
        var title      = opts.title       || (opts.danger ? '¿Estás seguro?' : 'Confirmar acción');
        var message    = opts.message     || '';
        var confirmTxt = opts.confirmText || (opts.danger ? 'Sí, eliminar' : 'Confirmar');
        var cancelTxt  = opts.cancelText  || 'Cancelar';

        els.modal.classList.toggle('is-danger', !!opts.danger);
        els.icon.innerHTML  = CD_ICONS[icon] || CD_ICONS.question;
        els.title.textContent = title;
        // Permite saltos de línea simples (\n) en el mensaje
        els.message.innerHTML = String(message).split('\n').map(function (line) {
            return line.replace(/[&<>"']/g, function (c) {
                return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
            });
        }).join('<br>');
        els.confirm.textContent = confirmTxt;
        els.cancel.textContent  = cancelTxt;

        _cdState.prevFocus = document.activeElement;
        document.body.style.overflow = 'hidden';
        els.overlay.classList.add('visible');
        els.overlay.setAttribute('aria-hidden', 'false');
        // Focus al botón cancelar por defecto (más seguro)
        setTimeout(function () { els.cancel.focus(); }, 50);

        return new Promise(function (resolve) { _cdState.resolve = resolve; });
    };

    // Listeners (una sola vez al cargar el script)
    (function () {
        var els = _cdEls();
        if (!els.overlay) return;
        els.confirm.addEventListener('click', function () { _cdClose(true); });
        els.cancel .addEventListener('click', function () { _cdClose(false); });
        els.overlay.addEventListener('click', function (e) {
            if (e.target === els.overlay) _cdClose(false);
        });
        document.addEventListener('keydown', function (e) {
            if (!els.overlay.classList.contains('visible')) return;
            if (e.key === 'Escape')                 { e.preventDefault(); _cdClose(false); }
            else if (e.key === 'Enter')             { e.preventDefault(); _cdClose(true);  }
        });
    })();

    /* ─── Restaurar toasts activos al cargar la página ─── */
    function restoreToasts() {
        var now = Date.now();
        var stored = loadStored();
        // Filtra los que aún no expiraron (con margen de 500ms)
        var active = stored.filter(function (t) {
            return (t.createdAt + t.duration - 500) > now;
        });
        saveStored(active);   // limpia los expirados de storage

        active.forEach(function (t) {
            var remaining = (t.createdAt + t.duration) - now;
            renderToast({
                id:       t.id,         // mantiene el mismo id
                type:     t.type,
                title:    t.title,
                message:  t.message,
                href:     t.href,
                duration: remaining,    // continúa con el tiempo que quedaba
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', restoreToasts);
    } else {
        restoreToasts();
    }
})();

/* ─── Gestor de temas (se ejecuta ANTES de que el usuario interactúe) ─── */
// Temas válidos: 'dark' y 'carbon'. Si llega 'light' (versión vieja) → 'dark'.
const VALID_THEMES = ['dark', 'carbon'];
(function () {
    let saved = localStorage.getItem('sms_theme') || 'dark';
    if (!VALID_THEMES.includes(saved)) {
        saved = 'dark';
        localStorage.setItem('sms_theme', saved);
    }
    document.documentElement.setAttribute('data-theme', saved);
})();

function openThemeModal() {
    // En móvil/tablet el drawer del sidebar está abierto cuando el usuario
    // hace clic en "Apariencia" desde el dropdown del usuario; lo escondemos
    // para que la theme-modal quede visible. Sólo removemos las clases —
    // body.overflow lo controla la modal abajo (si aquí lo reseteáramos,
    // dejaríamos la página scrolleable detrás de la modal).
    var sb = document.getElementById('sidebar');
    var bd = document.getElementById('sidebarBackdrop');
    if (sb) sb.classList.remove('open');
    if (bd) bd.classList.remove('visible');

    const current = localStorage.getItem('sms_theme') || 'dark';
    document.querySelectorAll('.theme-card').forEach(c => {
        c.classList.toggle('selected', c.dataset.theme === current);
    });
    document.getElementById('themeOverlay').classList.add('visible');
    document.body.style.overflow = 'hidden';
}
function closeThemeModal() {
    document.getElementById('themeOverlay').classList.remove('visible');
    document.body.style.overflow = '';
}
function selectThemeCard(name) {
    if (!VALID_THEMES.includes(name)) return;
    const current = localStorage.getItem('sms_theme') || 'dark';
    // Si ya es el tema actual, solo cierra la modal
    if (name === current) {
        closeThemeModal();
        return;
    }
    // Feedback visual antes de recargar (se ve el card seleccionado un instante)
    document.querySelectorAll('.theme-card').forEach(c => {
        c.classList.toggle('selected', c.dataset.theme === name);
    });
    // Guarda y recarga: garantiza que todos los estilos inline / hardcoded
    // se recalculen desde cero con el nuevo tema (sin glitches de texto ilegible).
    localStorage.setItem('sms_theme', name);
    document.documentElement.setAttribute('data-theme', name);
    setTimeout(() => location.reload(), 120);
}
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        const ov = document.getElementById('themeOverlay');
        if (ov && ov.classList.contains('visible')) closeThemeModal();
    }
});

/* ─── Dropdown de usuario ─── */
(function () {
    const btn      = document.getElementById('userBtn');
    const dropdown = document.getElementById('userDropdown');
    const chevron  = document.getElementById('chevronIcon');
    let open = false;

    function close() {
        open = false;
        dropdown.classList.remove('open');
        chevron.classList.remove('up');
    }

    btn.addEventListener('click', function (e) {
        e.stopPropagation();
        open = !open;
        dropdown.classList.toggle('open', open);
        chevron.classList.toggle('up', open);
    });

    // Cierra al hacer clic fuera
    document.addEventListener('click', close);

    // Evita que clics dentro del dropdown lo cierren
    dropdown.addEventListener('click', function (e) {
        e.stopPropagation();
    });
})();

/* ─── Bell de notificaciones (dropdown + polling) ─── */
(function () {
    const bell  = document.getElementById('notif-bell');
    const panel = document.getElementById('notif-panel');
    const list  = document.getElementById('notif-panel-list');
    const badge = document.getElementById('notif-badge');
    const markAll = document.getElementById('notif-mark-all');
    if (!bell || !panel) return;   // No autenticado, no hay bell

    // Iconos SVG por tipo
    const ICONS = {
        forward_request: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        forwarded:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>',
        threat_alert:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        system:          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/></svg>',
    };

    let openPanel = false;
    // Último id de notificación cuyo toast ya se mostró al usuario.
    // Antes vivía en localStorage (per-dispositivo): si el usuario veía un
    // toast en su celular, al abrir la app en su PC se le volvía a mostrar.
    // Ahora el marker es SERVER-SIDE (UserProfile.last_toast_notif_id),
    // sincronizado entre todos los dispositivos del mismo usuario.
    //
    // Mantenemos una copia local en memoria (lastSeenId) y la sincronizamos
    // con el server en cada refresh. localStorage queda como caché caliente
    // para evitar parpadeos de toasts entre el render inicial y la primera
    // respuesta del endpoint en F5.
    const SEEN_KEY = 'sms_notif_last_seen_id';
    let lastSeenId = null;   // null = aún no sabemos (esperar respuesta server)
    try {
        const cached = localStorage.getItem(SEEN_KEY);
        if (cached !== null) lastSeenId = parseInt(cached, 10) || 0;
    } catch (e) { /* localStorage bloqueado, sin caché */ }

    function updateLocalCache(id) {
        try { localStorage.setItem(SEEN_KEY, String(id)); } catch (e) {}
    }
    function pushToServer(id) {
        // Avanza el marker server-side. El backend solo lo mueve hacia
        // adelante (nunca retrocede), así llamadas desordenadas son safe.
        const fd = new FormData();
        fd.append('last_id', String(id));
        fetch('/notificaciones/api/toast-shown/', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-CSRFToken': getCsrf() },
            body: fd,
        }).catch(err => console.debug('[notif] toast-shown sync error:', err));
    }

    function setOpen(state) {
        openPanel = state;
        panel.classList.toggle('open', state);
        if (state) refresh();
    }

    bell.addEventListener('click', function (e) {
        e.stopPropagation();
        setOpen(!openPanel);
    });
    panel.addEventListener('click', function (e) { e.stopPropagation(); });
    document.addEventListener('click', function () { if (openPanel) setOpen(false); });

    function getCsrf() {
        const c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
        return c ? c.split('=')[1] : '';
    }
    // Exponer globalmente para que CUALQUIER template hijo (perfil, etc.)
    // pueda llamarlo sin tener que redefinirlo localmente. Esta función
    // vive dentro de un IIFE — sin esta línea quedaría inaccesible fuera.
    window.getCsrf = getCsrf;

    function renderItem(n) {
        const cls = (n.read ? '' : 'unread');
        const pendingPill = n.is_actionable
            ? '<div class="notif-item-pending-pill">PENDIENTE</div>' : '';
        // Color del icono por nivel de riesgo del correo asociado.
        // Si no hay correo (notificación de sistema), usamos el color por tipo.
        let iconCls;
        if (typeof n.risk_score === 'number') {
            if      (n.risk_score >= 61) iconCls = 'r-danger';
            else if (n.risk_score >= 31) iconCls = 'r-warn';
            else                         iconCls = 'r-safe';
        } else {
            iconCls = 't-' + n.type;
        }
        return `<a href="${n.url}" class="notif-item ${cls}" data-id="${n.id}">
            <div class="notif-item-icon ${iconCls}">${ICONS[n.type] || ICONS.system}</div>
            <div class="notif-item-body">
                <div class="notif-item-title">${escapeHtml(n.title)}</div>
                <div class="notif-item-msg">${escapeHtml(n.message || '')}</div>
                ${pendingPill}
            </div>
            <div class="notif-item-time">${escapeHtml(n.time_human)}</div>
        </a>`;
    }
    function escapeHtml(s) {
        return String(s || '').replace(/[&<>"']/g, c => ({
            '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
        })[c]);
    }

    function refresh() {
        fetch('/notificaciones/api/unread/', { credentials: 'same-origin' })
            .then(r => r.ok ? r.json() : Promise.reject(r.status))
            .then(data => {
                // Badge
                const n = data.unread_count || 0;
                if (n > 0) {
                    badge.textContent = n > 99 ? '99+' : n;
                    badge.style.display = 'flex';
                    bell.classList.add('has-unread');
                } else {
                    badge.style.display = 'none';
                    bell.classList.remove('has-unread');
                }

                // Lista
                if (!data.recent || data.recent.length === 0) {
                    list.innerHTML = '<div class="notif-panel-empty">No tienes notificaciones por ahora.</div>';
                } else {
                    list.innerHTML = data.recent.map(renderItem).join('');
                }

                // ── Toasts en cada recarga: dispara solo para notificaciones
                // que el usuario NO ha visto antes (id > último visto). El
                // marker es server-side, sincronizado entre dispositivos.
                if (data.recent && data.recent.length > 0) {
                    // Server es la fuente de verdad. Si localStorage tenía
                    // un valor mayor (raro), lo respetamos como caché — pero
                    // siempre tomamos el MAX entre server y local.
                    const serverSeen = (typeof data.last_toast_id === 'number')
                        ? data.last_toast_id
                        : 0;
                    const effectiveSeen = Math.max(serverSeen, lastSeenId ?? serverSeen);
                    // Si es la primera carga del usuario (server=0 Y sin caché
                    // local) NO toasteamos las viejas — solo registramos el max.
                    const firstTime = (serverSeen === 0 && lastSeenId === null);

                    const maxId = data.recent.reduce(
                        (m, it) => (it.id > m ? it.id : m), 0
                    );

                    if (!firstTime && maxId > effectiveSeen) {
                        const newOnes = data.recent.filter(it => it.id > effectiveSeen);
                        // Orden cronológico (más antigua primero) para que la
                        // más reciente quede arriba del stack de toasts.
                        newOnes.sort((a, b) => a.id - b.id).forEach(item => {
                            // Color del toast por nivel de riesgo del correo:
                            //   amenaza (≥61)    → rojo
                            //   sospechoso (31-60) → amarillo
                            //   seguro (≤30)      → verde
                            // Sin score → criterio por tipo.
                            let toastType;
                            const r = (typeof item.risk_score === 'number') ? item.risk_score : null;
                            const title = (item.title || '').toLowerCase();
                            if (item.type === 'threat_alert' || (r !== null && r >= 61)) {
                                toastType = 'danger';
                            } else if (r !== null && r >= 31) {
                                toastType = 'warning';
                            } else if (r !== null && r >= 0) {
                                toastType = 'success';
                            } else if (item.type === 'system' && title.indexOf('aprobada') !== -1) {
                                // Solicitud aprobada → verde con check.
                                toastType = 'success';
                            } else if (item.type === 'system' && title.indexOf('rechazada') !== -1) {
                                // Solicitud rechazada → rojo con X.
                                toastType = 'danger';
                            } else if (item.type === 'system' && title.indexOf('solicitud') !== -1) {
                                // Notif al admin: "Nueva solicitud de cupo" → ámbar (acción).
                                toastType = 'warning';
                            } else {
                                toastType =
                                    item.type === 'forward_request' ? 'warning' :
                                    item.type === 'forwarded'       ? 'success' :
                                                                      'info';
                            }
                            window.showToast({
                                type:    toastType,
                                title:   item.title,
                                message: item.message,
                                href:    item.url,
                                duration: 9500,
                            });
                        });
                    }

                    // Persistimos el máximo. localStorage queda como caché
                    // caliente (evita parpadeos en F5) y el server queda como
                    // fuente de verdad sincronizada entre dispositivos. Solo
                    // hacemos push al server si el marker AVANZA (no en cada
                    // refresh, para no spammear el endpoint).
                    if (maxId > (lastSeenId ?? 0) || maxId > serverSeen) {
                        updateLocalCache(maxId);
                        lastSeenId = maxId;
                        pushToServer(maxId);
                    }
                }
            })
            .catch(err => console.debug('[notif] refresh error:', err));
    }

    if (markAll) {
        markAll.addEventListener('click', function () {
            fetch('/notificaciones/leer-todo/', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'X-CSRFToken': getCsrf() },
            }).then(() => refresh());
        });
    }

    // Carga inicial — pinta el badge y el contenido del dropdown con los
    // datos del servidor al cargar la página. Sin auto-refresh: el usuario
    // tiene que recargar manualmente (F5) para ver el contador actualizado.
    refresh();
})();
