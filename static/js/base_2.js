/* ════════════════════════════════════════════════════════════════════
   SIDEBAR DRAWER — móvil + tablet
   ════════════════════════════════════════════════════════════════════ */
(function () {
    var toggle  = document.getElementById('sidebarToggle');
    var sidebar = document.getElementById('sidebar');
    var backdrop = document.getElementById('sidebarBackdrop');
    if (!toggle || !sidebar || !backdrop) return;

    /* Bloqueo de scroll cuando el drawer está abierto.
       Solo body.overflow:hidden no alcanza en móvil: por la regla
       html,body{overflow-x:hidden} algunos navegadores móviles usan
       <html> como elemento scrolleable, y queda libre. Bloqueamos
       overflow en ambos. Guardamos los valores previos por si otra
       cosa (modal de tema, compose modal) ya los había modificado. */
    var prevHtmlOverflow = '';
    var prevBodyOverflow = '';

    function openSidebar() {
        sidebar.classList.add('open');
        backdrop.classList.add('visible');
        prevHtmlOverflow = document.documentElement.style.overflow;
        prevBodyOverflow = document.body.style.overflow;
        document.documentElement.style.overflow = 'hidden';
        document.body.style.overflow = 'hidden';
    }
    function closeSidebar() {
        sidebar.classList.remove('open');
        backdrop.classList.remove('visible');
        document.documentElement.style.overflow = prevHtmlOverflow;
        document.body.style.overflow = prevBodyOverflow;
    }
    function isOpen() {
        return sidebar.classList.contains('open');
    }

    toggle.addEventListener('click', function (e) {
        e.stopPropagation();
        isOpen() ? closeSidebar() : openSidebar();
    });
    backdrop.addEventListener('click', closeSidebar);

    // Cerrar al navegar a otra ruta (los <a> del sidebar)
    sidebar.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', function () {
            if (window.innerWidth < 1024) closeSidebar();
        });
    });

    // Cerrar con Escape
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && isOpen()) closeSidebar();
    });

    // Si el viewport crece a desktop, asegurar estado limpio
    window.addEventListener('resize', function () {
        if (window.innerWidth >= 1024 && isOpen()) closeSidebar();
    });

    /* Exponemos closeSidebar al scope global para que otros handlers
       (ej. composeFromSidebarAlias) puedan cerrar el drawer sin tener
       que duplicar la lógica de overflow/backdrop. */
    window.closeSidebarDrawer = closeSidebar;
})();

/* ════════════════════════════════════════════════════════════════════
   SIDEBAR — Persistencia del scroll entre páginas
   ─────────────────────────────────────────────────────────────────────
   Si el usuario baja en el sidebar y le da click a "Notificaciones" (o
   cualquier link de abajo), la siguiente página cargaba con el sidebar
   en scrollTop=0 y tenía que volver a scrollear. Ahora guardamos el
   scrollTop en sessionStorage antes de navegar y lo restauramos al
   cargar la nueva página.

   sessionStorage (no localStorage) → es por-tab, así múltiples tabs no
   se pisan. Se borra solo al cerrar el tab.
   ════════════════════════════════════════════════════════════════════ */
(function () {
    var nav = document.getElementById('sidebarNav');
    if (!nav) return;

    var SCROLL_KEY = 'sms_sidebar_scroll';

    function restoreScroll() {
        try {
            var saved = sessionStorage.getItem(SCROLL_KEY);
            if (saved === null) return;
            var val = parseInt(saved, 10);
            if (isNaN(val) || val <= 0) return;
            // Si el contenido todavía no tiene su altura final
            // (fuentes/imágenes cargando), scrollTop=val se clampea a 0.
            // Por eso restoreScroll() se llama en VARIOS momentos abajo.
            nav.scrollTop = val;
        } catch (e) {}
    }

    // ── 1) RESTAURAR — múltiples momentos para cubrir todos los casos
    // a) inmediato (DOM ya listo, base_2.js está al final del body)
    restoreScroll();
    // b) tras la primera pintura (layout calculado, fuentes web-safe ya
    //    aplicadas)
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(restoreScroll);
    }
    // c) cuando todo terminó de cargar (fuentes externas, imágenes —
    //    podían estar inflando el alto del sidebar después del render
    //    inicial y por eso el scrollTop se clampeaba a 0)
    if (document.readyState === 'complete') {
        // ya está cargado, no esperamos al evento
    } else {
        window.addEventListener('load', restoreScroll);
    }
    // d) último fallback: 100ms después del load por si alguna anim CSS
    //    cambia la altura del nav post-carga
    setTimeout(restoreScroll, 120);

    // ── 2) GUARDAR antes de navegar a otra página ────────────────────
    function saveScroll() {
        try { sessionStorage.setItem(SCROLL_KEY, String(nav.scrollTop)); }
        catch (e) {}
    }
    // pagehide → cubre back/forward + navegaciones normales (mejor que
    // beforeunload, especialmente en mobile/iOS).
    window.addEventListener('pagehide', saveScroll);
    // beforeunload → backup para algunos browsers.
    window.addEventListener('beforeunload', saveScroll);
    // Backup explícito al click — el listener corre en capture phase
    // para anticiparse al handler que cierra el drawer en mobile.
    var sidebarEl = document.getElementById('sidebar');
    if (sidebarEl) {
        sidebarEl.addEventListener('click', function (e) {
            var link = e.target.closest('a[href]');
            if (link && sidebarEl.contains(link)) saveScroll();
        }, true);
    }
    // También guardamos al scroll (debounced) — así si el usuario solo
    // scrollea y no navega, igual queda persistido.
    var scrollTimer = null;
    nav.addEventListener('scroll', function () {
        if (scrollTimer) clearTimeout(scrollTimer);
        scrollTimer = setTimeout(saveScroll, 200);
    });
})();


/* ════════════════════════════════════════════════════════════════════
   SIDEBAR — Botón "Nuevo correo" + picker de alias
   Handlers globales (live en base_2.js para estar disponibles en TODAS
   las páginas, no solo en /enviados/). Usan IDs propios del sidebar
   (sidebarComposeBtn, sidebarAliasPicker) para no chocar con el botón
   homólogo del módulo Enviados.
   ════════════════════════════════════════════════════════════════════ */
function toggleSidebarAliasPicker(e) {
    if (e) e.stopPropagation();
    var picker = document.getElementById('sidebarAliasPicker');
    var btn    = document.getElementById('sidebarComposeBtn');
    if (!picker || !btn) return;
    var willOpen = !picker.classList.contains('open');
    picker.classList.toggle('open', willOpen);
    btn.classList.toggle('open', willOpen);
}
function closeSidebarAliasPicker() {
    var picker = document.getElementById('sidebarAliasPicker');
    var btn    = document.getElementById('sidebarComposeBtn');
    if (picker) picker.classList.remove('open');
    if (btn)    btn.classList.remove('open');
}
document.addEventListener('click', function (e) {
    var wrap = e.target.closest('#sidebarCompose');
    if (!wrap) closeSidebarAliasPicker();
});
function composeFromSidebarAlias(item) {
    var id    = item.dataset.aliasId;
    var addr  = item.dataset.aliasAddress;
    var label = item.dataset.aliasLabel || '';
    closeSidebarAliasPicker();
    /* En mobile el sidebar es un drawer que tapa el compose modal — hay
       que cerrarlo antes de abrir el compose para que el usuario lo vea. */
    if (window.innerWidth < 1024 && typeof window.closeSidebarDrawer === 'function') {
        window.closeSidebarDrawer();
    }
    if (typeof window.openCompose === 'function') {
        window.openCompose(id, addr, label);
    } else if (window.showToast) {
        window.showToast({
            type: 'danger',
            title: 'Compose no disponible',
            message: 'Recarga la página e inténtalo de nuevo.',
            duration: 5000,
        });
    }
}
