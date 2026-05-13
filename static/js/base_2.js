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
