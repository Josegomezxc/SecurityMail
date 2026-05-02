/* ════════════════════════════════════════════════════════════════════
   SIDEBAR DRAWER — móvil + tablet
   ════════════════════════════════════════════════════════════════════ */
(function () {
    var toggle  = document.getElementById('sidebarToggle');
    var sidebar = document.getElementById('sidebar');
    var backdrop = document.getElementById('sidebarBackdrop');
    if (!toggle || !sidebar || !backdrop) return;

    function openSidebar() {
        sidebar.classList.add('open');
        backdrop.classList.add('visible');
        document.body.style.overflow = 'hidden';
    }
    function closeSidebar() {
        sidebar.classList.remove('open');
        backdrop.classList.remove('visible');
        document.body.style.overflow = '';
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
})();
