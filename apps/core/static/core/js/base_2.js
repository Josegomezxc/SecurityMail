(function () {
    var toggle  = document.getElementById('sidebarToggle');
    var sidebar = document.getElementById('sidebar');
    var backdrop = document.getElementById('sidebarBackdrop');
    if (!toggle || !sidebar || !backdrop) return;

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

    sidebar.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', function () {
            if (window.innerWidth < 1024) closeSidebar();
        });
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && isOpen()) closeSidebar();
    });

    window.addEventListener('resize', function () {
        if (window.innerWidth >= 1024 && isOpen()) closeSidebar();
    });

    window.closeSidebarDrawer = closeSidebar;
})();


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

            nav.scrollTop = val;
        } catch (e) {}
    }

    restoreScroll();
    if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(restoreScroll);
    }
    if (document.readyState === 'complete') {
    } else {
        window.addEventListener('load', restoreScroll);
    }
    setTimeout(restoreScroll, 120);

    function saveScroll() {
        try { sessionStorage.setItem(SCROLL_KEY, String(nav.scrollTop)); }
        catch (e) {}
    }
    window.addEventListener('pagehide', saveScroll);
    window.addEventListener('beforeunload', saveScroll);
    var sidebarEl = document.getElementById('sidebar');
    if (sidebarEl) {
        sidebarEl.addEventListener('click', function (e) {
            var link = e.target.closest('a[href]');
            if (link && sidebarEl.contains(link)) saveScroll();
        }, true);
    }
    var scrollTimer = null;
    nav.addEventListener('scroll', function () {
        if (scrollTimer) clearTimeout(scrollTimer);
        scrollTimer = setTimeout(saveScroll, 200);
    });
})();

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
