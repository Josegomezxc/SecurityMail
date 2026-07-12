
(function () {
    try {
        var t = localStorage.getItem('sms_theme') || 'dark';
        if (t !== 'dark' && t !== 'carbon' && t !== 'light') {
            t = 'dark';
            localStorage.setItem('sms_theme', t);
        }
        document.documentElement.setAttribute('data-theme', t);
    } catch (e) {}
})();


(function () {
    function applyLoader() {
        document.documentElement.classList.add('ds-loading');
        var l = document.getElementById('dsLoader');
        if (l) l.style.display = 'flex';
    }
    function hideLoader() {
        document.documentElement.classList.remove('ds-loading');
        var l = document.getElementById('dsLoader');
        if (l) l.style.display = '';
        try { sessionStorage.removeItem('ds_navLoad'); } catch (e) {}
    }


    try {
        if (sessionStorage.getItem('ds_navLoad') === '1') {
            document.documentElement.classList.add('ds-loading');
        }
    } catch (e) {}

  
    function setupHideOnLoad() {
        if (!document.documentElement.classList.contains('ds-loading')) return;
        if (document.readyState === 'complete') {
            setTimeout(hideLoader, 250);
        } else {
            window.addEventListener('load', function () {
                setTimeout(hideLoader, 250);
            });
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupHideOnLoad);
    } else {
        setupHideOnLoad();
    }

  
    window.dsShowLoader = function () {
        try { sessionStorage.setItem('ds_navLoad', '1'); } catch (e) {}
        applyLoader();
    };
    window.dsHideLoader = hideLoader;



    function handleFormSubmit(e) {
        var form = e.target;
        if (!form || form.nodeName !== 'FORM') return;
        if (!form.hasAttribute('data-ds-loader')) return;
        if (e.defaultPrevented) return;       
        if (form._dsSubmitted) return;        
        form._dsSubmitted = true;
        e.preventDefault();
        window.dsShowLoader();
        requestAnimationFrame(function () { form.submit(); });
    }

    function handleLinkClick(e) {

        if (e.button !== 0) return;
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
        var t = e.target;
        if (!t || typeof t.closest !== 'function') return;
        var a = t.closest('a[data-ds-loader]');
        if (!a) return;
        if (a.target && a.target !== '' && a.target !== '_self') return;  
        var href = a.getAttribute('href');
        if (!href || href === '#' || href.indexOf('javascript:') === 0) return;
        
        e.preventDefault();
        window.dsShowLoader();
        requestAnimationFrame(function () {
            window.location.href = a.href;
        });
    }

    document.addEventListener('submit', handleFormSubmit, false);
    document.addEventListener('click',  handleLinkClick,  true);
})();
