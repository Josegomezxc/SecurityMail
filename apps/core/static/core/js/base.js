// Aplica el tema guardado ANTES de renderizar — evita el flash del tema por defecto.
// Los temas válidos son 'dark' y 'carbon'. Si en localStorage queda
// 'light' (de una versión vieja) se migra a 'dark' automáticamente.
(function () {
    try {
        var t = localStorage.getItem('sms_theme') || 'dark';
        if (t !== 'dark' && t !== 'carbon') {
            t = 'dark';
            localStorage.setItem('sms_theme', t);
        }
        document.documentElement.setAttribute('data-theme', t);
    } catch (e) {}
})();

/* ─── Loader global de navegación ────────────────────────────────────
   Este bloque vive en base.js (cargado en <head>) y NO depende de
   base_3.js — el login override del bloque body_outer no incluye
   base_3.js, así que la función dsShowLoader tiene que estar acá
   para que el form de login pueda invocarla.

   Flujo:
     1. login.js (u otro) llama a window.dsShowLoader() antes del submit.
     2. dsShowLoader setea sessionStorage.ds_navLoad y agrega la clase
        'ds-loading' a <html> → el CSS muestra el overlay.
     3. El browser navega; en la página destino, este mismo script
        detecta el flag al cargar <head> y vuelve a agregar la clase.
     4. window.load → quitamos clase y limpiamos el flag.
   ────────────────────────────────────────────────────────────────── */
(function () {
    function applyLoader() {
        document.documentElement.classList.add('ds-loading');
        // Fallback inline por si el CSS aún no cargó cuando se invoca:
        var l = document.getElementById('dsLoader');
        if (l) l.style.display = 'flex';
    }
    function hideLoader() {
        document.documentElement.classList.remove('ds-loading');
        var l = document.getElementById('dsLoader');
        if (l) l.style.display = '';
        try { sessionStorage.removeItem('ds_navLoad'); } catch (e) {}
    }

    // 1) Al cargar <head>, si veníamos de una navegación marcada, mostramos
    //    el loader inmediatamente. El elemento #dsLoader aún no existe en
    //    el DOM (estamos parseando <head>), así que solo agregamos la clase
    //    al <html> — el CSS hace que aparezca apenas pinte el body.
    try {
        if (sessionStorage.getItem('ds_navLoad') === '1') {
            document.documentElement.classList.add('ds-loading');
        }
    } catch (e) {}

    // 2) Hide automático al disparar window.load — la página destino ya
    //    terminó de cargar todo (HTML, CSS, JS, imágenes).
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

    // 3) API pública para que otros scripts disparen el loader (login, etc.)
    window.dsShowLoader = function () {
        try { sessionStorage.setItem('ds_navLoad', '1'); } catch (e) {}
        applyLoader();
    };
    window.dsHideLoader = hideLoader;

    /* ─── Delegación global: data-ds-loader ───────────────────────────
       Cualquier <form data-ds-loader> o <a data-ds-loader> activa
       automáticamente el loader. Funciona en TODA la app sin tener
       que escribir JS específico por página.

       Para forms: cancelamos el submit nativo, mostramos el loader,
       y reenviamos programáticamente tras un frame (browser pinta
       el overlay antes de empezar a navegar). Si otro handler ya
       canceló el submit (validación fallida) no hacemos nada.

       Para links: simplemente disparamos el loader y dejamos que el
       browser navegue normalmente — `<a>` no necesita prevenir nada.
       Skipea click derecho, middle click y modificadores (ctrl/cmd).
       ─────────────────────────────────────────────────────────────── */

    function handleFormSubmit(e) {
        var form = e.target;
        if (!form || form.nodeName !== 'FORM') return;
        if (!form.hasAttribute('data-ds-loader')) return;
        if (e.defaultPrevented) return;       // validación falló — no mostrar loader
        if (form._dsSubmitted) return;        // re-entrada por form.submit() programático
        form._dsSubmitted = true;
        e.preventDefault();
        window.dsShowLoader();
        requestAnimationFrame(function () { form.submit(); });
    }

    function handleLinkClick(e) {
        // Solo click izquierdo sin modificadores
        if (e.button !== 0) return;
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
        var t = e.target;
        if (!t || typeof t.closest !== 'function') return;
        var a = t.closest('a[data-ds-loader]');
        if (!a) return;
        if (a.target && a.target !== '' && a.target !== '_self') return;  // target=_blank, etc.
        var href = a.getAttribute('href');
        if (!href || href === '#' || href.indexOf('javascript:') === 0) return;
        // Bloqueamos la navegación nativa, mostramos el loader, y navegamos
        // programáticamente tras un frame — así el browser pinta el overlay
        // ANTES de empezar a salir de la página. Sin esto, en sistemas
        // rápidos el navigate ocurre antes de que el repaint suceda.
        e.preventDefault();
        window.dsShowLoader();
        requestAnimationFrame(function () {
            window.location.href = a.href;
        });
    }

    // Click: registramos en fase de CAPTURA para correr ANTES de que
    // cualquier dropdown/menu llame a stopPropagation y nos deje afuera.
    // Submit: fase de bubble está bien — queremos ver si validaciones
    // de form hicieron preventDefault antes de mostrar el loader.
    document.addEventListener('submit', handleFormSubmit, false);
    document.addEventListener('click',  handleLinkClick,  true);
})();
