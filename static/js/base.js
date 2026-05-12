        // Aplica el tema guardado ANTES de renderizar — evita el flash del tema por defecto
        (function () {
            try {
                var t = localStorage.getItem('sms_theme') || 'dark';
                document.documentElement.setAttribute('data-theme', t);
            } catch (e) {}
        })();
