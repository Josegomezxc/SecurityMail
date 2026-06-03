(function () {
    // Mismas métricas que register.js — fortaleza con 4 segmentos,
    // requisitos con check, match hint con icono dinámico, caps lock,
    // toggle ojo. Mantiene UX consistente entre crear cuenta y cambiar
    // contraseña.
    const eyeOpenSVG  = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    const eyeCloseSVG = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

    // ── Toggle mostrar/ocultar contraseña ─────────────────────────────
    document.querySelectorAll('.eye-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById(btn.dataset.target);
            const svg = btn.querySelector('.eye-svg');
            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            svg.innerHTML = showing ? eyeOpenSVG : eyeCloseSVG;
        });
    });

    const pwd1 = document.getElementById('pwd1');
    const pwd2 = document.getElementById('pwd2');
    const capsWarn = document.getElementById('capsWarning');

    // ── Caps Lock detection ───────────────────────────────────────────
    function checkCaps(e) {
        if (e.getModifierState && e.getModifierState('CapsLock')) {
            capsWarn.classList.add('show');
        } else {
            capsWarn.classList.remove('show');
        }
    }
    pwd1.addEventListener('keydown', checkCaps);
    pwd1.addEventListener('keyup', checkCaps);
    pwd1.addEventListener('blur', () => capsWarn.classList.remove('show'));

    // ── Barra de fortaleza (4 segmentos) ──────────────────────────────
    const bars = document.querySelectorAll('#strengthBar span');
    const levelLabel = document.getElementById('strengthLevel');
    const reqList = document.getElementById('reqList');
    const colors = ['var(--danger)', 'var(--warning)', '#facc15', 'var(--success)'];
    const labels = ['Débil', 'Aceptable', 'Buena', 'Fuerte'];

    function evaluatePwd() {
        const v = pwd1.value;
        const checks = {
            len:   v.length >= 8,
            upper: /[A-Z]/.test(v),
            num:   /\d/.test(v),
            sym:   /[^A-Za-z0-9]/.test(v),
        };

        Object.keys(checks).forEach(k => {
            const el = reqList.querySelector('[data-req="' + k + '"]');
            if (el) el.classList.toggle('ok', checks[k]);
        });

        const score = Object.values(checks).filter(Boolean).length;
        bars.forEach((b, i) => {
            b.style.background = i < score ? colors[score - 1] : 'var(--bg-hover)';
        });

        if (v.length === 0) {
            levelLabel.textContent = '—';
            levelLabel.style.color = 'var(--text-muted)';
        } else {
            levelLabel.textContent = labels[score - 1] || 'Débil';
            levelLabel.style.color = colors[Math.max(score - 1, 0)];
        }
    }

    // ── Hint de coincidencia (con icono dinámico) ─────────────────────
    const matchHint = document.getElementById('matchHint');
    const matchText = document.getElementById('matchText');
    const matchIcon = document.getElementById('matchIcon');
    const okIconSvg  = '<polyline points="20 6 9 17 4 12"/>';
    const badIconSvg = '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';

    function updateMatch() {
        if (!pwd2.value) { matchHint.classList.remove('show'); return; }
        matchHint.classList.add('show');
        if (pwd1.value === pwd2.value) {
            matchHint.classList.add('ok');
            matchHint.classList.remove('bad');
            matchIcon.innerHTML = okIconSvg;
            matchText.textContent = 'Las contraseñas coinciden';
        } else {
            matchHint.classList.add('bad');
            matchHint.classList.remove('ok');
            matchIcon.innerHTML = badIconSvg;
            matchText.textContent = 'Las contraseñas no coinciden';
        }
    }

    pwd1.addEventListener('input', () => { evaluatePwd(); updateMatch(); checkSubmit(); });
    pwd2.addEventListener('input', () => { updateMatch(); checkSubmit(); });

    // ── Submit: bloqueo si no coinciden o son débiles ─────────────────
    const submitBtn = document.getElementById('submitBtn');
    function checkSubmit() {
        const pwdOk = pwd1.value.length >= 8 && pwd1.value === pwd2.value;
        submitBtn.disabled = !pwdOk;
    }

    document.getElementById('pwForm').addEventListener('submit', function (e) {
        if (pwd1.value !== pwd2.value) {
            e.preventDefault();
            matchHint.classList.add('show', 'bad');
            matchHint.classList.remove('ok');
            matchIcon.innerHTML = badIconSvg;
            matchText.textContent = 'Las contraseñas no coinciden';
            pwd2.focus();
        }
    });
})();
