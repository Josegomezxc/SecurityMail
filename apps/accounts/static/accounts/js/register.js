  (function () {
    const eyeOpenSVG = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    const eyeCloseSVG = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

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

    const bars = document.querySelectorAll('#strengthBar span');
    const levelLabel = document.getElementById('strengthLevel');
    const reqList = document.getElementById('reqList');
    const colors = ['var(--danger)', 'var(--warning)', '#facc15', 'var(--success)'];
    const labels = ['Débil', 'Aceptable', 'Buena', 'Fuerte'];

    function evaluatePwd() {
      const v = pwd1.value;
      const checks = {
        len: v.length >= 8,
        upper: /[A-Z]/.test(v),
        num: /\d/.test(v),
        sym: /[^A-Za-z0-9]/.test(v),
      };

      Object.keys(checks).forEach(k => {
        reqList.querySelector('[data-req="' + k + '"]').classList.toggle('ok', checks[k]);
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

    const matchHint = document.getElementById('matchHint');
    const matchText = document.getElementById('matchText');
    const matchIcon = document.getElementById('matchIcon');
    const okIconSvg = '<polyline points="20 6 9 17 4 12"/>';
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

    // ══════════════════════════════════════════════════════════════
    //  Validación en vivo: nombre + email (clon del backend)
    // ══════════════════════════════════════════════════════════════
    const nameInput = document.getElementById('name-input');
    const nameWrap  = document.getElementById('name-wrap');
    const nameErr   = document.getElementById('name-err');
    const nameErrT  = document.getElementById('name-err-text');

    const emailInput = document.getElementById('email-input');
    const emailWrap  = document.getElementById('email-wrap');
    const emailErr   = document.getElementById('email-err');
    const emailErrT  = document.getElementById('email-err-text');

    // Mismas reglas que validators.py para que UX y backend coincidan
    const USER_RE   = /^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9_\-]*$/;
    const USER_BLOCK = ['admin','administrator','administrador','root','test','testing',
                        'user','usuario','null','undefined','none','demo','guest','bot','system',
                        'api','www','mail','email','support','soporte','help','ayuda','info',
                        'contact','contacto','dockershield','docker','shield'];
    const EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/;

    function normalizeWS(s) {
      return (s || '').replace(/\s+/g, ' ').trim();
    }
    // Para username: elimina TODOS los espacios (interior y borde)
    function stripSpaces(s) {
      return (s || '').replace(/\s+/g, '');
    }

    function setFieldErr(wrap, errBox, txtNode, msg) {
      if (msg) {
        wrap.classList.add('has-error');
        errBox.classList.add('show');
        txtNode.textContent = msg;
      } else {
        wrap.classList.remove('has-error');
        errBox.classList.remove('show');
        txtNode.textContent = '';
      }
    }

    function validateNameLive() {
      const raw  = nameInput.value;
      const user = stripSpaces(raw);   // quita TODOS los espacios
      if (!user) {
        setFieldErr(nameWrap, nameErr, nameErrT, null);
        return false;
      }
      if (user.length < 2) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'El nombre de usuario debe tener al menos 2 caracteres.');
        return false;
      }
      if (user.length > 30) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'Máximo 30 caracteres.');
        return false;
      }
      if (USER_BLOCK.includes(user.toLowerCase())) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'Ese nombre de usuario está reservado, elige otro.');
        return false;
      }
      if (/^\d+$/.test(user)) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'El nombre de usuario no puede ser solo números.');
        return false;
      }
      if (!USER_RE.test(user)) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'Solo letras, números, _ y - . Debe empezar con letra.');
        return false;
      }
      if (/(.)\1{4,}/.test(user)) {
        setFieldErr(nameWrap, nameErr, nameErrT, 'Demasiados caracteres repetidos.');
        return false;
      }
      setFieldErr(nameWrap, nameErr, nameErrT, null);
      return true;
    }

    function validateEmailLive() {
      const raw = emailInput.value;
      if (!raw.trim()) {
        setFieldErr(emailWrap, emailErr, emailErrT, null);
        return false;
      }
      const em = raw.trim().toLowerCase();
      if (/\s/.test(em))                        { setFieldErr(emailWrap, emailErr, emailErrT, 'El correo no puede contener espacios.'); return false; }
      if (em.length > 254)                       { setFieldErr(emailWrap, emailErr, emailErrT, 'El correo es demasiado largo.'); return false; }
      if (!em.includes('@'))                     { setFieldErr(emailWrap, emailErr, emailErrT, 'Falta el "@" en el correo.'); return false; }
      if (em.indexOf('@') !== em.lastIndexOf('@')) { setFieldErr(emailWrap, emailErr, emailErrT, 'El correo tiene más de un "@".'); return false; }
      if (em.includes('..'))                     { setFieldErr(emailWrap, emailErr, emailErrT, 'No puede tener dos puntos seguidos.'); return false; }
      if (em.startsWith('.') || em.endsWith('.')){ setFieldErr(emailWrap, emailErr, emailErrT, 'No puede empezar ni terminar con punto.'); return false; }
      if (!em.split('@')[1].includes('.'))       { setFieldErr(emailWrap, emailErr, emailErrT, 'El dominio debe incluir una extensión (ej. .com).'); return false; }
      if (!EMAIL_RE.test(em))                    { setFieldErr(emailWrap, emailErr, emailErrT, 'El formato del correo no es válido.'); return false; }
      setFieldErr(emailWrap, emailErr, emailErrT, null);
      return true;
    }

    // Nombre de usuario: elimina espacios al vuelo mientras escribes
    // y también al perder el foco, para que no pueda haber ambigüedad.
    nameInput.addEventListener('input', function () {
      const before = this.value;
      const after  = stripSpaces(before);
      if (before !== after) {
        // Preserva posición del cursor (ajustada por los espacios que quitamos)
        const pos = this.selectionStart;
        const removed = before.slice(0, pos).length - stripSpaces(before.slice(0, pos)).length;
        this.value = after;
        try { this.setSelectionRange(pos - removed, pos - removed); } catch (e) {}
      }
      validateNameLive();
      checkSubmit();
    });
    nameInput.addEventListener('blur', function () {
      this.value = stripSpaces(this.value);
      validateNameLive();
      checkSubmit();
    });

    emailInput.addEventListener('blur',  function () { this.value = this.value.trim().toLowerCase(); validateEmailLive(); checkSubmit(); });
    emailInput.addEventListener('input', function () { validateEmailLive(); checkSubmit(); });

    const consents = ['consent1', 'consent2', 'consent3'].map(id => document.getElementById(id));
    const consentAll = document.getElementById('consent-all');
    const progress = document.getElementById('consentProgress');
    const progressText = document.getElementById('consentText');

    function syncMasterState() {
      const acceptedCount = consents.filter(c => c.checked).length;
      // Master = true solo si TODOS están marcados
      consentAll.checked = acceptedCount === consents.length;
      // Estado "indeterminate" para feedback visual cuando hay algunos
      consentAll.indeterminate = acceptedCount > 0 && acceptedCount < consents.length;
    }

    function checkConsents() {
      const accepted = consents.filter(c => c.checked).length;
      progressText.textContent = accepted + ' de 3 consentimientos aceptados';
      progress.classList.toggle('complete', accepted === 3);
      if (accepted === 3) {
        progress.querySelector('svg').innerHTML = '<polyline points="20 6 9 17 4 12"/>';
      } else {
        progress.querySelector('svg').innerHTML = '<circle cx="12" cy="12" r="10"/>';
      }
      syncMasterState();
      checkSubmit();
    }
    consents.forEach(c => c.addEventListener('change', checkConsents));

    // Clic en "Aceptar todo" → marca o desmarca los 3
    consentAll.addEventListener('change', function () {
      consents.forEach(c => { c.checked = consentAll.checked; });
      checkConsents();
    });

    const submitBtn = document.getElementById('submit-btn');
    function checkSubmit() {
      const allConsents = consents.every(c => c.checked);
      const pwdOk   = pwd1.value.length >= 8 && pwd1.value === pwd2.value;
      const nameOk  = !nameWrap.classList.contains('has-error') &&
                      stripSpaces(nameInput.value).length >= 2;
      const emailOk = !emailWrap.classList.contains('has-error') &&
                      emailInput.value.includes('@');
      submitBtn.disabled = !(allConsents && pwdOk && emailOk && nameOk);
    }

    document.getElementById('register-form').addEventListener('submit', () => {
      submitBtn.classList.add('loading');
    });
  })();

  function openModal(type) {
    document.getElementById('modal-overlay').classList.add('open');
    document.getElementById('modal-' + type).classList.add('open');
    document.body.style.overflow = 'hidden';
  }
  function closeModal() {
    document.getElementById('modal-overlay').classList.remove('open');
    document.querySelectorAll('.modal-box').forEach(m => m.classList.remove('open'));
    document.body.style.overflow = '';
  }
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
