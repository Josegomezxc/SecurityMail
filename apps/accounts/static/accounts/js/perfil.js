  /* ══════════════════════════════════════════════
     Avatar: click foto = preview, cámara = menú
     ══════════════════════════════════════════════ */
  function onAvatarClick() {
    var box = document.getElementById('avatarBox');
    if (box && box.dataset.hasAvatar === '1') {
      openAvatarPreview();
    } else {
      openAvatarFilePicker();
    }
  }
  function openAvatarFilePicker() {
    closeAvatarMenu();
    document.getElementById('avatarFileInput').click();
  }
  function toggleAvatarMenu() {
    document.getElementById('avatarMenu').classList.toggle('open');
  }
  function closeAvatarMenu() {
    var m = document.getElementById('avatarMenu');
    if (m) m.classList.remove('open');
  }
  function openAvatarPreview() {
    var overlay = document.getElementById('avatarPreviewOverlay');
    var box     = document.getElementById('avatarBox');
    var img     = document.getElementById('avatarPreviewImg');
    if (!overlay || !box || !img) return;
    img.src = box.dataset.avatarUrl || (box.querySelector('img') || {}).src || '';
    overlay.classList.add('visible');
    document.body.style.overflow = 'hidden';
  }
  function closeAvatarPreview() {
    var overlay = document.getElementById('avatarPreviewOverlay');
    if (!overlay) return;
    overlay.classList.remove('visible');
    document.body.style.overflow = '';
  }
  // Cerrar menú al hacer click fuera (botón cámara y menú son hermanos del avatar)
  document.addEventListener('click', function (e) {
    var menu  = document.getElementById('avatarMenu');
    var box   = document.getElementById('avatarBox');
    var btn   = document.querySelector('.avatar-edit-btn');
    if (!menu) return;
    if (menu.contains(e.target)) return;
    if (box && box.contains(e.target)) return;
    if (btn && btn.contains(e.target)) return;
    closeAvatarMenu();
  });
  // Cerrar preview con Escape
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeAvatarPreview();
  });

  // Fallback local de getCsrf por si base.html no lo expone en window
  // (defensivo — el modal de eliminar cuenta NO puede quedar bloqueado
  // por un ReferenceError silencioso).
  function getCsrf() {
    if (typeof window.getCsrf === 'function' && window.getCsrf !== getCsrf) {
      return window.getCsrf();
    }
    var c = document.cookie.split(';').find(function (c) {
      return c.trim().indexOf('csrftoken=') === 0;
    });
    return c ? c.split('=')[1] : '';
  }

  /* ══════════════════════════════════════════════
     Botón "Eliminar mi cuenta" → modal con password + reto "ELIMINAR"
     ══════════════════════════════════════════════
     Flujo:
       1) Usuario aplasta "Eliminar mi cuenta"
       2) Aparece modal con: lista de qué se borrará, input password,
          input "escribe ELIMINAR", botones Cancelar/Eliminar
       3) El botón Eliminar se habilita SOLO si los dos campos están válidos
       4) Submit AJAX → backend borra y devuelve {ok, redirect}
       5) Redirige al login (con mensaje de éxito) */
  (function () {
    var btn = document.getElementById('deleteAccountBtn');
    if (!btn) return;
    var overlay  = document.getElementById('deleteAccountOverlay');
    // Paso 1
    var formEl   = document.getElementById('deleteAccountForm');
    var pwdEl    = document.getElementById('deleteAccountPwd');
    var pwdEye   = document.getElementById('deleteAccountPwdEye');
    var confirmEl= document.getElementById('deleteAccountConfirm');
    var submitEl = document.getElementById('deleteAccountSubmit');
    var cancelEl = document.getElementById('deleteAccountCancel');
    var closeEl  = document.getElementById('deleteAccountClose');
    var errorEl  = document.getElementById('deleteAccountError');
    // Paso 2
    var codeFormEl  = document.getElementById('deleteAccountCodeForm');
    var codeInputEl = document.getElementById('deleteAccountCode');
    var codeSubmitEl = document.getElementById('deleteAccountConfirmFinal');
    var codeResendEl = document.getElementById('deleteAccountResend');
    var codeErrorEl  = document.getElementById('deleteAccountCodeError');
    // Textos del header
    var sub1 = document.getElementById('da-sub-step1');
    var sub2 = document.getElementById('da-sub-step2');
    var impactEl = document.getElementById('da-impact');
    if (!overlay || !formEl || !codeFormEl) return;

    function clearErrors() {
      errorEl.textContent = '';     errorEl.classList.remove('show');
      codeErrorEl.textContent = ''; codeErrorEl.classList.remove('show');
    }

    function showStep1() {
      formEl.style.display = '';
      codeFormEl.style.display = 'none';
      if (sub1) sub1.style.display = '';
      if (sub2) sub2.style.display = 'none';
      if (impactEl) impactEl.style.display = '';
      clearErrors();
    }

    function showStep2() {
      formEl.style.display = 'none';
      codeFormEl.style.display = '';
      if (sub1) sub1.style.display = 'none';
      if (sub2) sub2.style.display = '';
      // En el paso 2 ocultamos el bloque de stats — distrae del foco (código).
      if (impactEl) impactEl.style.display = 'none';
      clearErrors();
      codeInputEl.value = '';
      codeSubmitEl.disabled = true;
      codeSubmitEl.classList.remove('loading');
      setTimeout(function () { codeInputEl.focus(); }, 180);
    }

    function openModal() {
      pwdEl.value = '';
      confirmEl.value = '';
      submitEl.disabled = true;
      submitEl.classList.remove('loading');
      showStep1();
      overlay.classList.add('visible');
      document.body.style.overflow = 'hidden';
      setTimeout(function () { pwdEl.focus(); }, 180);
    }
    function closeModal() {
      overlay.classList.remove('visible');
      document.body.style.overflow = '';
    }
    function refreshSubmit() {
      var ready = pwdEl.value.length > 0 &&
                  confirmEl.value.trim().toUpperCase() === 'ELIMINAR';
      submitEl.disabled = !ready;
    }
    function refreshCodeSubmit() {
      codeSubmitEl.disabled = !/^\d{6}$/.test(codeInputEl.value);
    }

    btn.addEventListener('click', openModal);
    cancelEl.addEventListener('click', closeModal);
    closeEl.addEventListener('click', closeModal);
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closeModal();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && overlay.classList.contains('visible')) closeModal();
    });
    pwdEl.addEventListener('input', refreshSubmit);

    // ── Input de confirmación: solo letras ──────────────────────────
    function isLetter(ch) { return /^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]$/.test(ch); }
    function sanitizeConfirm(s) { return (s || '').replace(/[^A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/g, ''); }

    confirmEl.addEventListener('keydown', function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.length !== 1) return;
      if (!isLetter(e.key)) e.preventDefault();
    });
    confirmEl.addEventListener('input', function () {
      var clean = sanitizeConfirm(confirmEl.value);
      if (clean !== confirmEl.value) confirmEl.value = clean;
      refreshSubmit();
    });
    confirmEl.addEventListener('paste', function (e) {
      e.preventDefault();
      var pasted = (e.clipboardData || window.clipboardData).getData('text');
      var clean  = sanitizeConfirm(pasted);
      var start = confirmEl.selectionStart, end = confirmEl.selectionEnd;
      confirmEl.value = confirmEl.value.slice(0, start) + clean + confirmEl.value.slice(end);
      confirmEl.setSelectionRange(start + clean.length, start + clean.length);
      refreshSubmit();
    });

    // ── Toggle ojo de la password ──────────────────────────────────
    pwdEye.addEventListener('click', function () {
      var hidden = pwdEl.type === 'password';
      pwdEl.type = hidden ? 'text' : 'password';
      pwdEye.querySelector('.eye-open').style.display   = hidden ? 'none' : '';
      pwdEye.querySelector('.eye-closed').style.display = hidden ? ''     : 'none';
    });

    // ── Input código: solo dígitos, 6 chars ────────────────────────
    function sanitizeCode(s) { return (s || '').replace(/\D/g, '').slice(0, 6); }
    codeInputEl.addEventListener('input', function () {
      var clean = sanitizeCode(codeInputEl.value);
      if (clean !== codeInputEl.value) codeInputEl.value = clean;
      refreshCodeSubmit();
    });
    codeInputEl.addEventListener('paste', function (e) {
      e.preventDefault();
      var pasted = (e.clipboardData || window.clipboardData).getData('text');
      codeInputEl.value = sanitizeCode(pasted);
      refreshCodeSubmit();
    });

    // ── Helper genérico para fetch JSON con timeout ────────────────
    function postForm(url, fd, onResp, onErr, errorTarget, retryBtn) {
      var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
      var timeoutId = setTimeout(function () { if (ctrl) ctrl.abort(); }, 20000);

      fetch(url, {
        method:      'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRFToken':      getCsrf(),
          'X-Requested-With': 'XMLHttpRequest',
        },
        body:   fd,
        signal: ctrl ? ctrl.signal : undefined,
      })
      .then(function (r) {
        clearTimeout(timeoutId);
        return r.json().then(
          function (data) { return { status: r.status, data: data }; },
          function ()     { return { status: r.status, data: { ok: false, error: 'Respuesta inválida del servidor (HTTP ' + r.status + ').' } }; }
        );
      })
      .then(onResp)
      .catch(function (err) {
        clearTimeout(timeoutId);
        var msg = (err && err.name === 'AbortError')
          ? 'El servidor tardó demasiado en responder. Recarga la página.'
          : 'Error de red. Comprueba tu conexión.';
        if (errorTarget) {
          errorTarget.textContent = msg;
          errorTarget.classList.add('show');
        }
        if (retryBtn) {
          retryBtn.classList.remove('loading');
          retryBtn.disabled = false;
        }
        if (onErr) onErr(err);
      });
    }

    // ── PASO 1: enviar password + confirm_text → recibe código por email ──
    formEl.addEventListener('submit', function (e) {
      e.preventDefault();
      if (submitEl.disabled) return;
      clearErrors();
      submitEl.classList.add('loading');
      submitEl.disabled = true;

      var fd = new FormData();
      fd.append('password',     pwdEl.value);
      fd.append('confirm_text', confirmEl.value);

      postForm(
        window.__PERFIL_CTX__.deleteAccountUrl,
        fd,
        function (resp) {
          if (resp.data && resp.data.ok) {
            // Código enviado → pasamos al paso 2
            showStep2();
            submitEl.classList.remove('loading');
            if (window.showToast) {
              window.showToast({
                type: 'info',
                title: 'Código enviado',
                message: resp.data.message || 'Revisa tu correo.',
                duration: 4000,
              });
            }
          } else {
            var msg = (resp.data && resp.data.error) || 'No se pudo iniciar la eliminación. Intenta de nuevo.';
            errorEl.textContent = msg;
            errorEl.classList.add('show');
            submitEl.classList.remove('loading');
            refreshSubmit();
            if (resp.status === 401) { pwdEl.value = ''; pwdEl.focus(); }
          }
        },
        function () { /* onErr — manejado en postForm */ },
        errorEl,
        submitEl
      );
    });

    // ── PASO 2: enviar el código → backend hace soft delete ────────
    codeFormEl.addEventListener('submit', function (e) {
      e.preventDefault();
      if (codeSubmitEl.disabled) return;
      clearErrors();
      codeSubmitEl.classList.add('loading');
      codeSubmitEl.disabled = true;

      var fd = new FormData();
      fd.append('code', codeInputEl.value);

      postForm(
        window.__PERFIL_CTX__.deleteAccountConfirmUrl,
        fd,
        function (resp) {
          if (resp.data && resp.data.ok) {
            if (window.showToast) {
              window.showToast({
                type: 'success',
                title: 'Cuenta eliminada',
                message: 'Tu cuenta ha sido cerrada.',
                duration: 4000,
              });
            }
            setTimeout(function () {
              window.location.href = resp.data.redirect || '/';
            }, 600);
          } else {
            var msg = (resp.data && resp.data.error) || 'No pudimos confirmar la eliminación.';
            codeErrorEl.textContent = msg;
            codeErrorEl.classList.add('show');
            codeSubmitEl.classList.remove('loading');
            refreshCodeSubmit();
            // Si el código expiró o no existe, lo más útil es que vuelva al paso 1
            var state = resp.data && resp.data.code_state;
            if (state === 'no_encontrado' || state === 'expirado' || state === 'demasiados') {
              setTimeout(function () { showStep1(); }, 1500);
            } else {
              codeInputEl.value = '';
              codeInputEl.focus();
            }
          }
        },
        function () {},
        codeErrorEl,
        codeSubmitEl
      );
    });

    // ── Reenviar código (vuelve a pegarle al endpoint del paso 1) ──
    codeResendEl.addEventListener('click', function () {
      // El password ya no está en el form, pero el endpoint paso 1 lo
      // requiere. Volvemos al paso 1 para que el usuario re-confirme.
      showStep1();
      if (window.showToast) {
        window.showToast({
          type: 'info',
          title: 'Reenviar código',
          message: 'Confirma tu contraseña otra vez para que te enviemos uno nuevo.',
          duration: 4000,
        });
      }
    });
  })();

  function togglePwd(inputId, btn) {
    const input = document.getElementById(inputId);
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    btn.querySelector('.eye-open').style.display   = isHidden ? 'none' : '';
    btn.querySelector('.eye-closed').style.display = isHidden ? ''     : 'none';
  }

  /* ══════════════════════════════════════════════
     Validación del nombre de usuario en el perfil
     (mismas reglas que validators.py — backend autoritativo)
     ══════════════════════════════════════════════ */
  (function () {
    const USER_RE   = /^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ0-9_\-]*$/;
    const USER_BLOCK = ['admin','administrator','administrador','root','test','testing',
                        'user','usuario','null','undefined','none','demo','guest','bot','system',
                        'api','www','mail','email','support','soporte','help','ayuda','info',
                        'contact','contacto','dockershield','docker','shield'];
    const input  = document.getElementById('name-field');
    const errBox = document.getElementById('name-field-err');
    if (!input || !errBox) return;

    function stripSpaces(s) { return (s || '').replace(/\s+/g, ''); }

    function validate() {
      const u = stripSpaces(input.value);
      let msg = '';
      if (!u)                                      msg = 'El nombre de usuario es obligatorio.';
      else if (u.length < 2)                       msg = 'Debe tener al menos 2 caracteres.';
      else if (u.length > 30)                      msg = 'Máximo 30 caracteres.';
      else if (USER_BLOCK.includes(u.toLowerCase())) msg = 'Ese nombre está reservado, elige otro.';
      else if (/^\d+$/.test(u))                    msg = 'No puede ser solo números.';
      else if (!USER_RE.test(u))                   msg = 'Solo letras, números, _ y - . Empieza con letra.';
      else if (/(.)\1{4,}/.test(u))                msg = 'Demasiados caracteres repetidos.';

      errBox.textContent = msg;
      errBox.style.display = msg ? 'block' : 'none';
      input.style.borderColor = msg ? 'rgba(239,68,68,0.5)' : '';
      return !msg;
    }

    /* Elimina espacios al vuelo mientras escribes */
    input.addEventListener('input', function () {
      const before = this.value;
      const after  = stripSpaces(before);
      if (before !== after) {
        const pos = this.selectionStart;
        const removed = before.slice(0, pos).length - stripSpaces(before.slice(0, pos)).length;
        this.value = after;
        try { this.setSelectionRange(pos - removed, pos - removed); } catch (e) {}
      }
      validate();
    });
    input.addEventListener('blur',  () => { input.value = stripSpaces(input.value); validate(); });

    const form = input.closest('form');
    if (form) {
      form.addEventListener('submit', function (e) {
        input.value = stripSpaces(input.value);
        if (!validate()) {
          e.preventDefault();
          input.focus();
        }
      });
    }
  })();

  /* ══════════════════════════════════════════════
     CAMBIAR CONTRASEÑA — mismas métricas que register:
     barra de fortaleza (4 segmentos), checklist con
     check verde, hint de coincidencia con icono
     dinámico, caps lock detection.
     ══════════════════════════════════════════════ */
  (function () {
    const pwd1 = document.getElementById('pwd1');
    const pwd2 = document.getElementById('pwd2');
    if (!pwd1 || !pwd2) return;

    const capsWarn   = document.getElementById('capsWarning');
    const bars       = document.querySelectorAll('#strengthBar span');
    const levelLabel = document.getElementById('strengthLevel');
    const reqList    = document.getElementById('reqList');
    const matchHint  = document.getElementById('matchHint');
    const matchText  = document.getElementById('matchText');
    const matchIcon  = document.getElementById('matchIcon');
    const submitBtn  = document.getElementById('pwSubmitBtn');

    const colors = ['var(--danger)', 'var(--warning)', '#facc15', 'var(--success)'];
    const labels = ['Débil', 'Aceptable', 'Buena', 'Fuerte'];
    const okIconSvg  = '<polyline points="20 6 9 17 4 12"/>';
    const badIconSvg = '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>';

    function checkCaps(e) {
      if (!capsWarn) return;
      if (e.getModifierState && e.getModifierState('CapsLock')) {
        capsWarn.classList.add('show');
      } else {
        capsWarn.classList.remove('show');
      }
    }
    pwd1.addEventListener('keydown', checkCaps);
    pwd1.addEventListener('keyup', checkCaps);
    pwd1.addEventListener('blur', () => capsWarn && capsWarn.classList.remove('show'));

    function evaluatePwd() {
      const v = pwd1.value;
      const checks = {
        len:   v.length >= 8,
        upper: /[A-Z]/.test(v),
        num:   /\d/.test(v),
        sym:   /[^A-Za-z0-9]/.test(v),
      };

      if (reqList) {
        Object.keys(checks).forEach(k => {
          const el = reqList.querySelector('[data-req="' + k + '"]');
          if (el) el.classList.toggle('ok', checks[k]);
        });
      }

      const score = Object.values(checks).filter(Boolean).length;
      bars.forEach((b, i) => {
        b.style.background = i < score ? colors[score - 1] : 'var(--bg-hover)';
      });

      if (levelLabel) {
        if (v.length === 0) {
          levelLabel.textContent = '—';
          levelLabel.style.color = 'var(--text-muted)';
        } else {
          levelLabel.textContent = labels[score - 1] || 'Débil';
          levelLabel.style.color = colors[Math.max(score - 1, 0)];
        }
      }
    }

    function updateMatch() {
      if (!matchHint) return;
      if (!pwd2.value) { matchHint.classList.remove('show'); return; }
      matchHint.classList.add('show');
      if (pwd1.value === pwd2.value) {
        matchHint.classList.add('ok');
        matchHint.classList.remove('bad');
        if (matchIcon) matchIcon.innerHTML = okIconSvg;
        if (matchText) matchText.textContent = 'Las contraseñas coinciden';
      } else {
        matchHint.classList.add('bad');
        matchHint.classList.remove('ok');
        if (matchIcon) matchIcon.innerHTML = badIconSvg;
        if (matchText) matchText.textContent = 'Las contraseñas no coinciden';
      }
    }

    function checkSubmit() {
      if (!submitBtn) return;
      const pwdOk = pwd1.value.length >= 8 && pwd1.value === pwd2.value;
      submitBtn.disabled = !pwdOk;
    }

    pwd1.addEventListener('input', () => { evaluatePwd(); updateMatch(); checkSubmit(); });
    pwd2.addEventListener('input', () => { updateMatch(); checkSubmit(); });

    const pwForm = document.getElementById('pwForm');
    if (pwForm) {
      pwForm.addEventListener('submit', function (e) {
        if (pwd1.value !== pwd2.value) {
          e.preventDefault();
          if (matchHint) matchHint.classList.add('show', 'bad');
          if (matchHint) matchHint.classList.remove('ok');
          if (matchIcon) matchIcon.innerHTML = badIconSvg;
          if (matchText) matchText.textContent = 'Las contraseñas no coinciden';
          pwd2.focus();
        }
      });
    }
  })();
