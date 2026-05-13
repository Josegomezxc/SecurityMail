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
    var formEl   = document.getElementById('deleteAccountForm');
    var pwdEl    = document.getElementById('deleteAccountPwd');
    var pwdEye   = document.getElementById('deleteAccountPwdEye');
    var confirmEl= document.getElementById('deleteAccountConfirm');
    var submitEl = document.getElementById('deleteAccountSubmit');
    var cancelEl = document.getElementById('deleteAccountCancel');
    var closeEl  = document.getElementById('deleteAccountClose');
    var errorEl  = document.getElementById('deleteAccountError');
    if (!overlay || !formEl) return;

    function openModal() {
      pwdEl.value = '';
      confirmEl.value = '';
      errorEl.textContent = '';
      errorEl.classList.remove('show');
      submitEl.disabled = true;
      submitEl.classList.remove('loading');
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

    // El input de confirmación SOLO acepta letras (A-Z). Bloqueamos en 3
    // capas para que sea imposible meter espacios, números o símbolos:
    //   1) keydown → cancela el evento antes de que se inserte el char
    //   2) input  → limpia paste / IME / autocomplete que escapen del 1
    //   3) beforeinput → fallback para navegadores móviles
    function isLetter(ch) { return /^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]$/.test(ch); }
    function sanitizeConfirm(s) { return (s || '').replace(/[^A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/g, ''); }

    confirmEl.addEventListener('keydown', function (e) {
      // Permite teclas de control (backspace, flechas, tab, etc.)
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.length !== 1) return;        // teclas como ArrowLeft, Backspace
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
      // Inserta el texto limpiado en la posición del cursor
      var start = confirmEl.selectionStart, end = confirmEl.selectionEnd;
      confirmEl.value = confirmEl.value.slice(0, start) + clean + confirmEl.value.slice(end);
      confirmEl.setSelectionRange(start + clean.length, start + clean.length);
      refreshSubmit();
    });

    // Toggle ojo de la password
    pwdEye.addEventListener('click', function () {
      var hidden = pwdEl.type === 'password';
      pwdEl.type = hidden ? 'text' : 'password';
      pwdEye.querySelector('.eye-open').style.display   = hidden ? 'none' : '';
      pwdEye.querySelector('.eye-closed').style.display = hidden ? ''     : 'none';
    });

    formEl.addEventListener('submit', function (e) {
      e.preventDefault();
      if (submitEl.disabled) return;
      errorEl.textContent = '';
      errorEl.classList.remove('show');
      submitEl.classList.add('loading');
      submitEl.disabled = true;

      var fd = new FormData();
      fd.append('password',     pwdEl.value);
      fd.append('confirm_text', confirmEl.value);

      // Salvavidas: si el servidor se cuelga (red, proxy, lo que sea) abortamos
      // a los 15s para que el usuario NUNCA quede con el spinner eterno.
      var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
      var timeoutId = setTimeout(function () { if (ctrl) ctrl.abort(); }, 15000);

      fetch(window.__PERFIL_CTX__.deleteAccountUrl, {
        method:      'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRFToken':       getCsrf(),
          'X-Requested-With':  'XMLHttpRequest',
        },
        body:   fd,
        signal: ctrl ? ctrl.signal : undefined,
      })
      .then(function (r) { clearTimeout(timeoutId); return r.json().then(function (data) { return { status: r.status, data: data }; }, function () { return { status: r.status, data: { ok: false, error: 'Respuesta inválida del servidor (HTTP ' + r.status + ').' } }; }); })
      .then(function (resp) {
        if (resp.data && resp.data.ok) {
          // Cuenta borrada → redirige al login con un toast efímero
          if (window.showToast) {
            window.showToast({
              type: 'success',
              title: 'Cuenta eliminada',
              message: 'Tu cuenta y todos tus datos se han borrado.',
              duration: 4000,
            });
          }
          // Pequeño delay para que el usuario vea el toast antes de redirigir
          setTimeout(function () {
            window.location.href = resp.data.redirect || '/';
          }, 600);
        } else {
          var msg = (resp.data && resp.data.error) || 'No pudimos eliminar la cuenta. Intenta de nuevo.';
          errorEl.textContent = msg;
          errorEl.classList.add('show');
          submitEl.classList.remove('loading');
          refreshSubmit();
          // Si la password fue incorrecta, el usuario suele querer reescribirla
          if (resp.status === 401) {
            pwdEl.value = '';
            pwdEl.focus();
          }
        }
      })
      .catch(function (err) {
        clearTimeout(timeoutId);
        var msg = (err && err.name === 'AbortError')
          ? 'El servidor tardó demasiado en responder. Recarga la página y vuelve a intentar.'
          : 'Error de red. Comprueba tu conexión y vuelve a intentar.';
        errorEl.textContent = msg;
        errorEl.classList.add('show');
        submitEl.classList.remove('loading');
        refreshSubmit();
      });
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
