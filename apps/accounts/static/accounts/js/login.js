  (function () {
    const pwdInput = document.getElementById('password-input');
    const eyeBtn = document.getElementById('togglePwd');
    const eyeIcon = document.getElementById('eye-icon');
    const capsWarn = document.getElementById('capsWarning');
    const form = document.getElementById('loginForm');
    const btnLogin = document.getElementById('btnLogin');

    const eyeOpenSVG = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
    const eyeCloseSVG = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';

    eyeBtn.addEventListener('click', function () {
      const showing = pwdInput.type === 'text';
      pwdInput.type = showing ? 'password' : 'text';
      eyeIcon.innerHTML = showing ? eyeOpenSVG : eyeCloseSVG;
    });

    function checkCaps(e) {
      if (e.getModifierState && e.getModifierState('CapsLock')) {
        capsWarn.classList.add('show');
      } else {
        capsWarn.classList.remove('show');
      }
    }
    pwdInput.addEventListener('keydown', checkCaps);
    pwdInput.addEventListener('keyup', checkCaps);
    pwdInput.addEventListener('blur', () => capsWarn.classList.remove('show'));

    // Normaliza el identificador: trim + lowercase (no dañamos la contraseña)
    const emailField = document.getElementById('email-input');
    emailField.addEventListener('blur', function () {
      this.value = this.value.trim().toLowerCase();
    });

    form.addEventListener('submit', function (e) {
      // Normaliza al vuelo antes de enviar
      emailField.value = emailField.value.trim().toLowerCase();

      const ident = emailField.value;
      const pwd = pwdInput.value;

      if (!ident) {
        e.preventDefault();
        emailField.focus();
        return;
      }
      if (!pwd) {
        e.preventDefault();
        pwdInput.focus();
        return;
      }
      if (ident.length > 254 || pwd.length > 128) {
        e.preventDefault();
        return;
      }
      btnLogin.classList.add('loading');
      // El handler global de base.js (data-ds-loader en el <form>) se encarga
      // de mostrar el loader y disparar el submit programático.
    });
  })();
