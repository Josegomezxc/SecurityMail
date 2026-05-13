(function () {
  const inputs   = Array.from(document.querySelectorAll('.code-digit'));
  const hidden   = document.getElementById('codeHidden');
  const submit   = document.getElementById('submitBtn');
  const form     = document.getElementById('verifyForm');

  // Bandera que evita el DOUBLE-SUBMIT (el bug del CSRF 403):
  // si auto-submit + click manual disparan a la vez, el segundo POST
  // llega después de que el servidor ya rotó la sesión → CSRF inválido.
  let isSubmitting = false;

  function fullCode() {
    return inputs.map(i => i.value || '').join('');
  }
  function refresh() {
    const code = fullCode();
    hidden.value = code;
    submit.disabled = isSubmitting || code.length !== 6;
    inputs.forEach(i => i.classList.toggle('filled', i.value !== ''));
  }

  function doSubmit() {
    if (isSubmitting) return;
    isSubmitting = true;
    submit.disabled = true;
    submit.textContent = 'Verificando…';
    inputs.forEach(i => i.disabled = true);
    form.submit();
  }

  // Si el usuario hace click en el botón o presiona Enter, también
  // pasamos por la misma puerta para evitar el doble envío.
  form.addEventListener('submit', (e) => {
    if (isSubmitting) {
      e.preventDefault();
      return;
    }
    isSubmitting = true;
    submit.disabled = true;
    submit.textContent = 'Verificando…';
    inputs.forEach(i => i.disabled = true);
    // dejamos que el submit nativo continúe
  });

  inputs.forEach((inp, idx) => {
    inp.addEventListener('input', () => {
      if (isSubmitting) return;
      // Permitir solo dígitos
      inp.value = (inp.value || '').replace(/[^\d]/g, '').slice(0, 1);
      refresh();
      if (inp.value && idx < inputs.length - 1) {
        inputs[idx + 1].focus();
      }
    });
    inp.addEventListener('keydown', (e) => {
      if (isSubmitting) { e.preventDefault(); return; }
      if (e.key === 'Backspace' && !inp.value && idx > 0) {
        inputs[idx - 1].focus();
        inputs[idx - 1].value = '';
        refresh();
      }
      if (e.key === 'ArrowLeft' && idx > 0) inputs[idx - 1].focus();
      if (e.key === 'ArrowRight' && idx < inputs.length - 1) inputs[idx + 1].focus();
    });
    inp.addEventListener('paste', (e) => {
      if (isSubmitting) { e.preventDefault(); return; }
      const text = (e.clipboardData || window.clipboardData).getData('text');
      const digits = (text || '').replace(/[^\d]/g, '').slice(0, 6);
      if (!digits) return;
      e.preventDefault();
      digits.split('').forEach((d, i) => {
        if (inputs[i]) inputs[i].value = d;
      });
      refresh();
      const next = Math.min(digits.length, inputs.length - 1);
      inputs[next].focus();
    });
  });

  // Auto-submit cuando se completen los 6 dígitos (con guard anti-doble)
  form.addEventListener('input', () => {
    if (isSubmitting) return;
    if (fullCode().length === 6) {
      setTimeout(doSubmit, 120);
    }
  });

  refresh();

  /* ── Cuenta regresiva del código ── */
  const cd = document.getElementById('countdown');
  const expiresAt = cd ? new Date(cd.dataset.expiresAt) : null;
  function tick() {
    if (!expiresAt) return;
    const now = new Date();
    const ms = expiresAt - now;
    if (ms <= 0) {
      cd.textContent = 'El código expiró — pide uno nuevo.';
      cd.classList.add('expired');
      submit.disabled = true;
      return;
    }
    const m = Math.floor(ms / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    cd.textContent = `Expira en ${m}:${String(s).padStart(2, '0')}`;
  }
  if (expiresAt) {
    tick();
    setInterval(tick, 1000);
  }
})();
