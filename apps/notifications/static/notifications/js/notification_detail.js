(function () {
  const btnFw = document.getElementById('nd-btn-forward');
  const btnDc = document.getElementById('nd-btn-discard');
  const result = document.getElementById('nd-result');
  const statusEl = document.getElementById('nd-status');
  if (!btnFw || !btnDc) return;

  function getCsrf() {
    const c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
  }
  function show(cls, msg) {
    result.className = 'nd-result show ' + cls;
    result.textContent = msg;
  }
  const userEmail = btnFw.dataset.userEmail || '';
  function disable() {
    btnFw.disabled = true;
    btnDc.disabled = true;
  }
  function action(btn, url, okMsg, statusLabel, statusClass, toastType, toastTitle) {
    btn.disabled = true;
    fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
    })
      .then(async r => {

        let data = null;
        try { data = await r.json(); } catch (e) { /* sin JSON */ }
        return { ok: r.ok, status: r.status, data };
      })
      .then(({ ok, status, data }) => {
        if (ok && data && data.ok) {
          window.dsShowLoader();
          location.reload();
          return;
        }
        let msg;
        const errCode = (data && data.error) || '';
        if (status === 403)                  msg = 'Sesión expirada. Recarga la página.';
        else if (errCode === 'no_actionable') msg = 'Esta notificación ya fue procesada.';
        else if (errCode === 'no_email')     msg = 'El correo asociado ya no existe.';
        else if (status === 500)             msg = 'Error del servidor al reenviar. Revisa la consola.';
        else if (status >= 400 && status < 500) msg = `No se pudo procesar (HTTP ${status}).`;
        else                                  msg = 'Error inesperado. Intenta de nuevo.';
        console.error('[notification-action] fallo', { url, status, data });
        show('err', msg);
        btn.disabled = false;
      })
      .catch(err => {

        console.error('[notification-action] network error', err);
        show('err', 'Error de red. Verifica tu conexión y reintenta.');
        btn.disabled = false;
      });
  }

  const fwUrl   = btnFw.dataset.url;
  const dcUrl   = btnDc.dataset.url;
  const isRisky = btnFw.dataset.risky === '1';

  btnFw.addEventListener('click', async () => {

    if (isRisky && window.confirmDialog) {
      const ok = await window.confirmDialog({
        danger:      true,
        icon:        'warning',
        title:       'Reenviar correo sospechoso',
        message:     'Este correo no es 100% seguro. Si lo reenvías llegará a tu Gmail real.\n¿Estás seguro de que quieres aceptar el riesgo?',
        confirmText: 'Sí, reenviar',
        cancelText:  'Cancelar',
      });
      if (!ok) return;
    }
    action(
      btnFw,
      fwUrl,
      'Correo reenviado con éxito a tu correo principal ' + userEmail,
      'Aprobada — reenviada',
      'nd-status-pill nd-status-approved',
      'success',
      'Reenviado'
    );
  });

  btnDc.addEventListener('click', () => action(
    btnDc,
    dcUrl,
    'Notificación descartada correctamente',
    'Descartada',
    'nd-status-pill nd-status-discarded',
    'danger',
    'Descartado'
  ));
})();
