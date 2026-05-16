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
  function disable() {
    btnFw.disabled = true;
    btnDc.disabled = true;
  }
  function action(btn, url, okMsg, statusLabel, statusClass) {
    btn.disabled = true;
    fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
    })
      .then(async r => {
        // Intentamos leer el body como JSON aunque el status no sea 2xx.
        // El backend devuelve {ok:false, error:'no_actionable'} con 400, etc.
        let data = null;
        try { data = await r.json(); } catch (e) { /* sin JSON */ }
        return { ok: r.ok, status: r.status, data };
      })
      .then(({ ok, status, data }) => {
        if (ok && data && data.ok) {
          disable();
          show('ok', okMsg);
          if (statusEl) {
            statusEl.textContent = statusLabel;
            statusEl.className = 'nd-status-pill ' + statusClass;
          }
          return;
        }
        // Hubo error. Mapeamos códigos comunes a mensajes legibles.
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
        // Sólo entra acá si la petición NO se completó (DNS, offline, CORS).
        console.error('[notification-action] network error', err);
        show('err', 'Error de red. Verifica tu conexión y reintenta.');
        btn.disabled = false;
      });
  }

  // El template inyecta la URL completa con {% url ... notif.id %} en
  // data-url. Antes el JS leía data-id (no existe), generando POSTs a
  // /notificaciones/undefined/reenviar/ que respondían 404.
  const fwUrl   = btnFw.dataset.url;
  const dcUrl   = btnDc.dataset.url;
  const isRisky = btnFw.dataset.risky === '1';

  btnFw.addEventListener('click', async () => {
    // Si el correo es sospechoso (score 31-60), pedimos confirmación
    // explícita con el modal danger antes de reenviar a Gmail.
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
      '✓ Listo. El correo está en camino a tu Gmail.',
      'Aprobada — reenviada',
      'nd-status-pill nd-status-approved'
    );
  });

  btnDc.addEventListener('click', () => action(
    btnDc,
    dcUrl,
    '✓ Descartado. El correo sigue en tu bandeja pero no se reenvió.',
    'Descartada',
    'nd-status-pill nd-status-discarded'
  ));
})();
