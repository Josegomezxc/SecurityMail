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
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        if (data.ok) {
          disable();
          show('ok', okMsg);
          if (statusEl) {
            statusEl.textContent = statusLabel;
            statusEl.className = 'nd-status-pill ' + statusClass;
          }
        } else {
          show('err', 'No se pudo procesar la acción.');
          btn.disabled = false;
        }
      })
      .catch(() => {
        show('err', 'Error de red. Intenta de nuevo.');
        btn.disabled = false;
      });
  }

  const id = btnFw.dataset.id;
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
      `/notificaciones/${id}/reenviar/`,
      '✓ Listo. El correo está en camino a tu Gmail.',
      'Aprobada — reenviada',
      'nd-status-pill nd-status-approved'
    );
  });

  btnDc.addEventListener('click', () => action(
    btnDc,
    `/notificaciones/${id}/descartar/`,
    '✓ Descartado. El correo sigue en tu bandeja pero no se reenvió.',
    'Descartada',
    'nd-status-pill nd-status-discarded'
  ));
})();
