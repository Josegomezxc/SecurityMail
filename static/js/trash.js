function getCsrfTok() {
  var c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
  return c ? c.split('=')[1] : '';
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(function (b) {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  /* "all" muestra los tres grupos juntos; las otras opciones solo el
     grupo correspondiente. */
  var showInbound  = (name === 'all' || name === 'inbound');
  var showOutbound = (name === 'all' || name === 'outbound');
  var showDraft    = (name === 'all' || name === 'draft');
  document.getElementById('tab-inbound').style.display  = showInbound  ? '' : 'none';
  document.getElementById('tab-outbound').style.display = showOutbound ? '' : 'none';
  var draftEl = document.getElementById('tab-draft');
  if (draftEl) draftEl.style.display = showDraft ? '' : 'none';

  /* Los empty-states individuales solo en su propia pestaña, no en "all". */
  var emIn    = document.getElementById('empty-inbound');
  var emOut   = document.getElementById('empty-outbound');
  var emDraft = document.getElementById('empty-draft');
  if (emIn)    emIn.style.display    = (name === 'inbound')  ? '' : 'none';
  if (emOut)   emOut.style.display   = (name === 'outbound') ? '' : 'none';
  if (emDraft) emDraft.style.display = (name === 'draft')    ? '' : 'none';
}

/* Activa "Todos" por defecto al cargar la papelera. */
document.addEventListener('DOMContentLoaded', function () {
  switchTab('all');
});

function restoreEmail(kind, pk) {
  var fd = new FormData();
  fd.append('kind', kind);
  fd.append('pk', pk);
  fetch(window.__TRASH_CTX__.restoreUrl, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRFToken': getCsrfTok(), 'X-Requested-With': 'XMLHttpRequest' },
    body: fd,
  })
  .then(function (r) { return r.json(); })
  .then(function (d) {
    if (d && d.ok) {
      var row = document.getElementById('trash-row-' + kind + '-' + pk);
      if (row) {
        row.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
        row.style.opacity = '0';
        row.style.transform = 'translateX(20px)';
        setTimeout(function () { row.remove(); }, 280);
      }
      if (window.showToast) {
        window.showToast({
          type: 'success',
          title: 'Correo restaurado',
          message: kind === 'inbound'
            ? 'Lo recuperamos de la papelera — ya está de vuelta en tu Bandeja.'
            : 'Lo recuperamos de la papelera — ya está de vuelta en Enviados.',
          duration: 4500,
        });
      }
    } else if (window.showToast) {
      window.showToast({ type: 'danger', title: 'Error', message: 'No se pudo restaurar', duration: 4000 });
    }
  });
}

function purgeEmail(kind, pk) {
  var question = '¿Borrar este correo permanentemente? Esta acción no se puede deshacer.';
  var doIt = function () {
    var fd = new FormData();
    fd.append('kind', kind);
    fd.append('pk', pk);
    fetch(window.__TRASH_CTX__.deleteUrl, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrfTok(), 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.ok) {
        var row = document.getElementById('trash-row-' + kind + '-' + pk);
        if (row) {
          row.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
          row.style.opacity = '0';
          row.style.transform = 'scale(0.96)';
          setTimeout(function () { row.remove(); }, 280);
        }
        if (window.showToast) {
          window.showToast({
            type: 'danger',
            title: 'Correo eliminado para siempre',
            message: 'Lo borramos de la papelera — esta acción no se puede deshacer.',
            duration: 4500,
          });
        }
      }
    });
  };

  if (window.confirmDialog) {
    window.confirmDialog({
      danger: true, icon: 'trash',
      title: 'Borrar permanentemente', message: question,
      confirmText: 'Sí, borrar', cancelText: 'Cancelar',
    }).then(function (ok) { if (ok) doIt(); });
  } else if (confirm(question)) {
    doIt();
  }
}

function emptyTrash() {
  var question = '¿Vaciar TODA la papelera? Se borrarán permanentemente los correos recibidos y enviados que están dentro. No se puede deshacer.';
  var doIt = function () {
    fetch(window.__TRASH_CTX__.emptyUrl, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrfTok(), 'X-Requested-With': 'XMLHttpRequest' },
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.ok) {
        document.querySelectorAll('.trash-row').forEach(function (r) {
          r.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
          r.style.opacity = '0';
          r.style.transform = 'scale(0.96)';
        });
        setTimeout(function () { window.location.reload(); }, 350);
        if (window.showToast) {
          window.showToast({
            type: 'danger',
            title: 'Papelera vaciada',
            message: 'Eliminamos ' + d.deleted + ' correo' + (d.deleted === 1 ? '' : 's') + ' para siempre — no se pueden recuperar.',
            duration: 4500,
          });
        }
      }
    });
  };

  if (window.confirmDialog) {
    window.confirmDialog({
      danger: true, icon: 'trash',
      title: 'Vaciar papelera', message: question,
      confirmText: 'Sí, vaciar', cancelText: 'Cancelar',
    }).then(function (ok) { if (ok) doIt(); });
  } else if (confirm(question)) {
    doIt();
  }
}
