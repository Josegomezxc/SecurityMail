function getCsrfTok() {
  var c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
  return c ? c.split('=')[1] : '';
}

/* Reanuda el borrador en el compose modal global (incluido por base.html). */
function resumeDraft(id) {
  if (typeof window.openDraft === 'function') {
    window.openDraft(id);
  } else if (window.showToast) {
    window.showToast({
      type: 'danger',
      title: 'Compose no disponible',
      message: 'Recarga la página e inténtalo de nuevo.',
      duration: 4000,
    });
  }
}

/* Mueve el borrador a la papelera (soft-delete). Lo puedes restaurar
   desde /papelera/ durante 30 días. */
function deleteDraft(id) {
  fetch('/borradores/' + id + '/eliminar/', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRFToken': getCsrfTok(), 'X-Requested-With': 'XMLHttpRequest' },
  })
  .then(function (r) { return r.json(); })
  .then(function (d) {
    if (d && d.ok) {
      var row = document.getElementById('draft-row-' + id);
      if (row) {
        row.style.transition = 'opacity 0.25s ease, transform 0.25s ease, max-height 0.25s ease 0.1s, margin 0.25s ease 0.1s, padding 0.25s ease 0.1s';
        row.style.transform = 'translateX(-30px)';
        row.style.opacity   = '0';
        requestAnimationFrame(function () {
          row.style.maxHeight     = '0';
          row.style.marginTop     = '0';
          row.style.marginBottom  = '0';
          row.style.paddingTop    = '0';
          row.style.paddingBottom = '0';
          row.style.borderWidth   = '0';
          setTimeout(function () { row.remove(); }, 350);
        });
      }
      if (window.showToast) {
        window.showToast({
          type:    'danger',
          title:   'Borrador movido a Papelera',
          message: 'Lo quitamos de tus borradores — se borrará para siempre en 30 días.',
          duration: 4500,
        });
      }
    }
  });
}

/* Filtra la lista de borradores: 'all' | 'no-recipient' | 'scheduled'. */
function filterDrafts(filter, btn) {
  document.querySelectorAll('.dr-tab-btn').forEach(function (b) {
    b.classList.toggle('active', b === btn);
  });
  var rows    = document.querySelectorAll('.dr-row');
  var visible = 0;
  rows.forEach(function (r) {
    var show = true;
    if (filter === 'no-recipient') show = r.dataset.hasRecipient === '0';
    else if (filter === 'scheduled') show = r.dataset.scheduled === '1';
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  var noRes = document.getElementById('dr-no-results');
  var msg   = document.getElementById('dr-no-results-msg');
  if (noRes) {
    if (visible === 0 && rows.length > 0) {
      noRes.style.display = 'block';
      if (filter === 'no-recipient') msg.textContent = 'Todos tus borradores tienen destinatario';
      else if (filter === 'scheduled') msg.textContent = 'No hay borradores programados';
      else msg.textContent = 'Sin borradores en este filtro';
    } else {
      noRes.style.display = 'none';
    }
  }
}

/* Manda TODOS los borradores activos a la papelera. */
function emptyDrafts() {
  var doIt = function () {
    fetch('/borradores/vaciar/', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrfTok(), 'X-Requested-With': 'XMLHttpRequest' },
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.ok) {
        document.querySelectorAll('.dr-row').forEach(function (r) {
          r.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
          r.style.opacity = '0';
          r.style.transform = 'scale(0.96)';
        });
        setTimeout(function () { window.location.reload(); }, 350);
        if (window.showToast) {
          window.showToast({
            type:    'danger',
            title:   'Borradores movidos a Papelera',
            message: 'Mandamos ' + d.moved + ' borrador' + (d.moved === 1 ? '' : 'es') + ' a la papelera — se borran para siempre en 30 días.',
            duration: 5000,
          });
        }
      }
    });
  };

  if (window.confirmDialog) {
    window.confirmDialog({
      danger: true, icon: 'trash',
      title: 'Vaciar borradores',
      message: '¿Mover TODOS los borradores a la papelera? Podrás restaurarlos durante 30 días.',
      confirmText: 'Sí, vaciar', cancelText: 'Cancelar',
    }).then(function (ok) { if (ok) doIt(); });
  } else if (confirm('¿Mover todos los borradores a la papelera?')) {
    doIt();
  }
}
