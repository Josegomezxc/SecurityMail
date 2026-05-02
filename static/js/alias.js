function copyAlias(btn, address) {
  navigator.clipboard.writeText(address).then(() => {
    btn.classList.add('copied');
    btn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Copiado`;
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copiar`;
    }, 2000);
  });
}

/* Abre el compose modal global (definido en base.html) prellenado con
   los datos del alias seleccionado. */
function aliasOpenCompose(btn) {
  var id    = btn.dataset.aliasId;
  var addr  = btn.dataset.aliasAddress;
  var label = btn.dataset.aliasLabel || '';
  if (typeof window.openCompose === 'function') {
    window.openCompose(id, addr, label);
  } else if (window.showToast) {
    window.showToast({
      type: 'danger',
      title: 'Compose no disponible',
      message: 'Recarga la página e inténtalo de nuevo.',
      duration: 5000,
    });
  }
}

/* ── BÚSQUEDA + FILTROS ── */
var aliasCurrentFilter = 'all';
var aliasCurrentSearch = '';

function aliasSearch(value) {
  aliasCurrentSearch = (value || '').toLowerCase().trim();
  aliasApply();
}
function aliasFilter(type, btn) {
  aliasCurrentFilter = type;
  document.querySelectorAll('.alias-filter-btn').forEach(b =>
    b.classList.remove('active', 'active-success', 'active-neutral'));
  if      (type === 'active')    btn.classList.add('active-success');
  else if (type === 'destroyed') btn.classList.add('active-neutral');
  else                           btn.classList.add('active');
  aliasApply();
}
function aliasApply() {
  var cards = document.querySelectorAll('.alias-card');
  var visible = 0;
  cards.forEach(c => {
    var isActive = c.dataset.active === 'true';
    var label    = c.dataset.label || '';
    var addr     = c.dataset.address || '';

    var passFilter = true;
    if      (aliasCurrentFilter === 'active')    passFilter = isActive;
    else if (aliasCurrentFilter === 'destroyed') passFilter = !isActive;

    var passSearch = true;
    if (aliasCurrentSearch.length > 0) {
      passSearch = label.includes(aliasCurrentSearch) ||
                   addr.includes(aliasCurrentSearch);
    }
    var show = passFilter && passSearch;
    c.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  var noRes = document.getElementById('alias-no-results');
  var msgEl = document.getElementById('alias-no-results-msg');
  var hintEl = document.getElementById('alias-no-results-hint');
  if (visible === 0 && cards.length > 0) {
    noRes.style.display = 'block';
    if (aliasCurrentSearch) {
      msgEl.textContent  = 'Sin alias que coincidan con "' + aliasCurrentSearch + '"';
      hintEl.textContent = 'Prueba otro término o cambia el filtro';
    } else {
      msgEl.textContent  = 'Sin alias en esta categoría';
      hintEl.textContent = '';
    }
  } else {
    noRes.style.display = 'none';
  }
}

/* ── Anti doble-submit del botón "Generar alias" ──
   El usuario ya no escribe nada, así que solo bloqueamos que un doble
   click cree dos alias gastando cuota innecesariamente. */
(function () {
  var form = document.getElementById('alias-create-form');
  var btn  = document.getElementById('alias-create-btn');
  if (!form || !btn) return;

  var isSubmitting = false;
  form.addEventListener('submit', function (e) {
    if (isSubmitting) {
      e.preventDefault();
      return;
    }
    isSubmitting = true;
    btn.disabled = true;
    btn.style.opacity = '0.6';
    btn.style.cursor  = 'wait';
    var svg = btn.querySelector('svg');
    btn.textContent = ' Creando…';
    if (svg) btn.prepend(svg);
  });
})();

/* ── Confirmación bonita al destruir un alias (reemplaza window.confirm) ── */
document.addEventListener('submit', function (e) {
  var form = e.target.closest('.js-destroy-alias');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();
  if (!window.confirmDialog) { form.submit(); return; }
  window.confirmDialog({
    danger:      true,
    icon:        'trash',
    title:       'Destruir alias',
    message:     '¿Seguro que quieres destruir ' + (form.dataset.alias || 'este alias') + '?\nNo se puede reactivar y dejará de recibir correos.',
    confirmText: 'Sí, destruir',
    cancelText:  'Cancelar',
  }).then(function (ok) {
    if (!ok) return;
    form.dataset.confirmed = '1';
    form.submit();
  });
});

