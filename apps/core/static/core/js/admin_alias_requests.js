function aarOnlyDigits(e) {
  var ctrl = e.ctrlKey || e.metaKey;
  var allowed = ['Backspace','Delete','Tab','Escape','Enter',
                 'Home','End','ArrowLeft','ArrowRight','ArrowUp','ArrowDown'];
  if (allowed.indexOf(e.key) !== -1) return true;
  if (ctrl && ['a','c','v','x','z','A','C','V','X','Z'].indexOf(e.key) !== -1) return true;
  if (/^[0-9]$/.test(e.key)) return true;
  e.preventDefault();
  return false;
}
function aarOnPaste(e) {
  e.preventDefault();
  var data = (e.clipboardData || window.clipboardData).getData('text') || '';
  var digits = data.replace(/\D/g, '').slice(0, 2);
  if (digits) {
    e.target.value = digits;
    aarOnGrantInput(e.target);
  }
}

function aarStepGrant(btn, delta) {
  var form  = btn.closest('form');
  var input = form && form.querySelector('.js-aar-grant-input');
  if (!input) return;
  var min = parseInt(input.dataset.min, 10) || 1;
  var max = parseInt(input.dataset.max, 10) || 50;
  var v   = parseInt(input.value, 10) || min;
  input.value = String(Math.max(min, Math.min(max, v + delta)));
  aarOnGrantInput(input);
}

function aarOnGrantInput(input) {
  var cleaned = (input.value || '').replace(/\D/g, '').slice(0, 2);
  if (cleaned !== input.value) input.value = cleaned;

  var n = parseInt(input.value, 10);
  if (isNaN(n) || n < 1) n = 0;

  var form = input.closest('form');
  if (!form) return;
  var prevEl = form.querySelector('.js-aar-preview-amount');
  var btnEl  = form.querySelector('.js-aar-btn-amount');
  var txt = '+' + (n || '?');
  if (prevEl) prevEl.textContent = txt;
  if (btnEl)  btnEl.textContent  = txt;

  var deltaEl = form.querySelector('.js-aar-delta');
  if (deltaEl) aarUpdateDelta(deltaEl, n);
}

function aarUpdateDelta(deltaEl, granted) {
  var requested = parseInt(deltaEl.dataset.requested, 10) || 0;
  var diff = granted - requested;

  var headEl = deltaEl.querySelector('.aar-delta-headline');
  var hintEl = deltaEl.querySelector('.aar-delta-hint');
  var iconWrap = deltaEl.querySelector('.aar-delta-icon');
  if (!headEl || !hintEl || !iconWrap) return;

  deltaEl.classList.remove('is-equal', 'is-less', 'is-more');

  var SVG_CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
  var SVG_DOWN  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>';
  var SVG_UP    = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>';

  if (granted <= 0) {
    deltaEl.classList.add('is-less');
    headEl.textContent = 'Sin asignar';
    hintEl.textContent = 'Ingresá un número para conceder alias.';
    iconWrap.innerHTML = SVG_DOWN;
  } else if (diff === 0) {
    deltaEl.classList.add('is-equal');
    headEl.textContent = 'Igual a lo pedido';
    hintEl.textContent = 'El usuario recibe exactamente lo que solicitó.';
    iconWrap.innerHTML = SVG_CHECK;
  } else if (diff < 0) {
    deltaEl.classList.add('is-less');
    headEl.textContent = diff + ' vs lo pedido';
    hintEl.textContent = 'Le das menos: pidió +' + requested + ', recibirá +' + granted + '.';
    iconWrap.innerHTML = SVG_DOWN;
  } else {
    deltaEl.classList.add('is-more');
    headEl.textContent = '+' + diff + ' vs lo pedido';
    hintEl.textContent = 'Le das más: pidió +' + requested + ', recibirá +' + granted + '.';
    iconWrap.innerHTML = SVG_UP;
  }
}

document.addEventListener('blur', function (e) {
  if (e.target && e.target.classList && e.target.classList.contains('js-aar-grant-input')) {
    var min = parseInt(e.target.dataset.min, 10) || 1;
    var max = parseInt(e.target.dataset.max, 10) || 50;
    var v   = parseInt(e.target.value, 10);
    if (isNaN(v) || v < min) e.target.value = String(min);
    else if (v > max)        e.target.value = String(max);
    aarOnGrantInput(e.target);
  }
}, true);

function aarSetNote(btn, text) {
  var form = btn.closest('form');
  var ta = form && form.querySelector('.js-aar-note');
  if (!ta) return;
  ta.value = text;
  var chips = form.querySelectorAll('.aar-note-chip');
  chips.forEach(function (c) { c.classList.remove('active'); });
  btn.classList.add('active');
  aarSyncApproveState(form);
}

function aarSyncApproveState(form) {
  var approveBtn = form.querySelector('.aar-btn-approve');
  if (!approveBtn) return;
  var activeChip = form.querySelector('.aar-note-chip.active');
  var tone = activeChip && activeChip.dataset.tone;

  if (tone === 'reject' || tone === 'info') {
    approveBtn.disabled = true;
    approveBtn.setAttribute('aria-disabled', 'true');
    approveBtn.title = (tone === 'reject')
      ? 'Elegiste un mensaje de rechazo. Para aprobar, seleccioná otro chip.'
      : 'Elegiste un mensaje pidiendo más información. Para aprobar, seleccioná otro chip.';
  } else {
    approveBtn.disabled = false;
    approveBtn.removeAttribute('aria-disabled');
    approveBtn.title = '';
  }
}

(function () {
  const form  = document.getElementById('aar-search-form');
  const input = document.getElementById('aar-search-input');
  if (!form || !input) return;

  function syncHasValue() {
    form.classList.toggle('has-value', !!input.value);
  }
  syncHasValue();

  let timer = null;
  function go() {
    const q = input.value.trim();
    const url = new URL(window.location.href);
    if (q) url.searchParams.set('q', q);
    else   url.searchParams.delete('q');
    url.searchParams.delete('page');
    if (url.toString() !== window.location.href) {
      window.location.href = url.toString();
    }
  }
  input.addEventListener('input', function () {
    syncHasValue();
    if (timer) clearTimeout(timer);
    timer = setTimeout(go, 350);
  });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (timer) clearTimeout(timer);
    go();
  });
})();

function aarClearSearch() {
  const url = new URL(window.location.href);
  url.searchParams.delete('q');
  url.searchParams.delete('page');
  window.location.href = url.toString();
}

function aarOpenDetail(rowEl) {
  var targetId = rowEl && rowEl.dataset.modalTarget;
  if (!targetId) return;
  var tpl = document.getElementById(targetId);
  var modal   = document.getElementById('aarModalOverlay');
  var bodyEl  = document.getElementById('aarModalBody');
  if (!tpl || !modal || !bodyEl) return;

  bodyEl.innerHTML = '';
  bodyEl.appendChild(tpl.content.cloneNode(true));

  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function aarCloseDetail() {
  var modal = document.getElementById('aarModalOverlay');
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

(function () {
  var modal = document.getElementById('aarModalOverlay');
  if (!modal) return;
  modal.addEventListener('click', function (e) {
    if (e.target === modal) aarCloseDetail();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && modal.classList.contains('open')) aarCloseDetail();
  });
})();

(function () {
  var params = new URLSearchParams(window.location.search);
  var openId = params.get('open');
  if (!openId) return;

  function tryOpen() {
    var pending = document.querySelector('.aar-card[data-req-id="' + openId + '"]');
    if (pending) {
      pending.scrollIntoView({ behavior: 'smooth', block: 'center' });
      pending.classList.add('aar-flash');
      setTimeout(function () { pending.classList.remove('aar-flash'); }, 2400);
      return true;
    }
    var row = document.querySelector('.aar-row[data-modal-target="aar-detail-' + openId + '"]');
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(function () { aarOpenDetail(row); }, 360);
      return true;
    }
    return false;
  }

  if (!tryOpen()) {
    var allBtn = document.querySelector('.aar-filter-pill[data-filter="all"]');
    if (allBtn) allBtn.click();
    setTimeout(tryOpen, 80);
  }

  if (window.history && window.history.replaceState) {
    params.delete('open');
    var clean = window.location.pathname +
                (params.toString() ? '?' + params.toString() : '') +
                window.location.hash;
    window.history.replaceState({}, '', clean);
  }
})();

function injectAction(form, value) {
  var h = form.querySelector('input[name="action"][data-iar-injected]');
  if (!h) {
    h = document.createElement('input');
    h.type = 'hidden';
    h.name = 'action';
    h.setAttribute('data-iar-injected', '');
    form.appendChild(h);
  }
  h.value = value;
}

function aarConfirmApprove(ev, btn) {
  injectAction(btn.closest('form'), 'approve');
  return true;
}
function aarConfirmReject(ev, btn) {
  if (btn.dataset.aarConfirmed === '1') return true;
  ev.preventDefault();

  var email = btn.dataset.userEmail || 'este usuario';
  var form  = btn.closest('form');

  aarCloseDetail();

  var doSubmit = function () {
    btn.dataset.aarConfirmed = '1';
    injectAction(form, 'reject');
    window.dsShowLoader();
    form.submit();
  };

  if (window.confirmDialog) {
    window.confirmDialog({
      danger:      true,
      icon:        'trash',
      title:       'Rechazar solicitud',
      message:     '¿Rechazar la solicitud de ' + email + '? El usuario recibirá una notificación con tu motivo (si lo agregaste).',
      confirmText: 'Sí, rechazar',
      cancelText:  'Cancelar',
    }).then(function (ok) { if (ok) doSubmit(); });
  } else {
    if (confirm('¿Rechazar la solicitud de ' + email + '?')) doSubmit();
  }
  return false;
}
