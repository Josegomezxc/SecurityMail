(function () {
  const form  = document.getElementById('arr-search-form');
  const input = document.getElementById('arr-search-input');
  if (!form || !input) return;
  function syncHasValue() { form.classList.toggle('has-value', !!input.value); }
  syncHasValue();
  let timer = null;
  function go() {
    const q = input.value.trim();
    const url = new URL(window.location.href);
    if (q) url.searchParams.set('q', q); else url.searchParams.delete('q');
    url.searchParams.delete('page');
    if (url.toString() !== window.location.href) window.location.href = url.toString();
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
function arrClearSearch() {
  const url = new URL(window.location.href);
  url.searchParams.delete('q');
  url.searchParams.delete('page');
  window.location.href = url.toString();
}

function arrOpenDetail(rowEl) {
  var targetId = rowEl && rowEl.dataset.modalTarget;
  if (!targetId) return;
  var tpl = document.getElementById(targetId);
  var modal  = document.getElementById('arrModalOverlay');
  var bodyEl = document.getElementById('arrModalBody');
  if (!tpl || !modal || !bodyEl) return;
  bodyEl.innerHTML = '';
  bodyEl.appendChild(tpl.content.cloneNode(true));
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}
function arrCloseDetail() {
  var modal = document.getElementById('arrModalOverlay');
  if (!modal) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}
(function () {
  var modal = document.getElementById('arrModalOverlay');
  if (!modal) return;
  modal.addEventListener('click', function (e) { if (e.target === modal) arrCloseDetail(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && modal.classList.contains('open')) arrCloseDetail();
  });
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

function arrConfirmApprove(ev, btn) {
  injectAction(btn.closest('form'), 'approve');
  arrCloseDetail();
  return true;
}
function arrConfirmReject(ev, btn) {
  var email = btn.dataset.userEmail || 'este usuario';
  arrCloseDetail();
  injectAction(btn.closest('form'), 'reject');
  if (!window.confirm('¿Rechazar la recuperación de ' + email + '?\n\n'
                    + 'La cuenta quedará bloqueada y el usuario recibirá tu nota.')) {
    ev.preventDefault();
    return false;
  }
  return true;
}

(function () {
  var openId = new URLSearchParams(window.location.search).get('open');
  if (!openId) return;
  var row = document.querySelector('.aar-tr[data-modal-target="arr-detail-' + openId + '"]');
  if (row) {
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(function () { arrOpenDetail(row); }, 360);
  }
  if (window.history && window.history.replaceState) {
    var params = new URLSearchParams(window.location.search);
    params.delete('open');
    var clean = window.location.pathname +
                (params.toString() ? '?' + params.toString() : '') +
                window.location.hash;
    window.history.replaceState({}, '', clean);
  }
})();
