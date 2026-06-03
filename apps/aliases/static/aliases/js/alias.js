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


/* ════════════════════════════════════════════════════════════════════
   MODAL: solicitar más cupo de alias al administrador
   ════════════════════════════════════════════════════════════════════ */

function openAliasRequestModal() {
  var overlay = document.getElementById('aliasReqOverlay');
  if (!overlay) return;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  _aliasReqUpdateSliderFill();
  _aliasReqUpdateReasonCount();
  setTimeout(function () {
    var slider = document.getElementById('aliasReqAmount');
    if (slider) slider.focus();
  }, 80);
}

function closeAliasRequestModal() {
  var overlay = document.getElementById('aliasReqOverlay');
  if (!overlay) return;
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

(function () {
  var overlay = document.getElementById('aliasReqOverlay');
  if (!overlay) return;
  /* Click fuera del modal cierra. */
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeAliasRequestModal();
  });
  /* Escape cierra. */
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('open')) {
      closeAliasRequestModal();
    }
  });
  /* Slider: fill visual via --p y número grande. */
  var slider = document.getElementById('aliasReqAmount');
  if (slider) {
    slider.addEventListener('input', _aliasReqUpdateSliderFill);
    _aliasReqUpdateSliderFill();
  }
  /* Textarea: contador en vivo. */
  var ta = document.getElementById('aliasReqReason');
  if (ta) ta.addEventListener('input', _aliasReqUpdateReasonCount);
})();

/* ── Quick-picks (+1, +3, +5, +10) ──────────────────────────────────
   Sincronizan el slider, el número grande y el preview. También marcan
   visualmente el chip seleccionado. */
function aliasReqSetAmount(n) {
  var slider = document.getElementById('aliasReqAmount');
  if (!slider) return;
  n = Math.max(parseInt(slider.min, 10), Math.min(parseInt(slider.max, 10), n));
  slider.value = String(n);
  /* Disparamos el handler nativo del oninput para que actualice todo. */
  aliasReqOnSliderChange(n);
}

/* Handler central del slider: actualiza número, fill, preview, y
   el highlight del quick-pick si coincide con un valor "redondo". */
function aliasReqOnSliderChange(value) {
  var n = parseInt(value, 10) || 1;
  /* Número grande de la derecha */
  var numEl = document.getElementById('aliasReqAmountVal');
  if (numEl) numEl.textContent = n;
  /* Fill del slider */
  _aliasReqUpdateSliderFill();
  /* Preview "Si te aprueban" */
  _aliasReqUpdatePreview(n);
  /* Quick-picks: activamos el que coincide */
  var quicks = document.querySelectorAll('.aliasreq-quick');
  quicks.forEach(function (b) {
    var match = parseInt(b.dataset.amount, 10) === n;
    b.classList.toggle('active', match);
  });
}

function _aliasReqUpdatePreview(n) {
  var overlay = document.getElementById('aliasReqOverlay');
  var prevEl  = document.getElementById('aliasReqPreviewNext');
  if (!overlay || !prevEl) return;
  var current = parseInt(overlay.dataset.currentQuota || '0', 10) || 0;
  prevEl.textContent = String(current + n);
}

/* ── Chips de razón predefinida ────────────────────────────────────
   El textarea es readonly: el usuario NO puede escribir libre. Sólo
   puede elegir un chip. Click pone el texto del chip en el textarea y
   marca al chip como activo (los demás se desmarcan). */
function aliasReqSetReason(btn, text) {
  /* Defensa: la firma cambió de (text) → (btn, text). Detectamos qué
     vino y lo acomodamos. Nunca escribimos un HTMLElement en el textarea. */
  if (typeof btn === 'string') {
    /* Llamada legacy: aliasReqSetReason('texto') */
    text = btn;
    btn = null;
  } else if (btn && btn.nodeType === 1 && typeof text !== 'string') {
    /* Recibimos el botón pero NO texto. Intentamos sacar el texto del
       label del propio botón como fallback decente (en lugar de imprimir
       "[object HTMLButtonElement]" en el textarea). */
    text = (btn.textContent || '').trim();
  }
  /* Si aun así no es string, abortamos para no contaminar el textarea. */
  if (typeof text !== 'string') return;

  var ta = document.getElementById('aliasReqReason');
  if (!ta) return;
  ta.value = text;
  _aliasReqUpdateReasonCount();

  /* Activo: el chip clickeado. Los demás vuelven a estado normal. */
  if (btn && btn.classList) {
    var all = document.querySelectorAll('.aliasreq-chip');
    all.forEach(function (c) { c.classList.remove('active'); });
    btn.classList.add('active');
  }
}

function _aliasReqUpdateSliderFill() {
  var slider = document.getElementById('aliasReqAmount');
  if (!slider) return;
  var min = parseFloat(slider.min || '1');
  var max = parseFloat(slider.max || '10');
  var val = parseFloat(slider.value || '1');
  var pct = ((val - min) / (max - min)) * 100;
  slider.style.setProperty('--p', pct + '%');
}

function _aliasReqUpdateReasonCount() {
  var ta = document.getElementById('aliasReqReason');
  var counter = document.getElementById('aliasReqReasonCount');
  if (ta && counter) counter.textContent = ta.value.length;
}

function _aliasReqCsrfToken() {
  var input = document.querySelector('#aliasReqForm input[name="csrfmiddlewaretoken"]');
  if (input && input.value) return input.value;
  var c = document.cookie.split(';').find(function (x) {
    return x.trim().startsWith('csrftoken=');
  });
  return c ? c.split('=')[1] : '';
}

/* Flag a nivel módulo: garantiza UNA sola petición y UN solo reload.
   Sin esto, en algunos casos el submit puede dispararse dos veces (cache
   stale del JS, doble click rápido, evento submit duplicado) y la página
   acaba recargándose dos veces. */
var __aliasReqSending = false;
var __aliasReqReloadScheduled = false;

function submitAliasRequest(ev) {
  if (ev) {
    ev.preventDefault();
    if (ev.stopImmediatePropagation) ev.stopImmediatePropagation();
  }
  /* Lock: si ya hay un submit en vuelo, ignoramos cualquier intento
     adicional (doble click, Enter encolado, etc.). */
  if (__aliasReqSending) return false;
  __aliasReqSending = true;

  var btn = document.getElementById('aliasReqSubmitBtn');
  var url = window.__ALIAS_REQ_URL__;
  if (!url) { __aliasReqSending = false; return false; }

  if (btn) {
    btn.disabled = true;
    var span = btn.querySelector('span');
    if (span) span.textContent = 'Enviando...';
  }

  var fd = new FormData(document.getElementById('aliasReqForm'));

  function _resetBtn() {
    __aliasReqSending = false;
    if (btn) {
      btn.disabled = false;
      var sp = btn.querySelector('span');
      if (sp) sp.textContent = 'Enviar solicitud';
    }
  }

  function _scheduleReload() {
    if (__aliasReqReloadScheduled) return;
    __aliasReqReloadScheduled = true;
    setTimeout(function () { window.location.reload(); }, 800);
  }

  fetch(url, {
    method:      'POST',
    credentials: 'same-origin',
    headers: {
      'X-CSRFToken':      _aliasReqCsrfToken(),
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: fd,
  })
  .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, body: d }; }); })
  .then(function (res) {
    var d = res.body || {};
    if (res.ok && d.ok) {
      closeAliasRequestModal();
      if (window.showToast) {
        window.showToast({
          type:     'success',
          title:    'Solicitud enviada',
          message:  'El admin revisará tu pedido de +' + (d.amount || '?') + ' alias. Te avisaremos por notificaciones.',
          duration: 5000,
        });
      }
      /* Recargamos UNA sola vez para mostrar el pill "Solicitud pendiente". */
      _scheduleReload();
    } else {
      if (window.showToast) {
        window.showToast({
          type:     'danger',
          title:    'No se pudo enviar',
          message:  d.message || 'Intenta de nuevo en un momento.',
          duration: 5000,
        });
      }
      _resetBtn();
    }
  })
  .catch(function () {
    if (window.showToast) {
      window.showToast({
        type:     'danger',
        title:    'Error de red',
        message:  'No pudimos contactar al servidor. Revisa tu conexión.',
        duration: 5000,
      });
    }
    _resetBtn();
  });

  return false;
}

/* ══════════════════════════════════════════
   VER MÁS / VER MENOS (load-more con toggle)
══════════════════════════════════════════ */
var aliasLoadingMore = false;

function loadMoreAlias() {
  if (aliasLoadingMore) return;
  var btn      = document.getElementById('alias-loadmore-btn');
  var collapse = document.getElementById('alias-collapse-btn');
  var list     = document.getElementById('alias-list');
  if (!btn || !list) return;

  var offset = parseInt(list.dataset.nextOffset || '0', 10) || 0;
  aliasLoadingMore = true;
  btn.classList.add('loading');
  btn.disabled = true;

  fetch('/alias/mas/?offset=' + encodeURIComponent(offset), {
    credentials: 'same-origin',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  })
    .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function (data) {
      if (!data || !data.ok) throw new Error('bad response');

      if (data.count > 0) {
        // Append antes del placeholder #alias-no-results
        var noRes = document.getElementById('alias-no-results');
        var tmp = document.createElement('div');
        tmp.innerHTML = data.html.trim();
        while (tmp.firstChild) {
          var node = tmp.firstChild;
          if (node.nodeType === 1 && node.classList && node.classList.contains('alias-card')) {
            node.dataset.loaded = '1';
          }
          if (noRes) list.insertBefore(node, noRes);
          else       list.appendChild(node);
        }
      }

      list.dataset.nextOffset = String(data.next_offset);
      list.dataset.hasMore    = data.has_more ? '1' : '0';

      if (!data.has_more) btn.style.display = 'none';
      if (collapse)       collapse.style.display = '';

      // Re-aplicar filtro+búsqueda a las tarjetas recién insertadas
      if (typeof aliasApply === 'function') aliasApply();
    })
    .catch(function () {
      if (window.showToast) {
        window.showToast({
          type: 'danger',
          title: 'No se pudieron cargar más alias',
          message: 'Intenta de nuevo en unos segundos.',
          duration: 4000,
        });
      }
    })
    .finally(function () {
      aliasLoadingMore = false;
      btn.classList.remove('loading');
      btn.disabled = false;
    });
}

function collapseAlias() {
  var btn      = document.getElementById('alias-loadmore-btn');
  var collapse = document.getElementById('alias-collapse-btn');
  var wrap     = document.getElementById('alias-loadmore-wrap');
  var list     = document.getElementById('alias-list');
  if (!list || !wrap) return;

  list.querySelectorAll('.alias-card[data-loaded="1"]').forEach(function (c) {
    c.remove();
  });

  var initial = parseInt(wrap.dataset.initialCount || '0', 10) || 0;
  list.dataset.nextOffset = String(initial);
  list.dataset.hasMore    = '1';

  if (btn)      btn.style.display = '';
  if (collapse) collapse.style.display = 'none';

  if (typeof aliasApply === 'function') aliasApply();
  list.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

