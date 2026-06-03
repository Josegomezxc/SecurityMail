/* ══════════════════════════════════════════════════════════════════════
   INBOX (server-side pagination)
   ───────────────────────────────────────────────────────────────────────
   Filtros y búsqueda ahora viven en query params (?filter=, ?q=, ?page=).
   Este JS solo se encarga de:
     - Abrir el panel lateral con el detalle del correo + iframe del HTML
     - Cerrar el panel (X / overlay / ESC / swipe a la derecha en mobile)
     - "Responder" → abre el compose modal pre-llenado
     - "Mover a papelera" (soft delete) — con animación de salida de la fila
     - "Vaciar bandeja" — dropdown con scopes (read/threats/safe/all)
     - Botón clear de la búsqueda (navega a la misma URL sin ?q=)
   ══════════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════
   BÚSQUEDA — clear button
══════════════════════════════════════════ */
function clearSearch() {
  const url = new URL(window.location.href);
  url.searchParams.delete('q');
  url.searchParams.delete('page');
  window.location.href = url.toString();
}

document.addEventListener('DOMContentLoaded', function () {
  const searchInput = document.getElementById('search-input');
  const searchWrap  = document.getElementById('search-form');
  if (!searchInput || !searchWrap) return;

  function syncHasValue() {
    searchWrap.classList.toggle('has-value', !!searchInput.value);
  }
  syncHasValue();

  /* ── Búsqueda en tiempo real ──────────────────────────────────────────
     Cada pulsación arranca un timer de 350ms. Si el usuario sigue
     escribiendo, se cancela y reinicia (debounce). Al soltar la última
     tecla el timer dispara la navegación: una sola URL con ?q=... que
     refresca la página con los resultados paginados del servidor. */
  let debounceTimer = null;
  function scheduleSearch() {
    syncHasValue();
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(submitSearch, 350);
  }
  function submitSearch() {
    const q = searchInput.value.trim();
    const url = new URL(window.location.href);
    if (q) url.searchParams.set('q', q);
    else   url.searchParams.delete('q');
    url.searchParams.delete('page');   // nueva búsqueda → vuelve a página 1
    if (url.toString() !== window.location.href) {
      window.location.href = url.toString();
    }
  }

  searchInput.addEventListener('input', scheduleSearch);

  /* Enter sigue funcionando (dispara la búsqueda inmediatamente sin
     esperar al debounce) — submitSearch hace el navigation directo. */
  searchWrap.addEventListener('submit', function (e) {
    e.preventDefault();
    if (debounceTimer) clearTimeout(debounceTimer);
    submitSearch();
  });
});

/* ══════════════════════════════════════════
   ABRIR EMAIL (panel lateral)
══════════════════════════════════════════ */
function openEmail(id) {
  var data = document.getElementById('detail-' + id);
  if (!data) return;

  /* Marcar como leído — primero en el DOM (feedback inmediato),
     luego persistir en el backend. */
  var row = document.querySelector('.inbox-row[data-id="' + id + '"]');
  if (row && row.dataset.read === 'false') {
    row.classList.remove('unread');
    row.dataset.read = 'true';
    var dot = row.querySelector('.ds-dot');
    if (dot) dot.remove();

    var csrf = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    csrf = csrf ? csrf.split('=')[1] : '';
    fetch('/bandeja/' + id + '/leido/', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
    }).catch(function (e) { console.debug('[read] persist error:', e); });
  }

  /* Rellenar panel */
  document.getElementById('panel-subject').textContent = data.dataset.subject;
  document.getElementById('panel-from').textContent    = data.dataset.from;
  document.getElementById('panel-alias').textContent   = data.dataset.alias;
  document.getElementById('panel-time').textContent    = data.dataset.time;

  /* ── Render del cuerpo: HTML si existe (lazy fetch), texto plano si no ── */
  var emailId      = data.dataset.id;
  var hasHtml      = data.dataset.hasHtml === '1';
  var plainBody    = data.dataset.body || '';
  var iframeWrap   = document.getElementById('panel-body-html-wrap');
  var iframe       = document.getElementById('panel-body-iframe');
  var plainBox     = document.getElementById('panel-body');
  var viewToggle   = document.getElementById('panel-view-toggle');

  window.__smsHtmlCache = window.__smsHtmlCache || {};

  function showPlain() {
    iframeWrap.style.display = 'none';
    plainBox.style.display   = 'block';
    plainBox.textContent     = plainBody || '(Sin cuerpo de mensaje)';
    if (hasHtml) {
      viewToggle.style.display = 'inline-block';
      viewToggle.textContent   = 'VER COMO HTML';
      viewToggle.onclick       = showHtml;
    } else {
      viewToggle.style.display = 'none';
    }
  }

  function setIframeContent(html, withAutoHeight) {
    var old = document.getElementById('panel-body-iframe');
    if (old && old.parentNode) old.parentNode.removeChild(old);
    var fresh = document.createElement('iframe');
    fresh.id  = 'panel-body-iframe';
    fresh.setAttribute('sandbox', '');
    fresh.style.cssText = 'width:100%;min-height:320px;border:0;display:block;background:#ffffff';
    if (withAutoHeight) {
      fresh.addEventListener('load', function () {
        try {
          var h = fresh.contentDocument.body.scrollHeight;
          fresh.style.height = Math.min(Math.max(h + 20, 200), 800) + 'px';
        } catch (e) {}
      });
    }
    iframeWrap.appendChild(fresh);
    fresh.srcdoc = html;
    iframe = fresh;
  }

  function renderIframeFrom(html) {
    iframeWrap.style.display = 'block';
    plainBox.style.display   = 'none';
    setIframeContent(html, true);
    viewToggle.style.display = 'inline-block';
    viewToggle.textContent   = 'VER COMO TEXTO';
    viewToggle.onclick       = showPlain;
  }

  function showHtml() {
    if (!hasHtml) { showPlain(); return; }
    if (window.__smsHtmlCache[emailId]) {
      renderIframeFrom(window.__smsHtmlCache[emailId]);
      return;
    }
    iframeWrap.style.display = 'block';
    plainBox.style.display   = 'none';
    setIframeContent(
      '<!doctype html><html><body style="margin:0;padding:24px;font-family:system-ui;color:#888;text-align:center;background:#fff">'
      + '<div style="display:inline-flex;align-items:center;gap:10px">'
      + '<div style="width:14px;height:14px;border:2px solid #ddd;border-top-color:#7c5cff;border-radius:50%;animation:s 0.7s linear infinite"></div>'
      + 'Cargando correo…</div>'
      + '<style>@keyframes s{to{transform:rotate(360deg)}}</style></body></html>',
      false
    );
    fetch('/bandeja/' + emailId + '/html/', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) {
        window.__smsHtmlCache[emailId] = html;
        renderIframeFrom(html);
      })
      .catch(function (err) {
        console.warn('[inbox] no se pudo cargar el HTML:', err);
        showPlain();
      });
  }

  if (hasHtml) showHtml(); else showPlain();

  /* Riesgo */
  var risk = parseInt(data.dataset.risk) || 0;
  var analysisUrl = data.dataset.analysisUrl || '';
  var riskSection = document.getElementById('panel-risk-section');
  var reportLink = document.getElementById('panel-report-link');

  if (risk > 0 || analysisUrl) {
    riskSection.style.display = 'block';
    var color = risk >= 61 ? 'var(--danger)' : risk >= 31 ? 'var(--warning)' : 'var(--success)';
    var bar   = document.getElementById('panel-risk-bar');
    bar.style.background = color;
    bar.style.width = '0';
    setTimeout(function () { bar.style.width = risk + '%'; }, 80);
    var numEl = document.getElementById('panel-risk-num');
    numEl.textContent = risk + '/100';
    numEl.style.color = color;
    var badge = document.getElementById('panel-risk-badge');
    if (risk >= 61)
      badge.innerHTML = '<span class="risk-pill danger"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>Archivo bloqueado — malware detectado</span>';
    else if (risk >= 31)
      badge.innerHTML = '<span class="risk-pill warning">Comportamiento sospechoso</span>';
    else
      badge.innerHTML = '<span class="risk-pill success"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>Seguro — sin amenazas</span>';

    if (analysisUrl) {
      reportLink.href = analysisUrl;
      reportLink.style.display = 'inline-flex';
    } else {
      reportLink.style.display = 'none';
    }
  } else {
    riskSection.style.display = 'none';
  }

  /* Adjunto */
  var attName = data.dataset.attachment;
  var attSection = document.getElementById('panel-att-section');
  if (attName) {
    attSection.style.display = 'block';
    document.getElementById('panel-att-name-text').textContent = attName;
    var link = document.getElementById('panel-sandbox-link');
    if (analysisUrl) {
      link.href = analysisUrl;
      link.style.display = 'inline-flex';
    } else {
      link.style.display = 'none';
    }
  } else {
    attSection.style.display = 'none';
  }

  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

/* ══════════════════════════════════════════
   CERRAR PANEL
══════════════════════════════════════════ */
function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
  document.body.style.overflow = '';
  document.getElementById('panel-risk-bar').style.width = '0';
}

document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') closeDetail();
});

/* ══════════════════════════════════════════
   SWIPE-TO-CLOSE (mobile)
══════════════════════════════════════════ */
(function setupDetailPanelSwipe() {
  var panel = document.getElementById('detail-panel');
  if (!panel) return;

  var startX = 0, startY = 0, currentX = 0, dragging = false;
  var HORIZONTAL_THRESHOLD = 8;

  panel.addEventListener('touchstart', function (e) {
    if (e.touches.length !== 1) return;
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    currentX = startX;
    dragging = false;
    panel.style.transition = 'none';
  }, { passive: true });

  panel.addEventListener('touchmove', function (e) {
    if (e.touches.length !== 1) return;
    var t = e.touches[0];
    var dx = t.clientX - startX;
    var dy = t.clientY - startY;
    if (!dragging && Math.abs(dy) > Math.abs(dx)) return;
    if (!dragging && Math.abs(dx) < HORIZONTAL_THRESHOLD) return;
    dragging = true;
    if (dx < 0) dx = 0;
    currentX = startX + dx;
    panel.style.transform = 'translateX(' + dx + 'px)';
  }, { passive: true });

  panel.addEventListener('touchend', function () {
    if (!dragging) return;
    panel.style.transition = '';
    var dx = currentX - startX;
    var threshold = panel.offsetWidth * 0.33;
    if (dx >= threshold) {
      panel.style.transform = 'translateX(100%)';
      setTimeout(function () {
        panel.style.transform = '';
        closeDetail();
      }, 180);
    } else {
      panel.style.transform = '';
    }
    dragging = false;
  });
})();

/* ══════════════════════════════════════════
   RESPONDER CORREO
══════════════════════════════════════════ */
function replyFromButton(btn) {
  if (!btn) return;
  if (btn.classList.contains('disabled') || btn.disabled) {
    if (window.showToast) {
      window.showToast({
        type: 'danger', title: 'Alias destruido',
        message: 'No puedes responder: el alias que recibió este correo ya no está activo.',
        duration: 5000,
      });
    }
    return;
  }

  var aliasId    = btn.dataset.aliasId;
  var aliasAddr  = btn.dataset.aliasAddress;
  var aliasLabel = btn.dataset.aliasLabel || '';
  var fromRaw    = btn.dataset.from || '';
  var subject    = btn.dataset.subject || '';
  var bodyText   = btn.dataset.body || '';
  var receivedAt = btn.dataset.time || '';

  var fromEmail = fromRaw;
  var emailMatch = fromRaw.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);
  if (emailMatch) fromEmail = emailMatch[0];
  fromEmail = fromEmail.trim().replace(/^[<"']+|[>"']+$/g, '').trim();

  if (typeof window.openCompose !== 'function') {
    if (window.showToast) {
      window.showToast({
        type: 'danger', title: 'Compose no disponible',
        message: 'Recarga la página e inténtalo de nuevo.',
        duration: 5000,
      });
    }
    return;
  }

  window.openCompose(aliasId, aliasAddr, aliasLabel);

  var subjInput = document.getElementById('composeSubject');
  var editor    = document.getElementById('composeMessage');

  if (typeof window.composeSetRecipients === 'function') {
    window.composeSetRecipients(fromEmail);
  }
  if (subjInput) {
    var hasRePrefix = /^\s*re\s*:/i.test(subject);
    subjInput.value = hasRePrefix ? subject : ('Re: ' + subject);
  }

  if (editor) {
    var esc = function (s) {
      return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };
    var quoted   = esc(bodyText).replace(/\r?\n/g, '<br>');
    var safeFrom = esc(fromRaw || fromEmail);
    var safeWhen = esc(receivedAt);
    editor.innerHTML =
      '<p><br></p><p><br></p>' +
      '<blockquote style="border-left:3px solid #a78bfa;margin:12px 0;padding:8px 14px;color:#9e9cb8;font-size:13px">' +
        '<div style="font-size:11px;color:#6b6884;margin-bottom:6px">' +
          'El ' + safeWhen + ', ' + safeFrom + ' escribió:' +
        '</div>' +
        (quoted || '<em>(sin contenido)</em>') +
      '</blockquote>';
    try {
      editor.focus();
      var range = document.createRange();
      range.setStart(editor, 0); range.collapse(true);
      var sel = window.getSelection();
      sel.removeAllRanges(); sel.addRange(range);
    } catch (e) {}
  }
}

/* ══════════════════════════════════════════
   MOVER A PAPELERA
══════════════════════════════════════════ */
function trashEmail(btn, kind) {
  var id = btn.dataset.emailId;
  if (!id) return;
  var row = btn.closest('.inbox-row, .sent-row, tr');
  if (!row) return;

  var url = (kind === 'outbound')
    ? '/enviados/' + encodeURIComponent(id) + '/papelera/'
    : '/bandeja/' + encodeURIComponent(id) + '/papelera/';

  var csrf = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
  csrf = csrf ? csrf.split('=')[1] : '';

  row.style.transition = 'opacity 0.22s ease, transform 0.22s ease';
  row.style.opacity   = '0';
  row.style.transform = 'translateX(-12px)';

  fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
  })
  .then(function (res) { return res.json(); })
  .then(function (data) {
    if (data && data.ok) {
      setTimeout(function () { row.remove(); }, 240);
      if (window.showToast) {
        window.showToast({
          type: 'danger',
          title: 'Correo movido a Papelera',
          message: 'Lo eliminamos de tu bandeja — se borrará para siempre en 30 días.',
          href: '/papelera/',
          duration: 4500,
        });
      }
    } else {
      row.style.opacity   = '';
      row.style.transform = '';
      if (window.showToast) {
        window.showToast({
          type: 'danger', title: 'No se pudo eliminar',
          message: (data && data.error) || 'Intenta de nuevo', duration: 4000,
        });
      }
    }
  })
  .catch(function () {
    row.style.opacity   = '';
    row.style.transform = '';
    if (window.showToast) {
      window.showToast({
        type: 'danger', title: 'Error de red',
        message: 'No se pudo conectar con el servidor', duration: 4000,
      });
    }
  });
}


/* ════════════════════════════════════════════════════════════════════
   VACIAR BANDEJA — dropdown con scopes (read / threats / safe / all)
   Tras éxito recargamos la página: con paginación server-side la lista
   actual puede haber cambiado drásticamente, mejor releer.
   ════════════════════════════════════════════════════════════════════ */
(function () {
  const wrap   = document.getElementById('inbox-clear-wrap');
  const btn    = document.getElementById('inbox-clear-btn');
  const menu   = document.getElementById('inbox-clear-menu');
  if (!wrap || !btn || !menu) return;

  function getCsrf() {
    const c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
  }
  function setOpen(state) {
    menu.classList.toggle('open', state);
    btn.classList.toggle('open', state);
  }
  btn.addEventListener('click', e => {
    e.stopPropagation();
    setOpen(!menu.classList.contains('open'));
  });
  document.addEventListener('click', e => {
    if (!wrap.contains(e.target)) setOpen(false);
  });
  menu.addEventListener('click', e => e.stopPropagation());

  const SCOPE_META = {
    read: {
      title:   'Borrar correos leídos',
      message: 'Se eliminarán todos los correos que ya marcaste como leídos.\nEsta acción no se puede deshacer.',
      confirm: 'Borrar leídos',
    },
    threats: {
      title:   'Borrar amenazas bloqueadas',
      message: 'Se eliminarán todos los correos con score 61 o superior (amenazas bloqueadas).\nEsta acción no se puede deshacer.',
      confirm: 'Borrar amenazas',
    },
    safe: {
      title:   'Borrar correos seguros',
      message: 'Se eliminarán todos los correos con score 0-30.\nEsta acción no se puede deshacer.',
      confirm: 'Borrar seguros',
    },
    all: {
      title:   'Vaciar TODA la bandeja',
      message: 'Se eliminarán TODOS los correos de tu bandeja sin excepción.\nEsta acción no se puede deshacer.',
      confirm: 'Vaciar todo',
    },
  };

  menu.querySelectorAll('.icm-item[data-scope]').forEach(item => {
    item.addEventListener('click', async () => {
      const scope = item.dataset.scope;
      setOpen(false);
      const meta = SCOPE_META[scope] || SCOPE_META.read;

      const ok = window.confirmDialog
        ? await window.confirmDialog({
            danger: true, icon: 'trash',
            title: meta.title, message: meta.message,
            confirmText: meta.confirm, cancelText: 'Cancelar',
          })
        : confirm(meta.title + '\n\n' + meta.message);
      if (!ok) return;

      try {
        const fd = new FormData();
        fd.append('scope', scope);
        const res = await fetch(window.__INBOX_CTX__.clearUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
          body: fd,
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error || 'error');

        if (window.showToast) {
          window.showToast({
            type: 'success',
            title: 'Correos eliminados',
            message: data.deleted + ' correo' + (data.deleted === 1 ? '' : 's') + ' borrado' + (data.deleted === 1 ? '' : 's'),
            duration: 2500,
          });
        }
        // Releer la lista paginada con los datos actualizados
        setTimeout(function () { window.location.reload(); }, 350);
      } catch (err) {
        if (window.showToast) {
          window.showToast({
            type: 'danger', title: 'No se pudo vaciar',
            message: 'Intenta de nuevo en unos segundos.', duration: 5000,
          });
        }
      }
    });
  });
})();
