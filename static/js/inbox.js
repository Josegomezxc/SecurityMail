/* ══════════════════════════════════════════
   ESTADO GLOBAL
══════════════════════════════════════════ */
var currentFilter = 'all';
var currentSearch = '';

/* ══════════════════════════════════════════
   INICIALIZAR AL CARGAR
══════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', function () {

  /* Conectar clicks de los botones de filtro */
  document.querySelectorAll('.qfilter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      setFilter(btn.dataset.filter);
    });
  });

  /* Calcular y mostrar contadores */
  updateCounts();
});

/* ══════════════════════════════════════════
   CONTADORES
══════════════════════════════════════════ */
function updateCounts() {
  var rows = document.querySelectorAll('.email-row');
  var total = rows.length;
  var unread = 0, att = 0, danger = 0, safe = 0;

  rows.forEach(function (r) {
    var risk = parseInt(r.dataset.risk) || 0;
    if (r.dataset.read === 'false') unread++;
    if (r.dataset.attachment === 'true') att++;
    if (risk >= 61) danger++;
    if (risk > 0 && risk <= 30) safe++;
  });

  /* Hero stats */
  document.getElementById('stat-total').textContent   = total;
  document.getElementById('stat-unread').textContent  = unread;
  document.getElementById('stat-threats').textContent = danger;

  /* Badges en los botones de filtro */
  document.getElementById('qb-all').textContent    = total;
  document.getElementById('qb-unread').textContent = unread;
  document.getElementById('qb-att').textContent    = att;
  document.getElementById('qb-danger').textContent = danger;
  document.getElementById('qb-safe').textContent   = safe;
}

/* ══════════════════════════════════════════
   BÚSQUEDA
══════════════════════════════════════════ */
function onSearchInput(value) {
  currentSearch = value.toLowerCase().trim();

  /* Mostrar/ocultar botón de limpiar */
  var clearBtn = document.getElementById('search-clear');
  if (currentSearch.length > 0) {
    clearBtn.classList.add('visible');
  } else {
    clearBtn.classList.remove('visible');
  }

  applyFilters();
}

function clearSearch() {
  document.getElementById('search-input').value = '';
  document.getElementById('search-clear').classList.remove('visible');
  currentSearch = '';
  applyFilters();
  document.getElementById('search-input').focus();
}

/* ══════════════════════════════════════════
   FILTROS
══════════════════════════════════════════ */
function setFilter(type) {
  currentFilter = type;

  /* Actualizar clases visuales de los botones */
  document.querySelectorAll('.qfilter-btn').forEach(function (btn) {
    btn.classList.remove('active', 'active-danger', 'active-success', 'active-warning');
  });

  var activeBtn = document.querySelector('.qfilter-btn[data-filter="' + type + '"]');
  if (activeBtn) {
    if (type === 'danger')     activeBtn.classList.add('active-danger');
    else if (type === 'safe')  activeBtn.classList.add('active-success');
    else if (type === 'attachment') activeBtn.classList.add('active-warning');
    else                       activeBtn.classList.add('active');
  }

  applyFilters();
}

/* ══════════════════════════════════════════
   APLICAR FILTRO + BÚSQUEDA COMBINADOS
══════════════════════════════════════════ */
function applyFilters() {
  var rows = document.querySelectorAll('.email-row');
  var visible = 0;

  rows.forEach(function (row) {
    var risk    = parseInt(row.dataset.risk) || 0;
    var isUnread = row.dataset.read === 'false';
    var hasAtt   = row.dataset.attachment === 'true';

    /* 1. Aplicar filtro de categoría */
    var passFilter = true;
    if (currentFilter === 'unread')     passFilter = isUnread;
    if (currentFilter === 'attachment') passFilter = hasAtt;
    if (currentFilter === 'danger')     passFilter = risk >= 61;
    if (currentFilter === 'safe')       passFilter = risk > 0 && risk <= 30;

    /* 2. Aplicar búsqueda de texto (AND con el filtro) */
    var passSearch = true;
    if (currentSearch.length > 0) {
      var fromVal    = (row.dataset.from    || '').toLowerCase();
      var subjectVal = (row.dataset.subject || '').toLowerCase();
      var bodyVal    = (row.dataset.body    || '').toLowerCase();
      passSearch = fromVal.includes(currentSearch)
                || subjectVal.includes(currentSearch)
                || bodyVal.includes(currentSearch);
    }

    var show = passFilter && passSearch;
    row.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  /* Mensaje de "sin resultados" */
  var noResults = document.getElementById('no-results');
  var msgEl     = document.getElementById('no-results-msg');
  var hintEl    = document.getElementById('no-results-hint');

  if (visible === 0 && rows.length > 0) {
    noResults.style.display = 'block';
    if (currentSearch.length > 0) {
      msgEl.textContent  = 'Sin resultados para "' + currentSearch + '"';
      hintEl.textContent = 'Prueba con otro término o cambia el filtro activo';
    } else {
      msgEl.textContent  = 'No hay correos en esta categoría';
      hintEl.textContent = 'Selecciona "Todos" para ver todos los mensajes';
    }
  } else {
    noResults.style.display = 'none';
  }
}

/* ══════════════════════════════════════════
   ABRIR EMAIL (panel lateral)
══════════════════════════════════════════ */
function openEmail(id) {
  var data = document.getElementById('detail-' + id);
  if (!data) return;

  /* Marcar como leído — primero en el DOM (feedback inmediato),
     luego persistir en el backend. */
  var row = document.querySelector('.email-row[data-id="' + id + '"]');
  if (row && row.dataset.read === 'false') {
    row.classList.remove('unread');
    row.dataset.read = 'true';
    var dot = row.querySelector('.unread-dot');
    if (dot) dot.remove();
    updateCounts();

    /* POST al backend — si falla, no pasa nada grave, el usuario sigue viéndolo como leído */
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

  /* Cache simple en memoria de los HTML ya descargados (evita re-fetch
     cuando vuelves a abrir el mismo correo). Clave = id del correo. */
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

  /* Helper: crea un iframe NUEVO desde cero y le mete el HTML.
     Se asegura de que cada apertura sea un documento limpio
     (evita el bug de srcdoc en blanco al reabrir el mismo correo). */
  function setIframeContent(html, withAutoHeight) {
    /* Quitar el iframe viejo del DOM si sigue ahí */
    var old = document.getElementById('panel-body-iframe');
    if (old && old.parentNode) old.parentNode.removeChild(old);

    /* Crear uno nuevo desde cero */
    var fresh = document.createElement('iframe');
    fresh.id  = 'panel-body-iframe';
    fresh.setAttribute('sandbox', '');   // sin allow-* → bloquea scripts/forms/nav
    fresh.style.cssText = 'width:100%;min-height:320px;border:0;display:block;background:#ffffff';

    if (withAutoHeight) {
      fresh.addEventListener('load', function () {
        try {
          var h = fresh.contentDocument.body.scrollHeight;
          fresh.style.height = Math.min(Math.max(h + 20, 200), 800) + 'px';
        } catch (e) {}
      });
    }

    /* Insertar antes de setear srcdoc para que el load dispare correctamente */
    iframeWrap.appendChild(fresh);
    fresh.srcdoc = html;
    iframe = fresh;   // actualiza la referencia local
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

    /* Cache hit → render inmediato */
    if (window.__smsHtmlCache[emailId]) {
      renderIframeFrom(window.__smsHtmlCache[emailId]);
      return;
    }

    /* Cache miss → spinner + fetch */
    iframeWrap.style.display = 'block';
    plainBox.style.display   = 'none';
    setIframeContent(
      '<!doctype html><html><body style="margin:0;padding:24px;font-family:system-ui;color:#888;text-align:center;background:#fff">'
      + '<div style="display:inline-flex;align-items:center;gap:10px">'
      + '<div style="width:14px;height:14px;border:2px solid #ddd;border-top-color:#7c5cff;border-radius:50%;animation:s 0.7s linear infinite"></div>'
      + 'Cargando correo…</div>'
      + '<style>@keyframes s{to{transform:rotate(360deg)}}</style></body></html>',
      false   // sin auto-altura para el spinner
    );

    fetch('/bandeja/' + emailId + '/html/', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (html) {
        window.__smsHtmlCache[emailId] = html;
        renderIframeFrom(html);
      })
      .catch(function (err) {
        console.warn('[inbox] no se pudo cargar el HTML:', err);
        showPlain();   // Fallback a texto plano
      });
  }

  /* Por defecto siempre intentamos HTML (más bonito); fallback a texto plano */
  if (hasHtml) showHtml(); else showPlain();

  /* Riesgo */
  var risk = parseInt(data.dataset.risk) || 0;
  var analysisId = data.dataset.analysisId;
  var riskSection = document.getElementById('panel-risk-section');
  var reportLink = document.getElementById('panel-report-link');

  /* Mostrar la sección si hay score O si hay análisis (aunque score=0) */
  if (risk > 0 || analysisId) {
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

    /* Botón "Ver reporte" — siempre que exista un análisis */
    if (analysisId) {
      reportLink.href = '/sandbox/reporte/' + analysisId + '/';
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
    if (analysisId) {
      link.href = '/sandbox/reporte/' + analysisId + '/';
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

/* Cerrar con ESC */
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') closeDetail();
});

/* ══════════════════════════════════════════
   RESPONDER CORREO
   ══════════════════════════════════════════
   Llamado desde el botón ".quick-reply" de cada fila. Lee toda la info
   del correo y del alias destino directamente del propio botón (data-*),
   por lo que no depende de tener el panel lateral abierto.

   Abre el compose modal global (definido en _compose_modal.html, incluido
   por base.html) prellenado con:
     - Desde:   el alias que recibió el correo
     - Para:    el remitente original
     - Asunto:  "Re: ..." (sin duplicar si ya empieza con Re:)
     - Cuerpo:  un bloque citado con el mensaje original
*/
function replyFromButton(btn) {
  if (!btn) return;
  if (btn.classList.contains('disabled') || btn.disabled) {
    if (window.showToast) {
      window.showToast({
        type:    'danger',
        title:   'Alias destruido',
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

  /* Extrae SOLO el correo del string del remitente.
     SendGrid puede guardarlo en cualquiera de estos formatos:
       - "josegomezxc14@proton.me"
       - "josegomezxc14 <josegomezxc14@proton.me>"
       - '"Jose Gomez" <jose@proton.me>'
       - "Jose <  jose@proton.me  >"
     El input type="email" rechaza cualquier cosa que no sea un email
     puro, así que buscamos la primera secuencia tipo email en el
     string y la usamos. Si no hay match, dejamos el string tal cual. */
  var fromEmail = fromRaw;
  var emailMatch = fromRaw.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);
  if (emailMatch) {
    fromEmail = emailMatch[0];
  }
  fromEmail = fromEmail.trim().replace(/^[<"']+|[>"']+$/g, '').trim();

  if (typeof window.openCompose !== 'function') {
    if (window.showToast) {
      window.showToast({
        type:    'danger',
        title:   'Compose no disponible',
        message: 'Recarga la página e inténtalo de nuevo.',
        duration: 5000,
      });
    }
    return;
  }

  /* 1) Abrir compose con el alias correcto en "Desde" */
  window.openCompose(aliasId, aliasAddr, aliasLabel);

  /* 2) Sobrescribir "Para" y "Asunto". openCompose deja estos campos
        vacíos por defecto — los rellenamos justo después. */
  var toInput   = document.getElementById('composeTo');
  var subjInput = document.getElementById('composeSubject');
  var editor    = document.getElementById('composeMessage');

  if (toInput)   toInput.value   = fromEmail;
  if (subjInput) {
    var hasRePrefix = /^\s*re\s*:/i.test(subject);
    subjInput.value = hasRePrefix ? subject : ('Re: ' + subject);
  }

  /* 3) Insertar bloque citado con el mensaje original. Convertimos
        saltos de línea a <br> y escapamos HTML — el body viene en
        texto plano. */
  if (editor) {
    var esc = function (s) {
      return String(s || '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    };
    var quoted   = esc(bodyText).replace(/\r?\n/g, '<br>');
    /* En la cita preferimos el remitente con display name ("Jose <jose@x>")
       si lo tenemos — es más legible que solo el correo pelado. */
    var safeFrom = esc(fromRaw || fromEmail);
    var safeWhen = esc(receivedAt);

    editor.innerHTML =
      '<p><br></p>' +
      '<p><br></p>' +
      '<blockquote style="border-left:3px solid #a78bfa;margin:12px 0;padding:8px 14px;color:#9e9cb8;font-size:13px">' +
        '<div style="font-size:11px;color:#6b6884;margin-bottom:6px">' +
          'El ' + safeWhen + ', ' + safeFrom + ' escribió:' +
        '</div>' +
        (quoted || '<em>(sin contenido)</em>') +
      '</blockquote>';

    /* Mover el cursor al inicio para que el usuario escriba arriba de la cita */
    try {
      editor.focus();
      var range = document.createRange();
      range.setStart(editor, 0);
      range.collapse(true);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (e) { /* algunos navegadores pueden fallar; no es crítico */ }
  }
}

/* ══════════════════════════════════════════
   MOVER A PAPELERA
   ══════════════════════════════════════════
   Soft delete: el correo desaparece de la bandeja pero queda 30 días en
   papelera antes de borrarse permanentemente. */
function trashEmail(btn, kind) {
  var id = btn.dataset.emailId;
  if (!id) return;
  var row = btn.closest('.email-row, .sent-row');
  if (!row) return;

  var url = (kind === 'outbound')
    ? '/enviados/' + encodeURIComponent(id) + '/papelera/'
    : '/bandeja/' + encodeURIComponent(id) + '/papelera/';

  var csrf = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
  csrf = csrf ? csrf.split('=')[1] : '';

  /* Animación de salida — desliza hacia la izquierda y se desvanece */
  row.style.transition = 'transform 0.25s ease, opacity 0.25s ease, max-height 0.25s ease 0.1s, margin 0.25s ease 0.1s, padding 0.25s ease 0.1s';
  row.style.transform = 'translateX(-30px)';
  row.style.opacity   = '0';

  fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
  })
  .then(function (res) { return res.json(); })
  .then(function (data) {
    if (data && data.ok) {
      /* Colapsar verticalmente y quitar del DOM */
      row.style.maxHeight = row.offsetHeight + 'px';
      requestAnimationFrame(function () {
        row.style.maxHeight = '0';
        row.style.marginTop = '0';
        row.style.marginBottom = '0';
        row.style.paddingTop = '0';
        row.style.paddingBottom = '0';
        row.style.borderWidth = '0';
        setTimeout(function () { row.remove(); if (typeof updateCounts === 'function') updateCounts(); }, 350);
      });
      if (window.showToast) {
        window.showToast({
          type: 'danger',
          title: 'Correo movido a Papelera',
          message: 'Lo eliminamos de tu bandeja — se borrará para siempre en 30 días.',
          duration: 4500,
        });
      }
    } else {
      // Restaurar el row si falla
      row.style.transform = '';
      row.style.opacity   = '';
      if (window.showToast) {
        window.showToast({
          type: 'danger',
          title: 'No se pudo eliminar',
          message: (data && data.error) || 'Intenta de nuevo',
          duration: 4000,
        });
      }
    }
  })
  .catch(function () {
    row.style.transform = '';
    row.style.opacity   = '';
    if (window.showToast) {
      window.showToast({
        type: 'danger',
        title: 'Error de red',
        message: 'No se pudo conectar con el servidor',
        duration: 4000,
      });
    }
  });
}

/* ══════════════════════════════════════════
   AUTO-REFRESH: polling al backend cada 15s
   ══════════════════════════════════════════ */
var livePollingEnabled = true;
var livePollTimer      = null;
var pendingNewEmails   = [];     // buffer de correos nuevos esperando merge
var lastSeenId         = (function () {
  var rows = document.querySelectorAll('.email-row[data-id]');
  var max = 0;
  rows.forEach(function (r) {
    var id = parseInt(r.dataset.id);
    if (id > max) max = id;
  });
  return max;
})();

function toggleLivePolling() {
  livePollingEnabled = !livePollingEnabled;
  var ind = document.getElementById('liveIndicator');
  var txt = document.getElementById('liveIndicatorText');
  if (livePollingEnabled) {
    ind.classList.remove('paused');
    txt.textContent = 'en vivo';
    schedulePoll(3000);   /* poll rápido al reanudar */
  } else {
    ind.classList.add('paused');
    txt.textContent = 'pausado';
  }
}

function schedulePoll(delayMs) {
  if (livePollTimer) clearTimeout(livePollTimer);
  livePollTimer = setTimeout(pollNewEmails, delayMs || 6000);
}

async function pollNewEmails() {
  if (!livePollingEnabled) return;

  /* Pulso visual en el chip cuando estamos consultando */
  var chip = document.getElementById('liveIndicator');
  chip.style.opacity = '1';

  try {
    var url = window.__INBOX_CTX__.newApiUrl + "?after=" + lastSeenId;
    var res = await fetch(url, {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
    if (!res.ok) throw new Error('http ' + res.status);
    var data = await res.json();
    if (data.emails && data.emails.length > 0) {
      console.info('[live] ' + data.emails.length + ' correo(s) nuevo(s) — auto-merging');
      data.emails.forEach(function (em) {
        if (!pendingNewEmails.some(function (p) { return p.id === em.id; })) {
          pendingNewEmails.push(em);
        }
      });
      // Esperamos 400ms para que el TOAST aparezca primero (su slide-in dura ~420ms).
      // El correo se inserta justo cuando el toast termina su animación → se siente coordinado.
      setTimeout(mergeNewEmails, 400);
    }
  } catch (e) {
    console.warn('[live] poll error:', e);
  } finally {
    setTimeout(function () { chip.style.opacity = '0.6'; }, 400);
    schedulePoll(6000);
  }
}

function showLiveBanner(count) {
  var b = document.getElementById('liveBanner');
  var t = document.getElementById('liveBannerText');
  t.textContent = count + ' correo' + (count === 1 ? '' : 's') + ' nuevo' + (count === 1 ? '' : 's');
  b.classList.add('visible');
}

function mergeNewEmails() {
  var list = document.getElementById('email-list');
  var banner = document.getElementById('liveBanner');
  if (pendingNewEmails.length === 0) return;

  /* Quita el empty-state si había */
  var empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  /* Asegura que existe el separador "Hoy" al inicio */
  var hoyDivider = list.querySelector('.date-divider[data-group="hoy"]');
  if (!hoyDivider) {
    hoyDivider = document.createElement('div');
    hoyDivider.className = 'date-divider';
    hoyDivider.dataset.group = 'hoy';
    hoyDivider.innerHTML = 'Hoy <span class="count">0</span>';
    list.insertBefore(hoyDivider, list.firstChild);
  }
  var countEl = hoyDivider.querySelector('.count');
  var currentCount = parseInt(countEl?.textContent || '0') || 0;

  /* Inserta después del separador "Hoy" */
  pendingNewEmails.sort(function (a, b) { return b.id - a.id; });
  pendingNewEmails.forEach(function (em) {
    var row = buildEmailRow(em);
    hoyDivider.parentNode.insertBefore(row, hoyDivider.nextSibling);
    if (em.id > lastSeenId) lastSeenId = em.id;
    currentCount++;
  });
  if (countEl) countEl.textContent = currentCount;

  pendingNewEmails = [];
  banner.classList.remove('visible');
  updateCounts();
  applyFilters();
}

function buildEmailRow(em) {
  /* Crea un .email-row equivalente al que genera Django */
  var row = document.createElement('div');
  var classes = ['email-row', 'new-arrival'];
  if (!em.read)             classes.push('unread');
  if (em.risk_score >= 61)  classes.push('threat');
  row.className = classes.join(' ');

  row.dataset.id         = em.id;
  row.dataset.read       = em.read ? 'true' : 'false';
  row.dataset.attachment = em.has_attachment ? 'true' : 'false';
  row.dataset.risk       = em.risk_score || 0;
  row.dataset.from       = (em.from_email || '').toLowerCase();
  row.dataset.subject    = (em.subject || '').toLowerCase();
  row.dataset.body       = (em.body || '').toLowerCase().slice(0, 120);
  row.onclick = function () { openEmail(em.id); };

  var avatarColors = [
    ['rgba(124,58,237,0.1)', 'var(--ai-purple-light)'],
    ['rgba(46,204,113,0.1)', 'var(--success)'],
    ['rgba(245,158,11,0.1)', 'var(--warning)'],
    ['rgba(59,130,246,0.1)', '#60a5fa'],
    ['rgba(232,64,64,0.1)',  'var(--danger)'],
  ];
  var avColor = avatarColors[em.id % avatarColors.length];
  var firstLetter = (em.from_email || '?').charAt(0).toUpperCase();

  var riskPill = '';
  if (em.risk_score >= 61) {
    riskPill = '<span class="risk-pill danger"><svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>Bloqueado</span>';
  } else if (em.risk_score >= 31) {
    riskPill = '<span class="risk-pill warning">Sospechoso</span>';
  } else if (em.risk_score > 0) {
    riskPill = '<span class="risk-pill success"><svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>Seguro</span>';
  }
  var attPill = '';
  if (em.has_attachment) {
    attPill = '<span class="att-pill"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>' + escapeHtml(em.attachment_name || '') + '</span>';
  }

  /* Botón Responder con todos los data-* que necesita replyFromButton().
     Si el alias está destruido, lo dejamos visible pero deshabilitado. */
  var aliasActive = em.alias_active ? '1' : '0';
  var replyDisabled = em.alias_active ? '' : 'disabled';
  var replyClass = em.alias_active ? 'quick-reply' : 'quick-reply disabled';
  var replyTitle = em.alias_active
    ? 'Responder este correo'
    : 'Alias destruido — no se puede responder';
  var replyBtn =
    '<button type="button" class="' + replyClass + '" ' +
            'data-email-id="' + em.id + '" ' +
            'data-from="' + escapeHtml(em.from_email || '') + '" ' +
            'data-subject="' + escapeHtml(em.subject || '') + '" ' +
            'data-body="' + escapeHtml(em.body || '') + '" ' +
            'data-alias-id="' + escapeHtml(String(em.alias_id || '')) + '" ' +
            'data-alias-address="' + escapeHtml(em.alias || '') + '" ' +
            'data-alias-label="' + escapeHtml(em.alias_label || '') + '" ' +
            'data-alias-active="' + aliasActive + '" ' +
            'data-time="' + escapeHtml((em.received_at_iso || '').replace('T', ' ').slice(0, 16)) + '" ' +
            'onclick="event.stopPropagation();replyFromButton(this)" ' +
            'title="' + replyTitle + '" ' + replyDisabled + '>' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
        '<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>' +
      '</svg>Responder</button>';

  /* Botón "reporte" — solo si el correo tiene análisis del sandbox.
     URL hardcodeada: /sandbox/reporte/<id>/ (definida en apps/sandbox/urls.py). */
  var reportBtn = '';
  if (em.analysis_id) {
    reportBtn =
      '<a href="/sandbox/reporte/' + encodeURIComponent(em.analysis_id) + '/" ' +
         'class="quick-report" onclick="event.stopPropagation()">' +
        '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">' +
          '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
          '<polyline points="14 2 14 8 20 8"/>' +
        '</svg>reporte</a>';
  }

  /* Botón "Eliminar" (mover a papelera) */
  var trashBtn =
    '<button type="button" class="quick-trash" data-email-id="' + em.id + '" ' +
            'onclick="event.stopPropagation();trashEmail(this, \'inbound\')" ' +
            'title="Mover a papelera">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
        '<polyline points="3 6 5 6 21 6"/>' +
        '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' +
      '</svg>Eliminar</button>';

  row.innerHTML =
    (!em.read ? '<div class="unread-dot"></div>' : '') +
    '<div class="sender-avatar" style="background:' + avColor[0] + ';color:' + avColor[1] + '">' + firstLetter + '</div>' +
    '<div class="email-content">' +
      '<div class="email-top">' +
        '<span class="email-from">' + escapeHtml(em.from_email || '').slice(0, 32) + '</span>' +
        '<span class="email-time">' + escapeHtml(em.received_human || '') + ' atrás</span>' +
      '</div>' +
      '<div class="email-subject">' + escapeHtml(em.subject || '') + '</div>' +
      '<div class="email-preview">' + escapeHtml((em.body || '').slice(0, 80)) + '</div>' +
      '<div class="email-meta">' +
        '<span class="alias-tag">→ ' + escapeHtml(em.alias || '') + '</span>' +
        attPill + riskPill +
      '</div>' +
    '</div>' +
    reportBtn +
    trashBtn +
    replyBtn +
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" style="flex-shrink:0;margin-top:2px"><polyline points="9 18 15 12 9 6"/></svg>';

  /* detail-* oculto para que openEmail() funcione */
  var detail = document.createElement('div');
  detail.id = 'detail-' + em.id;
  detail.style.display = 'none';
  detail.dataset.from          = em.from_email || '';
  detail.dataset.subject       = em.subject || '';
  detail.dataset.body          = em.body || '';
  detail.dataset.alias         = em.alias || '';
  detail.dataset.aliasId       = em.alias_id || '';
  detail.dataset.aliasLabel    = em.alias_label || '';
  detail.dataset.aliasActive   = em.alias_active ? '1' : '0';
  detail.dataset.time          = (em.received_at_iso || '').replace('T', ' ').slice(0, 16);
  detail.dataset.attachment    = em.attachment_name || '';
  detail.dataset.risk          = em.risk_score || 0;
  if (em.analysis_id) detail.dataset.analysisId = em.analysis_id;
  row.appendChild(detail);

  return row;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Pausar cuando la pestaña no es visible (ahorra ancho de banda) */
document.addEventListener('visibilitychange', function () {
  if (document.hidden) {
    if (livePollTimer) clearTimeout(livePollTimer);
  } else {
    schedulePoll(3000);
  }
});

/* Arrancar polling INMEDIATAMENTE — no esperamos a DOMContentLoaded porque
   este script se inyecta al final del body y el evento ya pudo haber pasado. */
console.info('[live] polling activado — lastSeenId=' + lastSeenId);
pollNewEmails();           // primera llamada inmediata


/* ════════════════════════════════════════════════════════════════════
   VACIAR BANDEJA — dropdown con scopes (read / threats / safe / all)
   ════════════════════════════════════════════════════════════════════ */
(function () {
  const wrap   = document.getElementById('inbox-clear-wrap');
  const btn    = document.getElementById('inbox-clear-btn');
  const menu   = document.getElementById('inbox-clear-menu');
  const list   = document.getElementById('email-list');
  if (!wrap || !btn || !menu || !list) return;

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

  /* Decide si una fila <div.email-row> cae dentro del scope */
  function rowMatchesScope(row, scope) {
    if (scope === 'all') return true;
    if (scope === 'read')    return !row.classList.contains('unread');
    if (scope === 'threats') return row.classList.contains('threat');
    if (scope === 'safe') {
      const score = parseInt(row.dataset.risk || '0', 10);
      return score <= 30;
    }
    return false;
  }

  menu.querySelectorAll('.icm-item[data-scope]').forEach(item => {
    item.addEventListener('click', async () => {
      const scope = item.dataset.scope;
      setOpen(false);
      const meta = SCOPE_META[scope] || SCOPE_META.read;

      const ok = window.confirmDialog
        ? await window.confirmDialog({
            danger:      true,
            icon:        'trash',
            title:       meta.title,
            message:     meta.message,
            confirmText: meta.confirm,
            cancelText:  'Cancelar',
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

        // Animación cascada: marca las filas que caen dentro del scope
        const rows = Array.from(list.querySelectorAll('.email-row'));
        const toRemove = rows.filter(r => rowMatchesScope(r, scope));
        toRemove.forEach((row, i) => {
          setTimeout(() => {
            row.classList.add('removing-out');
            setTimeout(() => row.remove(), 300);
          }, i * 25);
        });

        // Limpia separadores de fecha que queden vacíos al terminar
        setTimeout(() => {
          list.querySelectorAll('.date-divider').forEach(div => {
            // Cada date-divider va antes del bloque de correos de ese grupo.
            // Si su próximo email-row hermano no existe → lo quitamos.
            let next = div.nextElementSibling;
            let hasEmail = false;
            while (next && !next.classList.contains('date-divider')) {
              if (next.classList.contains('email-row')) { hasEmail = true; break; }
              next = next.nextElementSibling;
            }
            if (!hasEmail) div.remove();
          });
        }, toRemove.length * 25 + 350);

        if (window.showToast) {
          window.showToast({
            type: 'success',
            title: 'Correos eliminados',
            message: data.deleted + ' correo' + (data.deleted === 1 ? '' : 's') + ' borrado' + (data.deleted === 1 ? '' : 's'),
            duration: 4500,
          });
        }
      } catch (err) {
        if (window.showToast) {
          window.showToast({
            type: 'danger',
            title: 'No se pudo vaciar',
            message: 'Intenta de nuevo en unos segundos.',
            duration: 5000,
          });
        }
      }
    });
  });
})();
