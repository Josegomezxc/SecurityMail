(function () {
  /* ─── Auto-actualización en vivo de la lista de notificaciones ───
     Polling cada 4s al endpoint /notificaciones/api/unread/.
     Si llega una notificación con id mayor al más alto que tenemos
     en pantalla, la prependemos al top con animación slide-in. */

  const container = document.getElementById('notif-list-container');
  if (!container) return;

  // Plantillas SVG por tipo (mismo diseño que el render Django)
  const ICONS = {
    forward_request: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    forwarded:       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>',
    threat_alert:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>',
    system:          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/></svg>',
  };

  // Etiquetas legibles del status (debe coincidir con get_status_display)
  const STATUS_LABEL = {
    pending:   'Pendiente',
    approved:  'Aprobada — reenviada',
    discarded: 'Descartada',
    expired:   'Expirada',
    done:      'Completada',
  };

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    })[c]);
  }

  function getMaxId() {
    const rows = container.querySelectorAll('.notif-row[data-id]');
    let max = 0;
    rows.forEach(r => {
      const id = parseInt(r.dataset.id, 10);
      if (id > max) max = id;
    });
    return max;
  }

  function fmtDate(iso) {
    try {
      const d = new Date(iso);
      const months = ['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'];
      const day = d.getDate();
      const mon = months[d.getMonth()];
      const hh = String(d.getHours()).padStart(2,'0');
      const mm = String(d.getMinutes()).padStart(2,'0');
      return `${day} ${mon}, ${hh}:${mm}`;
    } catch (e) { return ''; }
  }

  function buildRow(n) {
    const cls = n.read ? '' : 'unread';
    const icon = ICONS[n.type] || ICONS.system;
    const statusLabel = STATUS_LABEL[n.status] || n.status;
    // Color del icono por nivel de riesgo (gana sobre el tipo si hay correo asociado)
    let iconCls;
    if (typeof n.risk_score === 'number') {
      if      (n.risk_score >= 61) iconCls = 'r-danger';
      else if (n.risk_score >= 31) iconCls = 'r-warn';
      else                         iconCls = 'r-safe';
    } else {
      iconCls = 't-' + n.type;
    }
    const riskAttr = (typeof n.risk_score === 'number') ? ` data-risk="${n.risk_score}"` : '';
    return `<a href="${escapeHtml(n.url)}" class="notif-row ${cls} is-new" data-id="${n.id}" data-type="${escapeHtml(n.type)}" data-status="${escapeHtml(n.status)}" data-read="${n.read ? '1' : '0'}"${riskAttr}>
      <div class="notif-row-icon ${iconCls}">${icon}</div>
      <div class="notif-row-body">
        <div class="notif-row-title">${escapeHtml(n.title)} <span class="new-badge">NUEVO</span></div>
        ${n.message ? `<div class="notif-row-msg">${escapeHtml(n.message)}</div>` : ''}
      </div>
      <div class="notif-row-meta">
        <span class="notif-status-pill ns-${n.status}">${escapeHtml(statusLabel)}</span>
        <span>${fmtDate(n.time_iso)}</span>
      </div>
    </a>`;
  }

  function refresh() {
    const maxId = getMaxId();
    fetch('/notificaciones/api/unread/', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        if (!data.recent || data.recent.length === 0) return;

        // Filtra solo las nuevas (id > maxId)
        const news = data.recent.filter(n => n.id > maxId);
        if (news.length === 0) return;

        // Esperamos 400ms para que el TOAST aparezca primero (su slide-in dura ~420ms).
        // La fila se inserta justo cuando el toast termina su animación → se siente coordinado.
        setTimeout(() => {
          // Si estaba el "no tienes notificaciones todavía", lo quitamos
          const empty = document.getElementById('notif-empty-state');
          if (empty) empty.remove();

          // Prepend en orden: la más nueva queda arriba
          // (recent ya viene ordenado DESC, así que la primera es la más reciente)
          // Las prependemos en orden inverso para que la primera quede arriba al final
          const sorted = news.sort((a, b) => a.id - b.id);   // ASC para insertar
          sorted.forEach(n => {
            container.insertAdjacentHTML('afterbegin', buildRow(n));
          });

          // Quitar la clase is-new después de 6s para que el highlight se quite
          setTimeout(() => {
            container.querySelectorAll('.notif-row.is-new').forEach(el => {
              el.classList.remove('is-new');
              const badge = el.querySelector('.new-badge');
              if (badge) badge.remove();
            });
          }, 6000);
        }, 400);
      })
      .catch(err => console.debug('[notif-list] poll error:', err));
  }

  // Polling cada 6 segundos (rápido pero sin sobrecargar)
  setInterval(refresh, 6000);

  // Refresca al volver a la pestaña
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') refresh();
  });
})();

/* ════════════════════════════════════════════════════════════════════
   FILTROS + VACIAR LISTA
   ════════════════════════════════════════════════════════════════════ */
(function () {
  const container = document.getElementById('notif-list-container');
  const filtersBar = document.getElementById('notif-filters');
  if (!container || !filtersBar) return;

  let activeFilter = 'all';

  function getCsrf() {
    const c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1] : '';
  }

  /* ── Filtrado client-side ── */
  function applyFilter(filter) {
    activeFilter = filter;
    // Botones activos
    filtersBar.querySelectorAll('.notif-filter-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.filter === filter);
    });

    // Mostrar / ocultar filas
    let visible = 0;
    container.querySelectorAll('.notif-row').forEach(row => {
      const type   = row.dataset.type;
      const status = row.dataset.status;
      let show = false;
      if      (filter === 'all')       show = true;
      else if (filter === 'unread')    show = row.dataset.read === '0';
      else if (filter === 'pending')   show = status === 'pending';
      else if (filter === 'forwarded') show = type === 'forwarded' || status === 'approved';
      else if (filter === 'discarded') show = status === 'discarded';
      row.classList.toggle('filtered-out', !show);
      if (show) visible++;
    });

    // Mensaje "sin resultados con este filtro"
    let emptyMsg = container.querySelector('.notif-empty-filtered');
    const hasReal = container.querySelectorAll('.notif-row').length > 0;
    if (visible === 0 && hasReal) {
      if (!emptyMsg) {
        emptyMsg = document.createElement('div');
        emptyMsg.className = 'notif-empty-filtered';
        emptyMsg.textContent = 'No hay notificaciones que coincidan con este filtro.';
        container.appendChild(emptyMsg);
      }
    } else if (emptyMsg) {
      emptyMsg.remove();
    }
  }

  // Click en pills de filtro
  filtersBar.querySelectorAll('.notif-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => applyFilter(btn.dataset.filter));
  });

  /* ── Recalcula los counts del toolbar a partir del DOM ── */
  function recountFilters() {
    const rows = container.querySelectorAll('.notif-row');
    const counts = { all: rows.length, unread: 0, pending: 0, forwarded: 0, discarded: 0 };
    rows.forEach(r => {
      const type   = r.dataset.type;
      const status = r.dataset.status;
      if (r.dataset.read === '0')                              counts.unread++;
      if (status === 'pending')                                counts.pending++;
      if (type === 'forwarded' || status === 'approved')       counts.forwarded++;
      if (status === 'discarded')                              counts.discarded++;
    });
    Object.keys(counts).forEach(key => {
      const span = filtersBar.querySelector('[data-count="' + key + '"]');
      if (span) span.textContent = counts[key];
    });
  }

  /* ── Dropdown "Vaciar" ── */
  const clearBtn  = document.getElementById('notif-clear-btn');
  const clearMenu = document.getElementById('notif-clear-menu');
  const clearWrap = document.getElementById('notif-clear-wrap');

  function setMenuOpen(state) {
    clearMenu.classList.toggle('open', state);
    clearBtn.classList.toggle('open', state);
  }
  clearBtn.addEventListener('click', e => {
    e.stopPropagation();
    setMenuOpen(!clearMenu.classList.contains('open'));
  });
  document.addEventListener('click', e => {
    if (!clearWrap.contains(e.target)) setMenuOpen(false);
  });
  clearMenu.addEventListener('click', e => e.stopPropagation());

  /* ── Acciones de vaciar ── */
  const SCOPE_META = {
    read: {
      title:   'Borrar notificaciones leídas',
      message: 'Se eliminarán todas las notificaciones que ya viste.\nEsta acción no se puede deshacer.',
      confirm: 'Borrar leídas',
    },
    discarded: {
      title:   'Borrar notificaciones descartadas',
      message: 'Se eliminarán todas las solicitudes de reenvío que descartaste.\nEsta acción no se puede deshacer.',
      confirm: 'Borrar descartadas',
    },
    all: {
      title:   'Vaciar todas las notificaciones',
      message: 'Se eliminarán todas, excepto las pendientes de aprobación.\nEsta acción no se puede deshacer.',
      confirm: 'Vaciar todo',
    },
  };

  clearMenu.querySelectorAll('.ncm-item[data-scope]').forEach(item => {
    item.addEventListener('click', async () => {
      const scope = item.dataset.scope;
      setMenuOpen(false);
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
        const res = await fetch(window.__NOTIFICATIONS_CTX__.clearUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
          body: fd,
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error || 'error');

        // Decide qué filas borrar según el scope
        const toRemove = [];
        container.querySelectorAll('.notif-row').forEach(row => {
          if (scope === 'read'      && row.dataset.read === '1') toRemove.push(row);
          else if (scope === 'discarded' && row.dataset.status === 'discarded') toRemove.push(row);
          else if (scope === 'all'  && !(row.dataset.type === 'forward_request' && row.dataset.status === 'pending')) toRemove.push(row);
        });

        // Animación de salida
        toRemove.forEach((row, i) => {
          setTimeout(() => {
            row.classList.add('removing-out');
            setTimeout(() => row.remove(), 300);
          }, i * 35);   // efecto cascada
        });

        // Actualizar counts y mostrar toast
        setTimeout(() => {
          recountFilters();
          applyFilter(activeFilter);
        }, toRemove.length * 35 + 320);

        if (window.showToast) {
          showToast({
            type: 'success',
            title: 'Notificaciones eliminadas',
            message: data.deleted + ' notificacion' + (data.deleted === 1 ? '' : 'es') + ' borrada' + (data.deleted === 1 ? '' : 's'),
            duration: 4500,
          });
        }
      } catch (err) {
        if (window.showToast) {
          showToast({
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
