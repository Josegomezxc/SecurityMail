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

    // Mensaje "sin notificaciones en este filtro" — usa la misma
    // estructura que .notif-empty (server-side empty state): el
    // icono propio del módulo (campana) en grande dentro de la card,
    // un título y un subtítulo. Asi queda visualmente idéntico al
    // empty-state que aparece cuando no hay notificaciones del todo.
    // El TÍTULO y el SUBTÍTULO cambian según el filtro activo para que
    // el usuario sepa exactamente qué tipo de notificación falta.
    const COPY = {
      all: {
        title: 'No hay notificaciones',
        hint:  'Cuando llegue un correo a tus alias o haya un evento, aparecerá aquí.',
      },
      unread: {
        title: 'No hay notificaciones sin leer',
        hint:  'Estás al día — ya viste todas las notificaciones recibidas.',
      },
      pending: {
        title: 'No hay notificaciones pendientes',
        hint:  'No tienes solicitudes esperando tu respuesta.',
      },
      forwarded: {
        title: 'No hay notificaciones reenviadas',
        hint:  'Aún no has aprobado el reenvío de ningún correo a tu bandeja real.',
      },
      discarded: {
        title: 'No hay notificaciones descartadas',
        hint:  'No has descartado ninguna solicitud de reenvío todavía.',
      },
    };

    let emptyMsg = container.querySelector('.notif-empty-filtered');
    const hasReal = container.querySelectorAll('.notif-row').length > 0;
    if (visible === 0 && hasReal) {
      const copy = COPY[filter] || COPY.all;
      const html =
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
          'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" ' +
          'style="display:block;margin:0 auto">' +
          '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>' +
          '<path d="M13.73 21a2 2 0 0 1-3.46 0"/>' +
        '</svg>' +
        '<div class="notif-empty-msg"></div>' +
        '<div class="notif-empty-hint"></div>';
      if (!emptyMsg) {
        emptyMsg = document.createElement('div');
        emptyMsg.className = 'notif-empty notif-empty-filtered';
        emptyMsg.innerHTML = html;
        container.appendChild(emptyMsg);
      }
      // Si el usuario cambió de filtro pero el bloque ya existe, refrescamos
      // los textos para que el copy coincida con el filtro actual.
      const msgEl  = emptyMsg.querySelector('.notif-empty-msg');
      const hintEl = emptyMsg.querySelector('.notif-empty-hint');
      if (msgEl)  msgEl.textContent  = copy.title;
      if (hintEl) hintEl.textContent = copy.hint;
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

  /* ══════════════════════════════════════════
     VER MÁS / VER MENOS (load-more con toggle)
  ══════════════════════════════════════════ */
  let notifLoadingMore = false;

  window.loadMoreNotif = function () {
    if (notifLoadingMore) return;
    const btn      = document.getElementById('notif-loadmore-btn');
    const collapse = document.getElementById('notif-collapse-btn');
    const list     = document.getElementById('notif-list-container');
    if (!btn || !list) return;

    const offset = parseInt(list.dataset.nextOffset || '0', 10) || 0;
    notifLoadingMore = true;
    btn.classList.add('loading');
    btn.disabled = true;

    fetch('/notificaciones/mas/?offset=' + encodeURIComponent(offset), {
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        if (!data || !data.ok) throw new Error('bad response');

        if (data.count > 0) {
          // Append antes del empty-state si existe
          const emptyState = document.getElementById('notif-empty-state');
          const tmp = document.createElement('div');
          tmp.innerHTML = data.html.trim();
          while (tmp.firstChild) {
            const node = tmp.firstChild;
            if (node.nodeType === 1 && node.classList && node.classList.contains('notif-row')) {
              node.dataset.loaded = '1';
            }
            if (emptyState) list.insertBefore(node, emptyState);
            else            list.appendChild(node);
          }
        }

        list.dataset.nextOffset = String(data.next_offset);
        list.dataset.hasMore    = data.has_more ? '1' : '0';

        if (!data.has_more) btn.style.display = 'none';
        if (collapse)       collapse.style.display = '';

        // Re-aplicar el filtro activo a las filas recién insertadas
        applyFilter(activeFilter);
      })
      .catch(() => {
        if (window.showToast) {
          showToast({
            type: 'danger',
            title: 'No se pudieron cargar más',
            message: 'Intenta de nuevo en unos segundos.',
            duration: 4000,
          });
        }
      })
      .finally(() => {
        notifLoadingMore = false;
        btn.classList.remove('loading');
        btn.disabled = false;
      });
  };

  window.collapseNotif = function () {
    const btn      = document.getElementById('notif-loadmore-btn');
    const collapse = document.getElementById('notif-collapse-btn');
    const wrap     = document.getElementById('notif-loadmore-wrap');
    const list     = document.getElementById('notif-list-container');
    if (!list || !wrap) return;

    list.querySelectorAll('.notif-row[data-loaded="1"]').forEach(r => r.remove());

    const initial = parseInt(wrap.dataset.initialCount || '0', 10) || 0;
    list.dataset.nextOffset = String(initial);
    list.dataset.hasMore    = '1';

    if (btn)      btn.style.display = '';
    if (collapse) collapse.style.display = 'none';

    applyFilter(activeFilter);
    list.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
})();
