  /* ══════════════════════════════════════════
     ABRIR DETALLE DE CORREO ENVIADO
     ══════════════════════════════════════════
     Click en un correo enviado → abre el compose modal global en
     readonly con los datos del envío ya cargados. */
  function openSent(id) {
    var data = document.getElementById('sent-detail-' + id);
    if (!data) return;

    if (typeof window.openCompose !== 'function') {
      if (window.showToast) {
        window.showToast({
          type: 'danger',
          title: 'Compose no disponible',
          message: 'Recarga la página e inténtalo de nuevo.',
          duration: 5000,
        });
      }
      return;
    }

    var aliasId    = data.dataset.aliasId;
    var aliasAddr  = data.dataset.alias;
    var aliasLabel = data.dataset.aliasLabel || '';
    var to         = data.dataset.to || '';
    var subject    = data.dataset.subject || '';
    var bodyHtml   = data.dataset.body || '';

    window.openCompose(aliasId, aliasAddr, aliasLabel, { readonly: true });

    var subjInput = document.getElementById('composeSubject');
    var editor    = document.getElementById('composeMessage');

    if (typeof window.composeSetRecipients === 'function') {
      window.composeSetRecipients(to);
    }
    if (subjInput) subjInput.value = subject;

    if (editor) {
      var inner = bodyHtml;
      try {
        var doc = new DOMParser().parseFromString(bodyHtml, 'text/html');
        var wrapper = doc.body.firstElementChild;
        if (wrapper && wrapper.tagName === 'DIV') {
          var hr = wrapper.querySelector('hr');
          if (hr) {
            var node = hr;
            while (node) {
              var next = node.nextSibling;
              node.remove();
              node = next;
            }
          }
          inner = wrapper.innerHTML.trim();
        }
      } catch (e) {}
      editor.innerHTML = inner || '<p><br></p>';
    }

    var attachWrap = document.getElementById('composeAttachments');
    if (attachWrap) {
      attachWrap.innerHTML = '';
      var meta = [];
      try { meta = JSON.parse(data.dataset.attachmentsMeta || '[]'); } catch (e) { meta = []; }
      meta.forEach(function (att) {
        var name = att.filename || 'archivo';
        var size = formatBytes(att.size || 0);
        var chip = document.createElement('span');
        chip.className = 'compose-attachment readonly';
        chip.innerHTML =
          '<svg class="compose-attachment-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>' +
          '</svg>' +
          '<span class="compose-attachment-name" title="' + escapeAttr(name) + '">' + escapeAttr(name) + '</span>' +
          (size ? '<span class="compose-attachment-size">' + size + '</span>' : '');
        attachWrap.appendChild(chip);
      });
    }
  }

  function formatBytes(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }
  function escapeAttr(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeAliasPicker();
  });

  /* ══════════════════════════════════════════
     COMPOSE:SENT — al enviar un nuevo correo, lo mejor es recargar
     la página para que el load-more empiece "limpio" desde el batch 1
     ══════════════════════════════════════════ */
  document.addEventListener('compose:sent', function () {
    setTimeout(function () { window.location.reload(); }, 250);
  });

  /* ══════════════════════════════════════════
     VER MÁS / VER MENOS
     ──────────────────────────────────────────
     "Ver más"  → pide el siguiente lote al backend y lo appendea.
                  Cada fila nueva queda marcada con data-loaded="1"
                  para poder distinguir las server-rendered de las
                  cargadas dinámicamente.
     "Ver menos" → quita TODAS las filas con data-loaded="1" y
                  restaura el offset al inicial (las 6 originales).
     ══════════════════════════════════════════ */
  var loadingMore = false;

  function loadMoreSent() {
    if (loadingMore) return;
    var btn      = document.getElementById('sent-loadmore-btn');
    var collapse = document.getElementById('sent-collapse-btn');
    var list     = document.getElementById('sent-list');
    if (!btn || !list) return;

    var offset = parseInt(list.dataset.nextOffset || '0', 10) || 0;
    loadingMore = true;
    btn.classList.add('loading');
    btn.disabled = true;

    fetch('/enviados/mas/?offset=' + encodeURIComponent(offset), {
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        if (!data || !data.ok) throw new Error('bad response');

        if (data.count > 0) {
          // Append antes del placeholder #sent-no-results para que las
          // nuevas filas queden dentro de la lista pero arriba del
          // mensaje "Sin resultados".
          var noRes = document.getElementById('sent-no-results');
          var tmp = document.createElement('div');
          tmp.innerHTML = data.html.trim();
          while (tmp.firstChild) {
            var node = tmp.firstChild;
            // Marca solo los .sent-row appendeados (no los wrappers vacíos)
            if (node.nodeType === 1 && node.classList && node.classList.contains('sent-row')) {
              node.dataset.loaded = '1';
            }
            list.insertBefore(node, noRes);
          }
        }

        list.dataset.nextOffset = String(data.next_offset);
        list.dataset.hasMore    = data.has_more ? '1' : '0';

        // Ver más se oculta si ya no hay más; Ver menos aparece porque
        // hay rows extra cargados.
        if (!data.has_more) btn.style.display = 'none';
        if (collapse)       collapse.style.display = '';

        // Re-aplicar filtro/búsqueda actuales a las filas recién insertadas
        applySentFilters();
      })
      .catch(function () {
        if (window.showToast) {
          window.showToast({
            type: 'danger',
            title: 'No se pudieron cargar más correos',
            message: 'Intenta de nuevo en unos segundos.',
            duration: 4000,
          });
        }
      })
      .finally(function () {
        loadingMore = false;
        btn.classList.remove('loading');
        btn.disabled = false;
      });
  }

  function collapseSent() {
    var btn      = document.getElementById('sent-loadmore-btn');
    var collapse = document.getElementById('sent-collapse-btn');
    var wrap     = document.getElementById('sent-loadmore-wrap');
    var list     = document.getElementById('sent-list');
    if (!list || !wrap) return;

    // Quita todas las filas appendeadas vía AJAX
    list.querySelectorAll('.sent-row[data-loaded="1"]').forEach(function (r) {
      r.remove();
    });

    // Restaura el offset al inicial (lo que server-side trajo en el GET)
    var initial = parseInt(wrap.dataset.initialCount || '0', 10) || 0;
    list.dataset.nextOffset = String(initial);
    list.dataset.hasMore    = '1';

    // Ver más vuelve a aparecer; Ver menos se esconde
    if (btn)      btn.style.display = '';
    if (collapse) collapse.style.display = 'none';

    // Re-aplicar filtros + scroll suave al inicio de la lista
    applySentFilters();
    list.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  /* ══════════════════════════════════════════
     FILTROS + BÚSQUEDA — operan sobre el DOM cargado (client-side)
     ══════════════════════════════════════════ */
  var sentFilter = 'all';      // all | attach | scheduled
  var sentSearchQ = '';

  function applySentFilters() {
    var rows    = document.querySelectorAll('.sent-row');
    var visible = 0;

    rows.forEach(function (r) {
      var to    = r.dataset.to || '';
      var subj  = r.dataset.subject || '';
      var alias = r.dataset.alias || '';
      var hasAtt = r.dataset.hasAttach === '1';
      var sched  = r.dataset.scheduled  === '1';

      var matchSearch = !sentSearchQ ||
                        to.includes(sentSearchQ) ||
                        subj.includes(sentSearchQ) ||
                        alias.includes(sentSearchQ);
      var matchFilter = true;
      if (sentFilter === 'attach')        matchFilter = hasAtt;
      else if (sentFilter === 'scheduled') matchFilter = sched;

      var show = matchSearch && matchFilter;
      r.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    var noRes = document.getElementById('sent-no-results');
    var msg   = document.getElementById('sent-no-results-msg');
    var hint  = document.getElementById('sent-no-results-hint');
    if (visible === 0 && rows.length > 0) {
      noRes.style.display = 'block';
      if (sentSearchQ) {
        msg.textContent  = 'Sin correos que coincidan con "' + sentSearchQ + '"';
        hint.textContent = 'Prueba otro término, cambia el filtro o pulsa "Cargar más" para traer más correos.';
      } else if (sentFilter === 'attach') {
        msg.textContent  = 'Sin correos con adjuntos en lo cargado';
        hint.textContent = 'Prueba con otro filtro o pulsa "Cargar más".';
      } else if (sentFilter === 'scheduled') {
        msg.textContent  = 'Sin correos programados en lo cargado';
        hint.textContent = 'Prueba con otro filtro o pulsa "Cargar más".';
      } else {
        msg.textContent  = 'Sin resultados';
        hint.textContent = 'Prueba con otro filtro o término de búsqueda.';
      }
    } else {
      noRes.style.display = 'none';
    }

    /* Ocultar separadores de fecha cuyos grupos quedaron vacíos */
    document.querySelectorAll('.date-divider').forEach(function (div) {
      var sib = div.nextElementSibling;
      var hasVisible = false;
      while (sib && sib.classList.contains('sent-row')) {
        if (sib.style.display !== 'none') { hasVisible = true; break; }
        sib = sib.nextElementSibling;
      }
      div.style.display = hasVisible ? '' : 'none';
    });
  }

  function sentSearch(value) {
    sentSearchQ = (value || '').toLowerCase().trim();
    applySentFilters();
  }

  function filterSent(filter, btn) {
    sentFilter = filter;
    document.querySelectorAll('.sent-tab-btn').forEach(function (b) {
      b.classList.toggle('active', b === btn);
    });
    applySentFilters();
  }

  function emptySent() {
    var doIt = function () {
      var csrf = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
      csrf = csrf ? csrf.split('=')[1] : '';
      fetch('/enviados/vaciar/', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
      })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d && d.ok) {
          document.querySelectorAll('.sent-row').forEach(function (r) {
            r.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
            r.style.opacity = '0';
            r.style.transform = 'scale(0.96)';
          });
          setTimeout(function () { window.location.reload(); }, 350);
          if (window.showToast) {
            window.showToast({
              type:    'danger',
              title:   'Enviados movidos a Papelera',
              message: 'Mandamos ' + d.moved + ' correo' + (d.moved === 1 ? '' : 's') + ' enviado' + (d.moved === 1 ? '' : 's') + ' a la papelera — se borran para siempre en 30 días.',
              duration: 5000,
            });
          }
        }
      });
    };

    if (window.confirmDialog) {
      window.confirmDialog({
        danger: true, icon: 'trash',
        title:   'Vaciar enviados',
        message: '¿Mover TODOS los correos enviados a la papelera? Podrás restaurarlos durante 30 días.',
        confirmText: 'Sí, vaciar', cancelText: 'Cancelar',
      }).then(function (ok) { if (ok) doIt(); });
    } else if (confirm('¿Mover todos los enviados a la papelera?')) {
      doIt();
    }
  }

  /* ══════════════════════════════════════════
     NUEVO CORREO — picker de alias + abrir compose
     ══════════════════════════════════════════ */
  function toggleAliasPicker(e) {
    if (e) e.stopPropagation();
    var picker = document.getElementById('aliasPicker');
    var btn    = document.getElementById('composeNewBtn');
    var willOpen = !picker.classList.contains('open');
    picker.classList.toggle('open', willOpen);
    if (btn) btn.classList.toggle('open', willOpen);
  }
  function closeAliasPicker() {
    var picker = document.getElementById('aliasPicker');
    var btn    = document.getElementById('composeNewBtn');
    if (picker) picker.classList.remove('open');
    if (btn)    btn.classList.remove('open');
  }
  document.addEventListener('click', function (e) {
    var wrap = e.target.closest('.compose-new-wrap');
    if (!wrap) closeAliasPicker();
  });

  function composeFromAlias(item) {
    var id = item.dataset.aliasId;
    var addr = item.dataset.aliasAddress;
    var label = item.dataset.aliasLabel || '';
    closeAliasPicker();
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

  /* ══════════════════════════════════════════
     MOVER ENVIADO A PAPELERA
     ══════════════════════════════════════════ */
  function sentTrashEmail(btn) {
    var id = btn.dataset.emailId;
    if (!id) return;
    var row = btn.closest('.sent-row');
    if (!row) return;

    var csrf = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    csrf = csrf ? csrf.split('=')[1] : '';

    row.style.transition = 'transform 0.25s ease, opacity 0.25s ease, max-height 0.25s ease 0.1s, margin 0.25s ease 0.1s, padding 0.25s ease 0.1s';
    row.style.transform = 'translateX(-30px)';
    row.style.opacity = '0';

    fetch('/enviados/' + encodeURIComponent(id) + '/papelera/', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data && data.ok) {
          row.style.maxHeight = row.offsetHeight + 'px';
          requestAnimationFrame(function () {
            row.style.maxHeight = '0';
            row.style.marginTop = '0';
            row.style.marginBottom = '0';
            row.style.paddingTop = '0';
            row.style.paddingBottom = '0';
            row.style.borderWidth = '0';
            setTimeout(function () { row.remove(); }, 350);
          });
          if (window.showToast) {
            window.showToast({
              type: 'danger',
              title: 'Enviado movido a Papelera',
              message: 'Lo quitamos de tus enviados — se borrará para siempre en 30 días.',
              href: '/papelera/',
              duration: 4500,
            });
          }
        } else {
          row.style.transform = '';
          row.style.opacity = '';
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
        row.style.opacity = '';
      });
  }
