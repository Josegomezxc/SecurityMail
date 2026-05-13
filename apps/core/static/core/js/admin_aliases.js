/* ════════════════════════════════════════════════════════════════════
   Admin · Listado de alias
   ─────────────────────────────────────────────────────────────────────
   - Búsqueda en tiempo real (sin Enter): filtra rows por texto.
   - Paginación client-side: 10 filas por página.
   Las dos cosas trabajan juntas: al buscar, la paginación se recalcula
   sobre el subset filtrado y vuelve a la página 1.
   ════════════════════════════════════════════════════════════════════ */
(function () {
  var ROWS_PER_PAGE = 5;

  var tableWrap = document.querySelector('.al-table-wrap');
  if (!tableWrap) return;

  // Recolectamos todas las filas (sin el header). Si el backend devolvió
  // vacío, .al-empty existe pero NO es una row paginable — la excluimos.
  var allRows = Array.prototype.slice.call(
    tableWrap.querySelectorAll('.al-row:not(.head)')
  );
  // Filtrar el div .al-empty si quedó adentro (por el {% empty %} block).
  allRows = allRows.filter(function (r) { return !r.classList.contains('al-empty'); });

  var searchInput = document.getElementById('aliasSearchInput');
  var emptySearchEl = document.getElementById('al-empty-search');
  var paginationEl = document.getElementById('al-pagination');

  var state = {
    page: 1,
    query: (searchInput && searchInput.value) || '',
    filteredRows: allRows,
  };

  function applyFilter() {
    var q = state.query.trim().toLowerCase();
    if (!q) {
      state.filteredRows = allRows;
      return;
    }
    state.filteredRows = allRows.filter(function (r) {
      return (r.textContent || '').toLowerCase().indexOf(q) !== -1;
    });
  }

  function render() {
    // Total páginas para el filtro actual.
    var total = state.filteredRows.length;
    var pages = Math.max(1, Math.ceil(total / ROWS_PER_PAGE));
    if (state.page > pages) state.page = pages;
    if (state.page < 1) state.page = 1;

    // Ocultar TODAS las filas, después mostrar las de la página actual.
    allRows.forEach(function (r) { r.style.display = 'none'; });
    var start = (state.page - 1) * ROWS_PER_PAGE;
    var end = start + ROWS_PER_PAGE;
    state.filteredRows.slice(start, end).forEach(function (r) {
      r.style.display = '';
    });

    // Mensaje "sin resultados de búsqueda" — solo cuando la query no
    // está vacía y el filtro resulta en 0 rows. Si no hay búsqueda y
    // total=0, ya se muestra el .al-empty del backend.
    if (emptySearchEl) {
      var noResults = (state.query.trim() !== '' && total === 0);
      emptySearchEl.style.display = noResults ? '' : 'none';
    }

    renderPagination(pages, total);
  }

  function renderPagination(pages, total) {
    if (!paginationEl) return;
    // Si todo cabe en una sola página, no mostramos controles.
    if (total <= ROWS_PER_PAGE) {
      paginationEl.innerHTML = '';
      paginationEl.style.display = 'none';
      return;
    }
    paginationEl.style.display = '';
    paginationEl.innerHTML = '';

    // ── Botón "Anterior" ───────────────────────────────────────────
    var prev = makeBtn('‹', function () {
      if (state.page > 1) { state.page--; render(); scrollToTable(); }
    });
    prev.classList.add('al-pg-arrow');
    prev.disabled = (state.page === 1);
    paginationEl.appendChild(prev);

    // ── Números de página (compactos: 1, …, p-1, p, p+1, …, last) ─
    var pageNums = compactPages(state.page, pages);
    pageNums.forEach(function (n) {
      if (n === '…') {
        var dots = document.createElement('span');
        dots.className = 'al-pg-dots';
        dots.textContent = '…';
        paginationEl.appendChild(dots);
        return;
      }
      var btn = makeBtn(String(n), function () {
        state.page = n; render(); scrollToTable();
      });
      if (n === state.page) btn.classList.add('active');
      paginationEl.appendChild(btn);
    });

    // ── Botón "Siguiente" ──────────────────────────────────────────
    var next = makeBtn('›', function () {
      if (state.page < pages) { state.page++; render(); scrollToTable(); }
    });
    next.classList.add('al-pg-arrow');
    next.disabled = (state.page === pages);
    paginationEl.appendChild(next);

    // ── Info "1-10 de 47" ──────────────────────────────────────────
    var info = document.createElement('span');
    info.className = 'al-pg-info';
    var startIdx = (state.page - 1) * ROWS_PER_PAGE + 1;
    var endIdx = Math.min(state.page * ROWS_PER_PAGE, total);
    info.textContent = startIdx + '-' + endIdx + ' de ' + total;
    paginationEl.appendChild(info);
  }

  /* Devuelve un array tipo [1, '…', 4, 5, 6, '…', 12] que es la
     paginación "compacta": siempre mostramos primera, última, la actual
     y sus vecinas. */
  function compactPages(current, total) {
    if (total <= 7) {
      var arr = [];
      for (var i = 1; i <= total; i++) arr.push(i);
      return arr;
    }
    var result = [1];
    var left = Math.max(2, current - 1);
    var right = Math.min(total - 1, current + 1);
    if (left > 2) result.push('…');
    for (var j = left; j <= right; j++) result.push(j);
    if (right < total - 1) result.push('…');
    result.push(total);
    return result;
  }

  function makeBtn(text, onClick) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'al-pg-btn';
    b.textContent = text;
    b.addEventListener('click', onClick);
    return b;
  }

  function scrollToTable() {
    // En mobile, paginar puede dejarte mirando el final de la página
    // anterior. Scrolleamos al tope de la tabla para que se vea el
    // contenido nuevo.
    if (window.innerWidth < 720) {
      tableWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  // ── Exponemos la función de búsqueda en window para el oninput ──
  window.aliasTableSearch = function (q) {
    state.query = q || '';
    state.page = 1;
    applyFilter();
    render();
  };

  // Render inicial.
  applyFilter();
  render();
})();
