/* ══════════════════════════════════════════════════════════════════════
   SANDBOX LIST (server-side pagination)
   Filtros y búsqueda viven en query params (?filter=, ?q=, ?page=).
   Cada fila clickea al reporte del análisis correspondiente.
   ══════════════════════════════════════════════════════════════════════ */

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

  /* Búsqueda en tiempo real con debounce de 350ms (mismo patrón que bandeja).
     Cada pulsación reinicia el timer; al soltar la última tecla se navega
     a la URL con el nuevo `?q=`. Volver a página 1 al cambiar la búsqueda. */
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
    url.searchParams.delete('page');
    if (url.toString() !== window.location.href) {
      window.location.href = url.toString();
    }
  }

  searchInput.addEventListener('input', scheduleSearch);
  searchWrap.addEventListener('submit', function (e) {
    e.preventDefault();
    if (debounceTimer) clearTimeout(debounceTimer);
    submitSearch();
  });
});
