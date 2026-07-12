

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
