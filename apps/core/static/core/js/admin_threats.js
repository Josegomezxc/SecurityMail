(function () {
  const form  = document.getElementById('th-search-form');
  const input = document.getElementById('threatsSearchInput');
  if (!form || !input) return;

  let timer = null;
  function go() {
    const q = input.value.trim();
    const url = new URL(window.location.href);
    if (q) url.searchParams.set('q', q);
    else   url.searchParams.delete('q');
    url.searchParams.delete('page');
    if (url.toString() !== window.location.href) {
      window.location.href = url.toString();
    }
  }
  input.addEventListener('input', function () {
    if (timer) clearTimeout(timer);
    timer = setTimeout(go, 350);
  });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (timer) clearTimeout(timer);
    go();
  });
})();
