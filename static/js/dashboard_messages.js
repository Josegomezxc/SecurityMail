(function () {
  var pending = window.__DASHBOARD_MESSAGES__ || [];
  var SEEN_KEY = 'sms_seen_django_msgs';
  function loadSeen() {
    try { return JSON.parse(sessionStorage.getItem(SEEN_KEY) || '[]'); }
    catch (e) { return []; }
  }
  function saveSeen(arr) {
    try { sessionStorage.setItem(SEEN_KEY, JSON.stringify(arr.slice(-20))); }
    catch (e) {}
  }
  function fingerprint(m) { return m.tags + '|' + m.text; }

  function showAll() {
    if (!window.showToast) { setTimeout(showAll, 100); return; }
    var seen = loadSeen();
    pending.forEach(function (m) {
      var fp = fingerprint(m);
      if (seen.indexOf(fp) !== -1) return;   // ya mostrado esta sesión
      seen.push(fp);

      var type = m.tags === 'error'   ? 'danger'
               : m.tags === 'success' ? 'success'
               : m.tags === 'warning' ? 'warning'
               : 'info';
      var title = m.tags === 'success' ? '¡Listo!'
                : m.tags === 'error'   ? 'Atención'
                : 'Aviso';
      window.showToast({
        type:     type,
        title:    title,
        message:  m.text,
        duration: 6000,
      });
    });
    saveSeen(seen);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showAll);
  } else {
    showAll();
  }
})();
