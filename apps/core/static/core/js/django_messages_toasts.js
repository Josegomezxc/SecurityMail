/* ════════════════════════════════════════════════════════════════════
   Convierte cualquier `messages` pendiente de Django en toasts.

   ANTES vivía solo en dashboard.html. PROBLEMA: si un admin hacía una
   acción desde /admin-panel/solicitudes/ que disparaba
   `messages.success("Aprobada ...")`, el mensaje quedaba guardado en la
   sesión hasta que el admin llegara al dashboard — ahí explotaban 4
   toasts juntos. Pésima UX y confuso.

   AHORA vive en base.html → se procesa en TODAS las páginas. El admin
   ve el toast inmediatamente en la misma página donde hizo la acción.

   Deduplicación: cada toast tiene una huella (tag + texto). Si el mismo
   mensaje aparece otra vez (ej. usuario refresca antes de que Django
   limpie la sesión), no se muestra dos veces.
   ════════════════════════════════════════════════════════════════════ */
(function () {
  var pending = window.__DJANGO_MESSAGES__ || [];
  if (!pending.length) return;

  var SEEN_KEY = 'sms_seen_django_msgs';
  function loadSeen() {
    try { return JSON.parse(sessionStorage.getItem(SEEN_KEY) || '[]'); }
    catch (e) { return []; }
  }
  function saveSeen(arr) {
    try { sessionStorage.setItem(SEEN_KEY, JSON.stringify(arr.slice(-30))); }
    catch (e) {}
  }
  function fingerprint(m) { return m.tags + '|' + m.text; }

  function showAll() {
    if (!window.showToast) { setTimeout(showAll, 100); return; }
    var seen = loadSeen();
    pending.forEach(function (m) {
      var fp = fingerprint(m);
      if (seen.indexOf(fp) !== -1) return;   // ya mostrado en esta sesión
      seen.push(fp);

      var type = m.tags === 'error'   ? 'danger'
               : m.tags === 'success' ? 'success'
               : m.tags === 'warning' ? 'warning'
               :                        'info';
      var title = m.tags === 'success' ? '¡Listo!'
                : m.tags === 'error'   ? 'Atención'
                : m.tags === 'warning' ? 'Aviso'
                :                        'Info';
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
