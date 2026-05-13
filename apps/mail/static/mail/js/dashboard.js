  /* ── MODAL BIENVENIDA ── */
  var __DASH_CTX = window.__DASHBOARD_CTX__ || {};
  const welcomeKey = __DASH_CTX.welcomeKey;
  if (!localStorage.getItem(welcomeKey)) {
    document.getElementById('welcome-overlay').classList.add('visible');
  }
  function closeWelcome() {
    localStorage.setItem(welcomeKey, 'true');
    document.getElementById('welcome-overlay').classList.remove('visible');
  }
