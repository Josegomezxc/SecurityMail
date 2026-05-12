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

  /* ══════════════════════════════════════════
     AUTO-REFRESH DEL DASHBOARD
     ══════════════════════════════════════════ */
  var dashLiveEnabled = true;
  var dashPollTimer   = null;
  var dashLastStats   = null;     // para detectar cambios

  function toggleDashLive() {
    dashLiveEnabled = !dashLiveEnabled;
    var chip = document.getElementById('dashLiveChip');
    var txt  = document.getElementById('dashLiveChipText');
    if (dashLiveEnabled) {
      chip.classList.remove('paused');
      txt.textContent = 'en vivo';
      scheduleDashPoll(3000);
    } else {
      chip.classList.add('paused');
      txt.textContent = 'pausado';
    }
  }

  function scheduleDashPoll(delayMs) {
    if (dashPollTimer) clearTimeout(dashPollTimer);
    dashPollTimer = setTimeout(pollDashboard, delayMs || 15000);
  }

  function reloadDashboard() {
    window.location.reload();
  }

  async function pollDashboard() {
    if (!dashLiveEnabled) return;
    var chip = document.getElementById('dashLiveChip');
    chip.style.opacity = '1';

    try {
      var res = await fetch(__DASH_CTX.liveApiUrl, {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      });
      if (!res.ok) throw new Error('http ' + res.status);
      var data = await res.json();
      updateDashboardFromData(data);
    } catch (e) {
      console.warn('[dashboard-live] error:', e);
    } finally {
      setTimeout(function () { chip.style.opacity = '0.55'; }, 400);
      scheduleDashPoll(15000);
    }
  }

  function updateDashboardFromData(data) {
    /* Compara stats con la última snapshot. Anima los que cambiaron. */
    var keys = ['alias_count', 'total_emails', 'threats_count', 'safe_count', 'block_rate'];
    var anyChanged = false;
    var threatDelta = 0;

    keys.forEach(function (k) {
      var el = document.querySelector('[data-stat="' + k + '"]');
      if (!el) return;
      var newVal = parseInt(data[k]) || 0;
      var oldVal = parseInt(el.textContent) || 0;
      if (newVal !== oldVal) {
        animateStat(el, oldVal, newVal);
        if (dashLastStats !== null) {
          anyChanged = true;
          if (k === 'threats_count') threatDelta = newVal - oldVal;
        }
      }
    });

    /* Banner manual eliminado: los stats se actualizan solos con animateStat. */
    /* (Si quieres recordar que algo cambió, deja un console.info para debugging.) */
    if (anyChanged && dashLastStats !== null) {
      console.info('[dashboard-live] stats updated automatically');
    }

    dashLastStats = { ...data };
  }

  function animateStat(el, from, to) {
    el.classList.remove('bumped');
    void el.offsetWidth;
    el.classList.add('bumped');

    /* Tween rápido de números (200ms) */
    var diff = to - from;
    var start = performance.now();
    var dur = 400;
    function frame(t) {
      var pct = Math.min(1, (t - start) / dur);
      var pctEased = 1 - Math.pow(1 - pct, 3);
      el.textContent = Math.round(from + diff * pctEased);
      if (pct < 1) requestAnimationFrame(frame);
      else el.textContent = to;
    }
    requestAnimationFrame(frame);
  }

  /* Pausar cuando la pestaña no está visible */
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      if (dashPollTimer) clearTimeout(dashPollTimer);
    } else {
      scheduleDashPoll(2000);
    }
  });

  /* Arrancar el polling inmediatamente */
  console.info('[dashboard-live] polling activado');
  pollDashboard();
