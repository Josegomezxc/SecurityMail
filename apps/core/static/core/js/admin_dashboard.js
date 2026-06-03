/* ══════════════════════════════════════════════════════════════════════
   ADMIN DASHBOARD
     - Chart.js: bar de actividad 7d, doughnut de distribución de riesgo,
       y doughnut de desglose de usuarios.
   ══════════════════════════════════════════════════════════════════════ */

(function () {
  /* Colores leídos del tema activo (dark=morado, carbon=rosa) */
  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  function hexToRgba(hex, alpha) {
    hex = (hex || '').trim().replace('#', '');
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    if (hex.length !== 6) return `rgba(167, 139, 250, ${alpha})`;
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  const accent      = cssVar('--accent',       '#6d4aff');
  const accentLight = cssVar('--accent-hover', '#7c5cff');

  /* ── DEFAULTS Chart.js (lee del tema activo) ─────────────────────── */
  if (typeof Chart !== 'undefined') {
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size   = 11;
    Chart.defaults.color       = hexToRgba(accentLight, 0.6);
  }

  /* ── 1) BAR CHART: actividad global últimos 7 días ───────────────── */
  const activityEl = document.getElementById('admActivityChart');
  const activityRaw = document.getElementById('admActivityData');
  if (activityEl && activityRaw && typeof Chart !== 'undefined') {
    let activity = [];
    try { activity = JSON.parse(activityRaw.textContent || '[]'); } catch (e) { activity = []; }

    const ctx    = activityEl.getContext('2d');
    const labels = activity.map(d => d.label);
    const counts = activity.map(d => d.count);

    const grad = ctx.createLinearGradient(0, 0, 0, 220);
    grad.addColorStop(0, hexToRgba(accentLight, 0.9));
    grad.addColorStop(1, hexToRgba(accent, 0.45));

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Correos',
          data: counts,
          backgroundColor: grad,
          borderColor: hexToRgba(accentLight, 0.9),
          borderWidth: 0,
          borderRadius: 6,
          maxBarThickness: 32,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend:  { display: false },
          tooltip: {
            backgroundColor: 'rgba(20, 14, 40, 0.95)',
            titleColor:  '#fff',
            bodyColor:   accentLight,
            borderColor: hexToRgba(accent, 0.5),
            borderWidth: 1,
            padding:     10,
            displayColors: false,
            callbacks: {
              label: (ctx) => `${ctx.parsed.y} correo${ctx.parsed.y === 1 ? '' : 's'}`,
            },
          },
        },
        scales: {
          x: {
            grid:    { display: false },
            ticks:   { color: 'rgba(255,255,255,0.4)', maxRotation: 0 },
            border:  { display: false },
          },
          y: {
            beginAtZero: true,
            grid:    { color: 'rgba(255,255,255,0.04)' },
            ticks:   { color: 'rgba(255,255,255,0.4)', precision: 0, stepSize: 1 },
            border:  { display: false },
          },
        },
      },
    });
  }

  /* ── 2) DONUT: distribución global de riesgo ─────────────────────── */
  const donutEl  = document.getElementById('admRiskDonut');
  const donutRaw = document.getElementById('admRiskData');
  if (donutEl && donutRaw && typeof Chart !== 'undefined') {
    let donut = {};
    try { donut = JSON.parse(donutRaw.textContent || '{}'); } catch (e) { donut = {}; }

    const safe    = parseInt(donut.safe    || 0, 10);
    const susp    = parseInt(donut.susp    || 0, 10);
    const threats = parseInt(donut.threats || 0, 10);
    const total   = safe + susp + threats;

    const data = total > 0 ? [safe, susp, threats] : [1];
    const colors = total > 0
      ? ['rgba(16, 185, 129, 0.85)', 'rgba(245, 158, 11, 0.85)', 'rgba(239, 68, 68, 0.85)']
      : ['rgba(255, 255, 255, 0.05)'];
    const labels = total > 0 ? ['Seguros', 'Sospechosos', 'Amenazas'] : ['Sin datos'];

    new Chart(donutEl.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderColor: 'rgba(0, 0, 0, 0)',
          borderWidth: 0,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: total > 0,
            backgroundColor: 'rgba(20, 14, 40, 0.95)',
            titleColor:  '#fff',
            bodyColor:   accentLight,
            borderColor: hexToRgba(accent, 0.5),
            borderWidth: 1,
            padding: 10,
            callbacks: {
              label: (ctx) => `${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed / total * 100)}%)`,
            },
          },
        },
      },
    });
  }

  /* ── 3) DONUT: desglose de usuarios (activos / staff / inactivos) ── */
  const usersEl  = document.getElementById('admUsersChart');
  const usersRaw = document.getElementById('admUsersData');
  if (usersEl && usersRaw && typeof Chart !== 'undefined') {
    let userData = {};
    try { userData = JSON.parse(usersRaw.textContent || '{}'); } catch (e) { userData = {}; }

    const active   = parseInt(userData.active   || 0, 10);
    const staff    = parseInt(userData.staff    || 0, 10);
    const inactive = parseInt(userData.inactive || 0, 10);
    const total    = active + staff + inactive;

    // Colores: accent del tema (activos), ámbar (admins), rojo apagado (inactivos).
    const data = total > 0 ? [active, staff, inactive] : [1];
    const colors = total > 0
      ? [hexToRgba(accentLight, 0.88), 'rgba(245, 158, 11, 0.85)', 'rgba(239, 68, 68, 0.55)']
      : ['rgba(255, 255, 255, 0.05)'];
    const labels = total > 0
      ? ['Activos (regulares)', 'Administradores', 'Inactivos']
      : ['Sin datos'];

    new Chart(usersEl.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: colors,
          borderColor: 'rgba(0, 0, 0, 0)',
          borderWidth: 0,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: total > 0,
            backgroundColor: 'rgba(20, 14, 40, 0.95)',
            titleColor:  '#fff',
            bodyColor:   accentLight,
            borderColor: hexToRgba(accent, 0.5),
            borderWidth: 1,
            padding: 10,
            callbacks: {
              label: (ctx) => `${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed / total * 100)}%)`,
            },
          },
        },
      },
    });
  }
})();
