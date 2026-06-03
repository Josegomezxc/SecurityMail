/* ══════════════════════════════════════════════════════════════════════
   DASHBOARD USUARIO — Charts (Chart.js v4)

   Lee los colores del tema activo (dark/carbon) desde CSS variables al
   inicializar — así cuando el usuario cambie de tema los charts pintan
   con la paleta correcta. Reload necesario tras cambio de tema, no
   re-pintamos los charts en vivo (es aceptable, el usuario va a recargar
   tras tocar el toggle de todos modos).
   ══════════════════════════════════════════════════════════════════════ */
(function () {
  if (typeof Chart === 'undefined') {
    console.warn('[dashboard] Chart.js no se cargó.');
    return;
  }

  /* Lee una CSS custom property del :root con fallback */
  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }
  /* Convierte un hex (#aabbcc) a rgba(...) con la opacidad dada */
  function hexToRgba(hex, alpha) {
    hex = (hex || '').trim().replace('#', '');
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    if (hex.length !== 6) return `rgba(167, 139, 250, ${alpha})`;
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  /* Colores del tema actual (dark → morado, carbon → rosa) */
  const accent      = cssVar('--accent',       '#6d4aff');
  const accentLight = cssVar('--accent-hover', '#7c5cff');

  /* Defaults globales para Chart.js — fuente, color del eje, grid sutil */
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size   = 11;
  Chart.defaults.color       = hexToRgba(accentLight, 0.6);

  /* ── 1) BAR CHART: actividad últimos 14 días ──────────────────────── */
  const activityEl = document.getElementById('dashActivityChart');
  const activityData = JSON.parse(
    document.getElementById('dashActivityData').textContent || '[]'
  );
  if (activityEl && activityData.length) {
    const ctx    = activityEl.getContext('2d');
    const labels = activityData.map(d => d.label);
    const counts = activityData.map(d => d.count);

    /* Gradient vertical para las barras — usa el acento del tema activo */
    const grad = ctx.createLinearGradient(0, 0, 0, 220);
    grad.addColorStop(0, hexToRgba(accentLight, 0.9));
    grad.addColorStop(1, hexToRgba(accent, 0.5));

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
          maxBarThickness: 28,
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
            ticks:   { color: 'rgba(255,255,255,0.4)', maxRotation: 0, autoSkipPadding: 12 },
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

  /* ── 2) DONUT: distribución por nivel de riesgo ───────────────────── */
  const donutEl = document.getElementById('dashRiskDonut');
  const donutData = JSON.parse(
    document.getElementById('dashRiskData').textContent || '{}'
  );
  if (donutEl) {
    const safe    = parseInt(donutData.safe    || 0, 10);
    const susp    = parseInt(donutData.susp    || 0, 10);
    const threats = parseInt(donutData.threats || 0, 10);
    const total   = safe + susp + threats;

    /* Si está todo en cero, mostramos un anillo "vacío" gris */
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
          legend:  { display: false },
          tooltip: {
            enabled: total > 0,
            backgroundColor: 'rgba(20, 14, 40, 0.95)',
            titleColor:  '#fff',
            bodyColor:   accentLight,
            borderColor: hexToRgba(accent, 0.5),
            borderWidth: 1,
            padding:     10,
            callbacks: {
              label: (ctx) => `${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed / total * 100)}%)`,
            },
          },
        },
      },
    });
  }
})();
