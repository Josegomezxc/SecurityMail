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
    if (v) return v;
    // Fallback defensivo basado en el tema activo
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    if (theme === 'light') {
      if (name.includes('text-muted')) return '#000000';
      if (name.includes('border')) return 'rgba(0,0,0,0.1)';
      if (name.includes('accent-hover')) return '#5a3ee0';
      if (name.includes('accent')) return '#6d4aff';
    }
    return fallback;
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

  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const isLight = theme === 'light';

  /* Colores del tema actual (dark → morado, carbon → rosa) */
  const accent      = cssVar('--accent',       isLight ? '#6d4aff' : '#6d4aff');
  const accentLight = cssVar('--accent-hover', isLight ? '#5a3ee0' : '#7c5cff');

  /* Defaults globales para Chart.js — fuente, color del eje, grid sutil */
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size   = 11;
  Chart.defaults.color       = isLight ? '#000000' : hexToRgba(accentLight, 0.6);

  /* ── 1) BAR CHART: actividad según período ─────────────────────── */
  const activityEl = document.getElementById('dashActivityChart');
  const subtitleEl = document.getElementById('dashActivitySub');
  const periodSelect = document.getElementById('dashPeriodSelect');
  var activityChart = null;

  function buildGradient(ctx) {
    var g = ctx.createLinearGradient(0, 0, 0, 220);
    g.addColorStop(0, hexToRgba(accentLight, 0.9));
    g.addColorStop(1, hexToRgba(accent, 0.5));
    return g;
  }

  function renderChart(labels, counts) {
    if (!activityEl) return;
    var ctx = activityEl.getContext('2d');
    if (activityChart) activityChart.destroy();

    activityChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Correos',
          data: counts,
          backgroundColor: buildGradient(ctx),
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
              label: function (ctx) { return ctx.parsed.y + ' corre' + (ctx.parsed.y === 1 ? 'o' : 'os'); },
            },
          },
        },
        scales: {
          x: {
            grid:    { display: false },
            ticks:   { color: cssVar('--text-muted', isLight ? '#000000' : 'rgba(255,255,255,0.4)'), maxRotation: 0, autoSkipPadding: 12 },
            border:  { display: false },
          },
          y: {
            beginAtZero: true,
            grid:    { color: cssVar('--border', isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.04)') },
            ticks:   { color: cssVar('--text-muted', isLight ? '#000000' : 'rgba(255,255,255,0.4)'), precision: 0, stepSize: 1 },
            border:  { display: false },
          },
        },
      },
    });
  }

  // Initial render with server data
  var initialData = JSON.parse(
    document.getElementById('dashActivityData').textContent || '[]'
  );
  if (activityEl && initialData.length) {
    renderChart(
      initialData.map(function (d) { return d.label; }),
      initialData.map(function (d) { return d.count; })
    );
  }

  // Period selector → AJAX update
  if (periodSelect) {
    periodSelect.addEventListener('change', function () {
      var period = periodSelect.value;
      fetch('/dashboard/actividad/?period=' + period)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.activity_data && data.activity_data.length) {
            renderChart(
              data.activity_data.map(function (d) { return d.label; }),
              data.activity_data.map(function (d) { return d.count; })
            );
          }
          if (subtitleEl && data.range_label) {
            subtitleEl.textContent = data.range_label + ' — correos recibidos';
          }
        })
        .catch(function () {
          if (window.showToast) {
            window.showToast({ type: 'danger', title: 'Error', message: 'No se pudo actualizar el gráfico.', duration: 4000 });
          }
        });
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
      : [cssVar('--border', isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255, 255, 255, 0.05)')];
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
