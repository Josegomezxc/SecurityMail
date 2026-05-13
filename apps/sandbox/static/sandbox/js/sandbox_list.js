var currentFilter = 'all';
var currentSearch = '';

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.qfilter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () { setFilter(btn.dataset.filter); });
  });
  updateCounts();
});

function updateCounts() {
  var cards = document.querySelectorAll('.analysis-card');
  var total = cards.length;
  var malware = 0, danger = 0, warning = 0, safe = 0;
  cards.forEach(function (c) {
    var score = parseInt(c.dataset.score) || 0;
    if      (score >= 81) malware++;
    else if (score >= 61) danger++;
    else if (score >= 31) warning++;
    else                  safe++;
  });
  document.getElementById('qb-all').textContent     = total;
  document.getElementById('qb-malware').textContent = malware;
  document.getElementById('qb-danger').textContent  = danger;
  document.getElementById('qb-warning').textContent = warning;
  document.getElementById('qb-safe').textContent    = safe;
}

function onSearchInput(value) {
  currentSearch = value.toLowerCase().trim();
  var clearBtn = document.getElementById('search-clear');
  clearBtn.classList.toggle('visible', currentSearch.length > 0);
  applyFilters();
}
function clearSearch() {
  document.getElementById('search-input').value = '';
  document.getElementById('search-clear').classList.remove('visible');
  currentSearch = '';
  applyFilters();
  document.getElementById('search-input').focus();
}

function setFilter(type) {
  currentFilter = type;
  document.querySelectorAll('.qfilter-btn').forEach(function (btn) {
    btn.classList.remove('active', 'active-danger', 'active-success', 'active-warning');
  });
  var activeBtn = document.querySelector('.qfilter-btn[data-filter="' + type + '"]');
  if (activeBtn) {
    if      (type === 'malware' || type === 'danger') activeBtn.classList.add('active-danger');
    else if (type === 'safe')                          activeBtn.classList.add('active-success');
    else if (type === 'warning')                       activeBtn.classList.add('active-warning');
    else                                               activeBtn.classList.add('active');
  }
  applyFilters();
}

function applyFilters() {
  var cards = document.querySelectorAll('.analysis-card');
  var visible = 0;
  cards.forEach(function (c) {
    var score = parseInt(c.dataset.score) || 0;
    var passF = true;
    if      (currentFilter === 'malware') passF = score >= 81;
    else if (currentFilter === 'danger')  passF = score >= 61 && score < 81;
    else if (currentFilter === 'warning') passF = score >= 31 && score < 61;
    else if (currentFilter === 'safe')    passF = score < 31;

    var passS = true;
    if (currentSearch.length > 0) {
      var blob = (c.dataset.filename || '') + ' ' +
                 (c.dataset.subject  || '') + ' ' +
                 (c.dataset.sender   || '') + ' ' +
                 (c.dataset.threat   || '') + ' ' +
                 (c.dataset.category || '');
      passS = blob.indexOf(currentSearch) !== -1;
    }
    var show = passF && passS;
    c.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  var noResults = document.getElementById('no-results');
  var msgEl     = document.getElementById('no-results-msg');
  var hintEl    = document.getElementById('no-results-hint');
  if (visible === 0 && cards.length > 0) {
    noResults.style.display = 'block';
    if (currentSearch.length > 0) {
      msgEl.textContent  = 'Sin resultados para "' + currentSearch + '"';
      hintEl.textContent = 'Prueba con otro término o cambia el filtro activo';
    } else {
      var copy = FILTER_EMPTY_COPY[currentFilter] || FILTER_EMPTY_COPY.all;
      msgEl.textContent  = copy.title;
      hintEl.textContent = copy.hint;
    }
  } else {
    noResults.style.display = 'none';
  }
}

var FILTER_EMPTY_COPY = {
  all: {
    title: 'Sin análisis aún',
    hint:  'Cuando recibas correos con adjuntos en tus alias, aparecerán aquí.',
  },
  malware: {
    title: 'No hay archivos con malware',
    hint:  'Ningún adjunto analizado supera el umbral de score 81. Selecciona "Todos" para ver el resto.',
  },
  danger: {
    title: 'No hay archivos de alto riesgo',
    hint:  'Ningún adjunto cae en el rango de score 61-80. Selecciona "Todos" para ver los demás análisis.',
  },
  warning: {
    title: 'No hay archivos sospechosos',
    hint:  'Ningún adjunto cae en el rango de score 31-60. Selecciona "Todos" para ver los demás análisis.',
  },
  safe: {
    title: 'No hay archivos seguros',
    hint:  'Todos los adjuntos analizados tienen algún indicador. Selecciona "Todos" para ver los demás análisis.',
  },
};
