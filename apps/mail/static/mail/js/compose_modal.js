/* ════════════════════════════════════════════════════════════════════
   COMPOSE MODAL — JS con persistencia entre páginas (sessionStorage)
   ════════════════════════════════════════════════════════════════════ */
(function () {
  var overlay     = document.getElementById('composeOverlay');
  var win         = document.getElementById('composeWindow');
  var fromAddr    = document.getElementById('composeFromAddr');
  var inputTo       = document.getElementById('composeTo');         // hidden, valor real (chips coma-joined)
  var inputToTyping = document.getElementById('composeToTyping');    // visible, donde el usuario teclea
  var chipsBox     = document.getElementById('composeChips');
  var suggestBox   = document.getElementById('composeSuggestions');
  var inputSubj    = document.getElementById('composeSubject');
  var editor      = document.getElementById('composeMessage');
  var errTo       = document.getElementById('composeErrTo');
  var errSubj     = document.getElementById('composeErrSubject');
  var errMsg      = document.getElementById('composeErrMessage');
  var btnSend     = document.getElementById('composeSendBtn');
  var btnClose    = document.getElementById('composeClose');
  var btnMinimize = document.getElementById('composeMinimize');
  var form        = document.getElementById('composeForm');
  var toolbar     = form ? form.querySelector('.compose-toolbar') : null;
  var btnLink     = document.getElementById('ctbLink');
  var btnAttach   = document.getElementById('composeAttachBtn');
  var fileInput   = document.getElementById('composeFileInput');
  var attachList  = document.getElementById('composeAttachments');

  if (!win || !form) return;

  // ── Estado interno ──
  var STATE_KEY = 'sms_compose_state';
  var currentAliasId   = null;
  var currentAliasAddr = '';
  var currentAliasLabel = '';
  var currentDraftId   = null;               // id del borrador asociado (si lo hay)
  var recipients       = [];                 // chips committed [{email, label}]
  var suggestActive    = -1;                 // índice resaltado en el dropdown
  var suggestItems     = [];                 // resultados actuales del dropdown
  var attachedFiles    = [];                 // File[] (no se persiste)
  var attachedTotalBytes = 0;
  var MAX_TOTAL_BYTES  = 25 * 1024 * 1024;
  var MAX_FILES        = 10;

  function getCsrf() {
    var hidden = form.querySelector('input[name=csrfmiddlewaretoken]');
    if (hidden) return hidden.value;
    var c = document.cookie.split(';').find(function (s) { return s.trim().startsWith('csrftoken='); });
    return c ? c.split('=')[1] : '';
  }

  // ── Persistencia: sessionStorage ──
  // Guardamos el estado del compose entre navegaciones para que el usuario
  // pueda navegar por la web con el correo abierto/minimizado y al cerrar
  // explícitamente con la X se borra. NO se guardan adjuntos (File objects
  // no son serializables) — el usuario los pierde al navegar.
  function saveState() {
    if (!win.classList.contains('open')) return;
    var isMin = win.classList.contains('minimized');
    var isMax = win.classList.contains('maximized');
    // Si está minimizado, la clase 'maximized' fue removida temporalmente
    // pero queremos persistir la intención del usuario para restaurarla
    // al des-minimizar (incluso después de navegar de página).
    var maxIntent = isMin ? wasMaximizedBeforeMinimize : isMax;
    try {
      sessionStorage.setItem(STATE_KEY, JSON.stringify({
        aliasId:      currentAliasId,
        aliasAddress: currentAliasAddr,
        aliasLabel:   currentAliasLabel,
        to:           inputTo.value,
        subject:      inputSubj.value,
        bodyHtml:     editor.innerHTML,
        scheduledAt:  inputScheduled.value,
        minimized:    isMin,
        maximized:    maxIntent,
      }));
    } catch (e) {}
  }
  function clearState() {
    try { sessionStorage.removeItem(STATE_KEY); } catch (e) {}
  }

  function clearErrors() {
    [errTo, errSubj, errMsg].forEach(function (el) {
      el.classList.remove('show'); el.textContent = '';
    });
  }
  function showErrors(map) {
    clearErrors();
    if (map.to)          { errTo.textContent   = map.to;          errTo.classList.add('show'); }
    if (map.subject)     { errSubj.textContent = map.subject;     errSubj.classList.add('show'); }
    if (map.message)     { errMsg.textContent  = map.message;     errMsg.classList.add('show'); }
    if (map.attachments) { errMsg.textContent  = map.attachments; errMsg.classList.add('show'); }
  }

  function defaultBody() {
    return '<p>Hola,</p><p><br></p><p><br></p><p>Saludos,<br>Enviado desde mi alias seguro de DockerShield.</p>';
  }

  // ── Toolbar de formato ──
  if (toolbar) {
    toolbar.addEventListener('click', function (e) {
      var btn = e.target.closest('.ctb');
      if (!btn) return;
      var cmd = btn.dataset.cmd;
      if (!cmd) return;
      e.preventDefault();
      editor.focus();
      document.execCommand(cmd, false, null);
      updateToolbarState();
      saveState();
    });
  }
  if (btnLink) {
    btnLink.addEventListener('click', function (e) {
      e.preventDefault();
      var url = window.prompt('URL del enlace (debe empezar con https://):');
      if (!url) return;
      url = url.trim();
      if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
      editor.focus();
      document.execCommand('createLink', false, url);
      saveState();
    });
  }
  function updateToolbarState() {
    if (!toolbar) return;
    toolbar.querySelectorAll('.ctb[data-cmd]').forEach(function (b) {
      try {
        var active = document.queryCommandState(b.dataset.cmd);
        b.classList.toggle('active', !!active);
      } catch (e) {}
    });
  }
  if (editor) {
    editor.addEventListener('keyup', updateToolbarState);
    editor.addEventListener('mouseup', updateToolbarState);
    editor.addEventListener('focus', updateToolbarState);
    editor.addEventListener('input', saveState);
    editor.addEventListener('paste', function (e) {
      e.preventDefault();
      var text = (e.clipboardData || window.clipboardData).getData('text/plain');
      document.execCommand('insertText', false, text);
    });
  }
  // El input de "Para" (visible) tiene su propio listener más abajo en el
  // bloque de CHIPS, que llama a saveState() después de sincronizar.
  inputSubj.addEventListener('input', saveState);

  // ── Adjuntos ──
  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }
  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, function (c) {
      return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c];
    });
  }
  function renderAttachments() {
    if (!attachList) return;
    attachList.innerHTML = attachedFiles.map(function (f, i) {
      return '<span class="compose-attachment">'
        + '<svg class="compose-attachment-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>'
        + '<span class="compose-attachment-name" title="' + escapeHtml(f.name) + '">' + escapeHtml(f.name) + '</span>'
        + '<span class="compose-attachment-size">' + fmtSize(f.size) + '</span>'
        + '<button type="button" class="compose-attachment-remove" data-idx="' + i + '" aria-label="Quitar adjunto"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>'
        + '</span>';
    }).join('');
  }
  function addFiles(files) {
    var added = 0;
    Array.from(files).forEach(function (f) {
      if (attachedFiles.length >= MAX_FILES) return;
      if (attachedTotalBytes + f.size > MAX_TOTAL_BYTES) {
        if (window.showToast) window.showToast({ type:'warning', title:'Adjunto omitido', message: f.name + ' supera el límite total de 25 MB.', duration:5000 });
        return;
      }
      attachedFiles.push(f);
      attachedTotalBytes += f.size;
      added++;
    });
    if (added) renderAttachments();
  }
  if (btnAttach) {
    btnAttach.addEventListener('click', function () {
      if (!fileInput) return;
      fileInput.value = '';
      fileInput.click();
    });
  }
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      if (fileInput.files && fileInput.files.length) addFiles(fileInput.files);
    });
  }
  if (attachList) {
    attachList.addEventListener('click', function (e) {
      var btn = e.target.closest('.compose-attachment-remove');
      if (!btn) return;
      var idx = parseInt(btn.dataset.idx, 10);
      if (isNaN(idx)) return;
      var removed = attachedFiles.splice(idx, 1)[0];
      if (removed) attachedTotalBytes -= removed.size;
      renderAttachments();
    });
  }
  if (editor) {
    ['dragover','drop'].forEach(function (evt) {
      editor.addEventListener(evt, function (e) { e.preventDefault(); });
    });
    editor.addEventListener('drop', function (e) {
      e.preventDefault();
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
    });
  }

  // ── Programar envío (popover + custom) ──
  var sendWrap        = document.getElementById('composeSendWrap');
  var btnSendArrow    = document.getElementById('composeSendArrow');
  var schedulePopover = document.getElementById('schedulePopover');
  var sendText        = document.getElementById('composeSendText');
  var schedTomorrowEl = document.getElementById('schedTomorrowText');
  var schedMondayEl   = document.getElementById('schedMondayText');
  var inputScheduled  = document.getElementById('composeScheduledAt');
  var schedBanner     = document.getElementById('composeScheduledBanner');
  var schedLabel      = document.getElementById('composeScheduledLabel');
  var btnSchedClear   = document.getElementById('composeScheduledClear');
  var customOverlay   = document.getElementById('scheduleCustomOverlay');
  var customError     = document.getElementById('scheduleCustomError');
  var btnCustomClose  = document.getElementById('scheduleCustomClose');
  var btnCustomCancel = document.getElementById('scheduleCustomCancel');
  var btnCustomConfirm = document.getElementById('scheduleCustomConfirm');
  var calTitle        = document.getElementById('schedCalTitle');
  var calGrid         = document.getElementById('schedCalGrid');
  var calPrev         = document.getElementById('schedPrev');
  var calNext         = document.getElementById('schedNext');
  var hourInput       = document.getElementById('schedHour');
  var minuteInput     = document.getElementById('schedMinute');
  var ampmToggle      = document.getElementById('schedAmPm');
  var summaryWhen     = document.getElementById('schedSummaryWhen');
  var summaryRel      = document.getElementById('schedSummaryRel');
  var presets         = document.querySelectorAll('.sched-preset');
  var stepBtns        = document.querySelectorAll('.sched-time-btn');

  var MONTH_NAMES_FULL = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
  var MONTHS_ES = ['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'];
  var sched = { selected: null, viewYear: 0, viewMonth: 0 };

  function pad2(n) { return n < 10 ? '0' + n : '' + n; }
  function pad2x(n) { return pad2(n); }
  function startOfDay(d) { var x = new Date(d); x.setHours(0,0,0,0); return x; }
  function sameDay(a, b) {
    return a && b && a.getFullYear()===b.getFullYear() && a.getMonth()===b.getMonth() && a.getDate()===b.getDate();
  }
  function isoLocal(d) {
    return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+'T'+pad2(d.getHours())+':'+pad2(d.getMinutes());
  }

  function renderCalendar() {
    if (!calGrid || !calTitle) return;
    var y = sched.viewYear, m = sched.viewMonth;
    calTitle.textContent = MONTH_NAMES_FULL[m] + ' ' + y;
    var firstDow = new Date(y, m, 1).getDay();
    var startOffset = (firstDow + 6) % 7;
    var daysInMonth = new Date(y, m + 1, 0).getDate();
    var prevDays = new Date(y, m, 0).getDate();
    var todayStart = startOfDay(new Date());
    var maxDate = startOfDay(new Date(Date.now() + 72 * 60 * 60 * 1000));
    var html = '';
    for (var i = startOffset; i > 0; i--) html += '<button type="button" class="sched-day other" tabindex="-1" disabled>' + (prevDays - i + 1) + '</button>';
    for (var d = 1; d <= daysInMonth; d++) {
      var thisDate = new Date(y, m, d);
      var classes = ['sched-day'];
      if (sameDay(thisDate, new Date())) classes.push('today');
      if (sched.selected && sameDay(thisDate, sched.selected)) classes.push('selected');
      var disabled = thisDate < todayStart || thisDate > maxDate;
      if (disabled) classes.push('disabled');
      html += '<button type="button" class="' + classes.join(' ') + '" data-day="' + d + '"' + (disabled ? ' disabled' : '') + '>' + d + '</button>';
    }
    var totalCells = startOffset + daysInMonth;
    var pad = (Math.ceil(totalCells / 7) * 7) - totalCells;
    for (var k = 1; k <= pad; k++) html += '<button type="button" class="sched-day other" tabindex="-1" disabled>' + k + '</button>';
    calGrid.innerHTML = html;
    var todayMonth = new Date().getFullYear() * 12 + new Date().getMonth();
    var maxMonth   = new Date(maxDate).getFullYear() * 12 + new Date(maxDate).getMonth();
    var viewIdx    = y * 12 + m;
    if (calPrev) calPrev.disabled = viewIdx <= todayMonth;
    if (calNext) calNext.disabled = viewIdx >= maxMonth;
  }
  function relativeText(target) {
    var diffMs = target.getTime() - Date.now();
    if (diffMs <= 0) return 'En el pasado';
    /* Round UP en lugar de round: si faltan 27 segundos a las 14:45 y
       el usuario eligió 14:45, mostramos "En 1 min" en vez de "En 0
       min" (que sonaba a que ya estaba pasando o ya pasó). */
    var totalMin = Math.max(1, Math.ceil(diffMs / 60000));
    if (totalMin < 60) return 'En ' + totalMin + ' min';
    var hours = Math.floor(totalMin / 60);
    var mins  = totalMin % 60;
    if (hours < 24) return mins ? 'En '+hours+' h '+mins+' min' : 'En '+hours+' h';
    var days = Math.floor(hours / 24);
    var hrs = hours % 24;
    return hrs ? 'En '+days+' d '+hrs+' h' : 'En '+days+' d';
  }
  /* ────────────────────────────────────────────────────────────────
     Helpers de formato 12h: el estado interno (sched.selected) sigue
     siendo 24h (es lo que JS Date expone), pero el INPUT y el resumen
     muestran 12h + AM/PM.
       to12h(h24) → 0→12, 1-11→1-11, 12→12, 13-23→1-11
       to24h(h12, isPm) → reconstruye 0-23
     ──────────────────────────────────────────────────────────────── */
  function to12h(h24) {
    var h = h24 % 12;
    return h === 0 ? 12 : h;
  }
  function to24h(h12, isPm) {
    var h = h12 % 12;        // 12 → 0
    return isPm ? h + 12 : h; // AM keeps, PM +12
  }
  function fmt12(d) {
    var h12 = to12h(d.getHours());
    var mer = d.getHours() >= 12 ? 'PM' : 'AM';
    return h12 + ':' + pad2x(d.getMinutes()) + ' ' + mer;
  }

  function updateSummary() {
    if (!sched.selected || !summaryWhen) return;
    var d = sched.selected;
    var weekday = ['domingo','lunes','martes','miércoles','jueves','viernes','sábado'][d.getDay()];
    var dayStr = d.getDate() + ' ' + MONTH_NAMES_FULL[d.getMonth()];
    summaryWhen.textContent = weekday + ', ' + dayStr + ' · ' + fmt12(d);
    summaryRel.textContent  = relativeText(d);
    var now = Date.now();
    /* El selector zeroea los segundos del momento elegido (14:45:00).
       Si comparamos contra now+60s con now=14:44:33, min=14:45:33 y el
       usuario quedaba inválido eligiendo 14:45 aunque fuera 1 minuto
       en el futuro. Validamos contra el INICIO DEL PRÓXIMO MINUTO
       redondeando now hacia arriba al minuto siguiente. */
    var min = now - (now % 60000) + 60000;
    var max = now + 72 * 60 * 60 * 1000;
    var valid = d.getTime() >= min && d.getTime() <= max;
    btnCustomConfirm.disabled = !valid;
    if (!valid) {
      customError.textContent = (d.getTime() < min) ? 'La hora ya pasó. Elige al menos 1 minuto en el futuro.' : 'No se puede programar más de 72 horas en el futuro.';
      customError.hidden = false;
    } else { customError.hidden = true; }
  }
  function setSelectedDate(d) {
    sched.selected = new Date(d);
    sched.selected.setSeconds(0, 0);
    sched.viewYear = sched.selected.getFullYear();
    sched.viewMonth = sched.selected.getMonth();
    /* Input visible en 12h (1-12). El toggle AM/PM refleja el estado
       interno (24h). Si la hora interna es ≥12 → PM. */
    var h24 = sched.selected.getHours();
    hourInput.value = pad2x(to12h(h24));
    minuteInput.value = pad2x(sched.selected.getMinutes());
    if (ampmToggle) {
      var isPm = h24 >= 12;
      ampmToggle.textContent = isPm ? 'PM' : 'AM';
      ampmToggle.classList.toggle('is-pm', isPm);
    }
    renderCalendar();
    updateSummary();
  }

  if (calGrid) {
    calGrid.addEventListener('click', function (e) {
      var btn = e.target.closest('.sched-day');
      if (!btn || btn.disabled) return;
      var day = parseInt(btn.dataset.day, 10);
      if (isNaN(day)) return;
      var newDate = new Date(sched.selected || new Date());
      newDate.setFullYear(sched.viewYear);
      newDate.setMonth(sched.viewMonth);
      newDate.setDate(day);
      setSelectedDate(newDate);
    });
  }
  if (calPrev) calPrev.addEventListener('click', function () {
    sched.viewMonth--;
    if (sched.viewMonth < 0) { sched.viewMonth = 11; sched.viewYear--; }
    renderCalendar();
  });
  if (calNext) calNext.addEventListener('click', function () {
    sched.viewMonth++;
    if (sched.viewMonth > 11) { sched.viewMonth = 0; sched.viewYear++; }
    renderCalendar();
  });
  stepBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (!sched.selected) return;
      var step = parseInt(btn.dataset.step, 10) || 0;
      var target = btn.dataset.target;
      var d = new Date(sched.selected);
      if (target === 'hour') {
        /* Cicla 1-12 manteniendo AM/PM. Pasar de 12 a 1 (o 1 a 12)
           NO cambia el meridiano — para eso está el toggle dedicado. */
        var isPm = d.getHours() >= 12;
        var h12  = to12h(d.getHours()) + step;
        if (h12 > 12) h12 = 1;
        else if (h12 < 1) h12 = 12;
        d.setHours(to24h(h12, isPm));
      }
      else if (target === 'minute') d.setMinutes(d.getMinutes() + step);
      setSelectedDate(d);
    });
  });

  /* Toggle AM/PM: alterna el meridiano del estado interno. */
  if (ampmToggle) {
    ampmToggle.addEventListener('click', function () {
      if (!sched.selected) return;
      var d = new Date(sched.selected);
      var h24 = d.getHours();
      d.setHours(h24 >= 12 ? h24 - 12 : h24 + 12);
      setSelectedDate(d);
    });
  }
  function bindNumInput(input, min, max, isHour) {
    if (!input) return;
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); input.blur(); return; }
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key.length > 1) return;
      if (!/^\d$/.test(e.key)) e.preventDefault();
    });
    input.addEventListener('input', function () {
      var cleaned = input.value.replace(/[^\d]/g, '').slice(0, 2);
      if (cleaned !== input.value) input.value = cleaned;
      var v = parseInt(cleaned, 10);
      if (!isNaN(v) && v > max) input.value = String(max);
    });
    input.addEventListener('blur', function () {
      var v = parseInt(input.value, 10);
      if (isNaN(v)) v = isHour ? to12h(new Date().getHours()) : 0;
      v = Math.max(min, Math.min(max, v));
      input.value = pad2x(v);
      if (sched.selected) {
        var d = new Date(sched.selected);
        if (isHour) {
          /* v viene en 12h (1-12). Reconstruye 24h con el meridiano
             actual del estado interno (no del toggle por separado). */
          var isPm = d.getHours() >= 12;
          d.setHours(to24h(v, isPm));
        } else {
          d.setMinutes(v);
        }
        setSelectedDate(d);
      }
    });
    input.addEventListener('focus', function () { input.select(); });
  }
  /* Hora ahora va 1-12 (formato AM/PM); minutos siguen 0-59. */
  bindNumInput(hourInput, 1, 12, true);
  bindNumInput(minuteInput, 0, 59, false);

  presets.forEach(function (chip) {
    chip.addEventListener('click', function () {
      var mins = parseInt(chip.dataset.mins, 10);
      if (!isNaN(mins)) { setSelectedDate(new Date(Date.now() + mins * 60 * 1000)); return; }
      var tom = parseInt(chip.dataset.tomorrow, 10);
      if (!isNaN(tom)) {
        var t = new Date(); t.setDate(t.getDate() + 1); t.setHours(tom, 0, 0, 0);
        setSelectedDate(t);
      }
    });
  });

  function presetTomorrow() { var d = new Date(); d.setDate(d.getDate()+1); d.setHours(8,0,0,0); return d; }
  function presetNextMonday() {
    var d = new Date(); var day = d.getDay();
    var add = (1 - day + 7) % 7; if (add === 0) add = 7;
    d.setDate(d.getDate() + add); d.setHours(8,0,0,0); return d;
  }
  function refreshPresetLabels() {
    var t = presetTomorrow();
    var m = presetNextMonday();
    if (schedTomorrowEl) schedTomorrowEl.textContent = t.getDate()+' '+MONTHS_ES[t.getMonth()]+' · '+pad2(t.getHours())+':'+pad2(t.getMinutes());
    if (schedMondayEl) schedMondayEl.textContent = m.getDate()+' '+MONTHS_ES[m.getMonth()]+' · '+pad2(m.getHours())+':'+pad2(m.getMinutes());
  }
  function positionPopover() {
    if (!schedulePopover || !btnSendArrow) return;
    var rect = btnSendArrow.getBoundingClientRect();
    schedulePopover.style.bottom = (window.innerHeight - rect.top + 12) + 'px';
    schedulePopover.style.right  = (window.innerWidth - rect.right) + 'px';
    schedulePopover.style.left = 'auto'; schedulePopover.style.top = 'auto';
  }
  function setSchedulePopover(open) {
    if (!schedulePopover || !sendWrap) return;
    if (open) { refreshPresetLabels(); positionPopover(); }
    schedulePopover.classList.toggle('open', open);
    sendWrap.classList.toggle('menu-open', open);
    schedulePopover.setAttribute('aria-hidden', open ? 'false' : 'true');
  }
  if (btnSendArrow) {
    btnSendArrow.addEventListener('click', function (e) {
      e.stopPropagation();
      setSchedulePopover(!schedulePopover.classList.contains('open'));
    });
  }
  document.addEventListener('click', function (e) {
    if (!schedulePopover || !schedulePopover.classList.contains('open')) return;
    if (sendWrap && !sendWrap.contains(e.target) && !schedulePopover.contains(e.target)) setSchedulePopover(false);
  });
  window.addEventListener('resize', function () {
    if (schedulePopover && schedulePopover.classList.contains('open')) positionPopover();
  });

  function applySchedule(date) {
    if (!date || !inputScheduled || !schedBanner) return;
    inputScheduled.value = isoLocal(date);
    var labelText = date.getDate()+' '+MONTHS_ES[date.getMonth()]+' · '+pad2(date.getHours())+':'+pad2(date.getMinutes());
    if (schedLabel) schedLabel.textContent = labelText;
    schedBanner.hidden = false;
    if (sendText) sendText.textContent = 'Programar';
    saveState();
  }
  function clearSchedule() {
    if (!inputScheduled || !schedBanner) return;
    inputScheduled.value = '';
    schedBanner.hidden = true;
    if (sendText) sendText.textContent = 'Enviar';
    saveState();
  }
  if (btnSchedClear) btnSchedClear.addEventListener('click', clearSchedule);
  if (schedulePopover) {
    schedulePopover.addEventListener('click', function (e) {
      var btn = e.target.closest('.schedule-item');
      if (!btn) return;
      var preset = btn.dataset.preset;
      setSchedulePopover(false);
      if (preset === 'tomorrow') applySchedule(presetTomorrow());
      else if (preset === 'monday') applySchedule(presetNextMonday());
      else if (preset === 'custom') openCustomScheduler();
    });
  }
  function openCustomScheduler() {
    if (!customOverlay) return;
    customError.hidden = true; customError.textContent = '';
    var initial = new Date(Date.now() + 30 * 60 * 1000); initial.setSeconds(0,0);
    setSelectedDate(initial);
    customOverlay.classList.add('open');
    customOverlay.setAttribute('aria-hidden', 'false');
  }
  function closeCustomScheduler() {
    if (!customOverlay) return;
    customOverlay.classList.remove('open');
    customOverlay.setAttribute('aria-hidden', 'true');
  }
  if (btnCustomClose)  btnCustomClose.addEventListener('click', closeCustomScheduler);
  if (btnCustomCancel) btnCustomCancel.addEventListener('click', closeCustomScheduler);
  if (customOverlay) {
    customOverlay.addEventListener('click', function (e) { if (e.target === customOverlay) closeCustomScheduler(); });
  }
  if (btnCustomConfirm) {
    btnCustomConfirm.addEventListener('click', function () {
      if (!sched.selected) return;
      var now = Date.now();
      var t = sched.selected.getTime();
      /* Mismo criterio que updateSummary: validamos contra el inicio
         del próximo minuto (segundos zeroed) en vez de now+60s. */
      var minAllowed = now - (now % 60000) + 60000;
      if (t < minAllowed) {
        customError.textContent = 'La hora ya pasó. Elige al menos 1 minuto en el futuro.';
        customError.hidden = false; return;
      }
      if (t > now + 72 * 60 * 60 * 1000) {
        customError.textContent = 'No se puede programar más de 72 horas en el futuro.';
        customError.hidden = false; return;
      }
      applySchedule(sched.selected);
      closeCustomScheduler();
    });
  }

  // ══════════════════════════════════════════════════════════════════
  //  CHIPS DE DESTINATARIOS + AUTOCOMPLETADO
  // ══════════════════════════════════════════════════════════════════
  var EMAIL_RX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

  function escText(s) {
    return String(s || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // El hidden input `inputTo` refleja siempre: chips + lo que el usuario
  // está tecleando ahora. Así el código existente que lee `inputTo.value`
  // (saveState, saveDraftRemote, form submit) sigue funcionando.
  function syncHiddenTo() {
    var typed = (inputToTyping.value || '').trim().replace(/[,;]+$/, '');
    var emails = recipients.map(function (r) { return r.email; });
    if (typed) emails.push(typed);
    inputTo.value = emails.join(', ');
  }

  function renderChips() {
    if (!chipsBox) return;
    var old = chipsBox.querySelectorAll('.compose-chip');
    for (var i = 0; i < old.length; i++) old[i].remove();
    recipients.forEach(function (r, idx) {
      var valid = EMAIL_RX.test(r.email);
      var chip = document.createElement('span');
      chip.className = 'compose-chip' + (valid ? '' : ' invalid');
      chip.title = (r.label ? (r.label + ' <' + r.email + '>') : r.email)
                 + (valid ? '' : ' — formato inválido');
      chip.innerHTML =
        '<span class="compose-chip-text">' + escText(r.label || r.email) + '</span>'
        + '<button type="button" class="compose-chip-x" aria-label="Quitar destinatario">×</button>';
      chip.querySelector('.compose-chip-x').addEventListener('click', function (e) {
        e.stopPropagation();
        recipients.splice(idx, 1);
        renderChips();
        syncHiddenTo();
        saveState();
        inputToTyping.focus();
      });
      chipsBox.insertBefore(chip, inputToTyping);
    });
  }

  function addRecipient(email, label) {
    email = (email || '').trim().toLowerCase();
    if (!email) return false;
    if (recipients.some(function (r) { return r.email === email; })) return false;
    recipients.push({ email: email, label: label || '' });
    renderChips();
    return true;
  }

  function commitTyped() {
    var typed = (inputToTyping.value || '').trim().replace(/[,;]+$/, '');
    inputToTyping.value = '';
    if (!typed) { syncHiddenTo(); return false; }
    var ok = addRecipient(typed, '');
    syncHiddenTo();
    saveState();
    return ok;
  }

  // Llamado desde openCompose / openDraft / restoreState para reconstruir
  // los chips a partir de un string coma-separado.
  function setToValue(str) {
    recipients = [];
    if (inputToTyping) inputToTyping.value = '';
    if (str) {
      String(str).split(/[,;\s]+/).forEach(function (p) {
        p = p.trim();
        if (p) recipients.push({ email: p.toLowerCase(), label: '' });
      });
    }
    renderChips();
    syncHiddenTo();
  }

  // Expuesto para flujos externos (botón "Responder" del inbox, openSent):
  // recibe un string con uno o varios correos y los pinta como chips.
  window.composeSetRecipients = setToValue;

  // ── Dropdown de sugerencias (autocompletado) ──
  var suggestTimer = null;
  var suggestCache = {};   // query → results (cache simple)

  function fetchSuggestions(q) {
    clearTimeout(suggestTimer);
    suggestTimer = setTimeout(function () {
      var key = q.toLowerCase();
      if (suggestCache[key]) { applySuggestions(suggestCache[key]); return; }
      fetch('/contactos/?q=' + encodeURIComponent(q), {
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var results = (data && data.results) || [];
        suggestCache[key] = results;
        applySuggestions(results);
      })
      .catch(function () { hideSuggestions(); });
    }, 120);
  }

  function applySuggestions(results) {
    var taken = recipients.map(function (r) { return r.email; });
    suggestItems = results.filter(function (c) {
      return taken.indexOf(c.email) === -1;
    });
    suggestActive = suggestItems.length ? 0 : -1;
    renderSuggestions();
  }

  function renderSuggestions() {
    if (!suggestBox) return;
    if (!suggestItems.length) {
      suggestBox.hidden = true;
      suggestBox.innerHTML = '';
      return;
    }
    suggestBox.innerHTML = suggestItems.map(function (it, i) {
      var disp = it.label || it.email;
      var letter = (disp || '?').charAt(0).toUpperCase();
      var nameRow = it.label
        ? ('<span class="compose-suggestion-name">' + escText(it.label) + '</span>'
           + '<span class="compose-suggestion-email">' + escText(it.email) + '</span>')
        : ('<span class="compose-suggestion-name">' + escText(it.email) + '</span>');
      return '<div class="compose-suggestion'
           + (i === suggestActive ? ' active' : '')
           + '" data-i="' + i + '">'
           + '<span class="compose-suggestion-avatar">' + escText(letter) + '</span>'
           + '<span class="compose-suggestion-text">' + nameRow + '</span>'
           + '</div>';
    }).join('');
    suggestBox.hidden = false;
    Array.prototype.forEach.call(
      suggestBox.querySelectorAll('.compose-suggestion'),
      function (el) {
        el.addEventListener('mousedown', function (e) {
          e.preventDefault();   // evita que el blur del input cierre el dropdown
          pickSuggestion(parseInt(el.dataset.i, 10));
        });
        el.addEventListener('mouseenter', function () {
          suggestActive = parseInt(el.dataset.i, 10);
          var nodes = suggestBox.querySelectorAll('.compose-suggestion');
          for (var j = 0; j < nodes.length; j++) {
            nodes[j].classList.toggle('active', j === suggestActive);
          }
        });
      }
    );
  }

  function pickSuggestion(i) {
    var it = suggestItems[i];
    if (!it) return;
    inputToTyping.value = '';
    addRecipient(it.email, it.label);
    syncHiddenTo();
    saveState();
    hideSuggestions();
    inputToTyping.focus();
  }

  function hideSuggestions() {
    if (!suggestBox) return;
    suggestBox.hidden = true;
    suggestItems = []; suggestActive = -1;
  }

  // ── Eventos del input de tipeo ──
  if (inputToTyping) {
    inputToTyping.addEventListener('input', function () {
      syncHiddenTo();
      saveState();
      var v = (inputToTyping.value || '').trim();
      if (!v) { hideSuggestions(); return; }
      fetchSuggestions(v);
    });

    inputToTyping.addEventListener('keydown', function (e) {
      // Navegación del dropdown
      if (suggestBox && !suggestBox.hidden && suggestItems.length) {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          suggestActive = (suggestActive + 1) % suggestItems.length;
          renderSuggestions();
          return;
        }
        if (e.key === 'ArrowUp') {
          e.preventDefault();
          suggestActive = (suggestActive - 1 + suggestItems.length) % suggestItems.length;
          renderSuggestions();
          return;
        }
        if (e.key === 'Enter' && suggestActive >= 0) {
          e.preventDefault();
          pickSuggestion(suggestActive);
          return;
        }
        if (e.key === 'Escape') { e.preventDefault(); hideSuggestions(); return; }
      }
      // Confirmar chip con Enter / Tab / coma / punto y coma / espacio
      // (espacio solo si hay '@' — evita convertir palabras en chip)
      var isSpace = e.key === ' ' || e.key === 'Spacebar';
      var typedNow = (inputToTyping.value || '').trim();
      if (e.key === 'Enter' || e.key === 'Tab' || e.key === ',' || e.key === ';'
          || (isSpace && typedNow.indexOf('@') >= 0)) {
        if (typedNow) {
          e.preventDefault();
          commitTyped();
          hideSuggestions();
        }
        return;
      }
      // Backspace en input vacío → quita el último chip
      if (e.key === 'Backspace' && !inputToTyping.value && recipients.length) {
        recipients.pop();
        renderChips();
        syncHiddenTo();
        saveState();
        return;
      }
    });

    inputToTyping.addEventListener('blur', function () {
      // Pequeño delay para que el mousedown del dropdown registre primero
      setTimeout(function () {
        if ((inputToTyping.value || '').trim()) commitTyped();
        hideSuggestions();
      }, 150);
    });

    inputToTyping.addEventListener('paste', function (e) {
      var text = (e.clipboardData || window.clipboardData).getData('text/plain') || '';
      if (/[,;\s\n]/.test(text)) {
        e.preventDefault();
        text.split(/[,;\s\n]+/).forEach(function (p) {
          p = p.trim();
          if (p) addRecipient(p, '');
        });
        inputToTyping.value = '';
        syncHiddenTo();
        saveState();
        hideSuggestions();
      }
    });
  }

  // Click en el contenedor de chips (no en un chip) enfoca el input tipeo
  if (chipsBox) {
    chipsBox.addEventListener('click', function (e) {
      if (e.target === chipsBox) inputToTyping.focus();
    });
  }

  // ── Helpers de borrador ────────────────────────────────────────
  // Un borrador se guarda SOLO si hay al menos un destinatario válido en
  // "Para" Y texto real en el cuerpo. Asunto solo o cuerpo solo NO bastan
  // — evita borradores fantasma al abrir y cerrar el compose sin escribir.
  function hasDraftContent() {
    var to   = (inputTo.value   || '').trim();
    var text = (editor.innerText || '').trim();
    return !!(to && text);
  }

  // Guarda (o actualiza) el borrador de forma síncrona. Usa
  // navigator.sendBeacon si está disponible para que también funcione
  // cuando el usuario cierra la pestaña/recarga la página.
  function saveDraftRemote(opts) {
    if (!hasDraftContent()) return Promise.resolve(null);
    var fd = new FormData();
    if (currentDraftId)   fd.append('draft_id',     currentDraftId);
    if (currentAliasId)   fd.append('alias_id',     currentAliasId);
    fd.append('to',           inputTo.value || '');
    fd.append('subject',      inputSubj.value || '');
    fd.append('message_html', editor.innerHTML || '');
    if (inputScheduled && inputScheduled.value) fd.append('scheduled_at', inputScheduled.value);
    fd.append('csrfmiddlewaretoken', getCsrf());

    if (opts && opts.beacon && navigator.sendBeacon) {
      navigator.sendBeacon('/borradores/guardar/', fd);
      return Promise.resolve(null);
    }

    return fetch('/borradores/guardar/', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.ok && data.draft_id) currentDraftId = data.draft_id;
      return data;
    })
    .catch(function () { return null; });
  }

  function deleteDraftRemote() {
    if (!currentDraftId) return Promise.resolve(null);
    var id = currentDraftId;
    currentDraftId = null;
    /* hard=1 → borrado permanente. Se llama al enviar exitosamente
       (el correo ya partió, no tiene sentido conservar el borrador
       en la papelera durante 30 días). */
    var fd = new FormData();
    fd.append('hard', '1');
    fd.append('csrfmiddlewaretoken', getCsrf());
    return fetch('/borradores/' + id + '/eliminar/', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    }).catch(function () { return null; });
  }

  // ── Apertura / cierre / minimizar ──
  window.openCompose = function (aliasId, address, label, opts) {
    currentAliasId    = aliasId;
    currentAliasAddr  = address;
    currentAliasLabel = label || '';
    /* Si abrimos para reanudar un borrador (opts.draftId), arrastramos
       el id para que las próximas guardas/edición vayan al MISMO registro
       y no se dupliquen. Si se omite, empieza un borrador nuevo. */
    currentDraftId    = (opts && opts.draftId) ? opts.draftId : null;
    var readonly     = !!(opts && opts.readonly);
    fromAddr.textContent = address;
    fromAddr.title       = label ? (label + ' · ' + address) : address;
    setToValue(''); inputSubj.value = '';
    editor.innerHTML = defaultBody();
    attachedFiles = []; attachedTotalBytes = 0;
    renderAttachments();
    clearSchedule();
    setSchedulePopover(false);
    setMinimized(false);
    clearErrors();
    hideSuggestions();
    btnSend.classList.remove('loading');
    btnSend.disabled = false;

    /* ── Modo solo-lectura ──
       Marcamos la ventana, ponemos los inputs en readOnly y el editor
       no editable, y cambiamos el título a "Correo enviado".
       Al abrir un correo enviado desde /enviados/ no debe permitirse
       editar ni reenviar — solo verlo. */
    if (readonly) {
      win.classList.add('readonly');
      if (inputToTyping) inputToTyping.readOnly = true;
      inputSubj.readOnly     = true;
      editor.contentEditable = 'false';
      editor.setAttribute('aria-readonly', 'true');
      var titleEl = document.getElementById('composeTitle');
      if (titleEl) titleEl.textContent = 'Correo enviado';
    } else {
      win.classList.remove('readonly');
      if (inputToTyping) inputToTyping.readOnly = false;
      inputSubj.readOnly     = false;
      editor.contentEditable = 'true';
      editor.removeAttribute('aria-readonly');
      var titleEl2 = document.getElementById('composeTitle');
      if (titleEl2) titleEl2.textContent = 'Nuevo mensaje';
    }

    overlay.classList.add('open'); overlay.setAttribute('aria-hidden','false');
    win.classList.add('open'); win.setAttribute('aria-hidden','false');
    if (!readonly) {
      setTimeout(function () { (inputToTyping || inputTo).focus(); }, 200);
    }
    saveState();
  };

  /* Abre el compose ya cargado con un borrador existente. Llamado desde
     /borradores/ al hacer click en un row. Hace fetch al backend para
     traer los campos y luego rellena el editor sobre el modal abierto. */
  window.openDraft = function (draftId) {
    if (!draftId) return;
    fetch('/borradores/' + draftId + '/', {
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data || !data.ok) {
        if (window.showToast) {
          window.showToast({
            type: 'danger',
            title: 'Borrador no encontrado',
            message: 'Recarga la página e inténtalo de nuevo.',
            duration: 4000,
          });
        }
        return;
      }
      var d = data.draft;
      /* Si el borrador tiene alias asociado y sigue activo, lo usamos.
         Si el alias fue destruido o nunca se eligió, mostramos un toast
         para que el usuario sepa que tiene que reseleccionar — abrimos el
         compose vacío para que escoja desde la lista. */
      if (!d.alias_id || !d.alias_active) {
        if (window.showToast) {
          window.showToast({
            type: 'warning',
            title: 'Alias no disponible',
            message: 'El alias original ya no está activo. Elige uno nuevo desde "Nuevo correo".',
            duration: 5000,
          });
        }
        return;
      }
      window.openCompose(d.alias_id, d.alias_address, d.alias_label, { draftId: d.id });
      /* Rellena los campos después de abrir (openCompose los reseteó). */
      setToValue(d.to || '');
      inputSubj.value = d.subject || '';
      if (d.body_html) editor.innerHTML = d.body_html;
      currentDraftId = d.id;
    });
  };

  function closeCompose() {
    /* Si el modal estaba en modo solo-lectura (viendo un correo enviado),
       cerramos sin guardar nada como borrador — el usuario solo estaba
       viendo, no escribiendo. También limpiamos la clase para que la
       próxima apertura del compose sea editable normalmente. */
    var wasReadonly = win.classList.contains('readonly');
    if (wasReadonly) {
      win.classList.remove('readonly');
      if (inputToTyping) inputToTyping.readOnly = false;
      inputSubj.readOnly     = false;
      editor.contentEditable = 'true';
      editor.removeAttribute('aria-readonly');
      var titleEl3 = document.getElementById('composeTitle');
      if (titleEl3) titleEl3.textContent = 'Nuevo mensaje';
      /* Limpiar los chips de adjuntos visuales que pintó openSent — si no,
         la próxima vez que abras "Nuevo correo" aparecerían arrastrados. */
      if (attachList) attachList.innerHTML = '';
      overlay.classList.remove('open'); overlay.setAttribute('aria-hidden','true');
      win.classList.remove('open'); win.setAttribute('aria-hidden','true');
      currentAliasId = null;
      currentDraftId = null;
      clearState();
      return;
    }

    /* Antes de cerrar, si hay contenido y no se envió, lo guardamos como
       borrador (estilo Gmail: la X conserva el correo en Borradores). */
    var willSaveDraft = hasDraftContent();
    /* Si el usuario ya está en /borradores/, no tiene sentido mostrar el
       toast "Lo encuentras en la sección Borradores" — está ahí mismo.
       Refrescamos la lista para que el borrador aparezca/se actualice. */
    var onDraftsPage = window.location.pathname.replace(/\/+$/, '') === '/borradores';
    if (willSaveDraft) {
      saveDraftRemote().then(function () {
        if (onDraftsPage) {
          /* Refresh silencioso para que el nuevo borrador se vea en la lista */
          window.location.reload();
          return;
        }
        if (window.showToast) {
          window.showToast({
            type:     'warning',
            title:    'Guardado en Borradores',
            message:  'Tu correo no se envió — podrás continuarlo cuando quieras desde la sección Borradores.',
            href:     '/borradores/',
            duration: 4500,
          });
        }
      });
    }
    overlay.classList.remove('open'); overlay.setAttribute('aria-hidden','true');
    win.classList.remove('open'); win.setAttribute('aria-hidden','true');
    currentAliasId = null;
    currentDraftId = null;
    clearState();
  }
  // Recordamos si estaba ampliado al minimizar para poder restaurarlo
  // exactamente al estado anterior cuando se vuelve a abrir.
  var wasMaximizedBeforeMinimize = false;
  function setMinimized(min) {
    if (min) {
      // Si estaba en modo ampliado, recordamos para restaurarlo después
      // y QUITAMOS la clase maximized — si no, el chip minimizado heredaría
      // el alto del viewport y se vería como una caja vertical vacía.
      wasMaximizedBeforeMinimize = win.classList.contains('maximized');
      win.classList.remove('maximized');
      win.classList.add('minimized');
      win.setAttribute('aria-expanded','false');
      // CLAVE: al minimizar, quitamos el overlay (oscuro + blur) para que
      // el usuario pueda seguir navegando y haciendo click en la web con
      // total normalidad. La ventana minimizada queda flotando abajo a
      // la derecha como un widget independiente, sin bloquear nada.
      overlay.classList.remove('open');
      overlay.setAttribute('aria-hidden','true');
      btnMinimize.title = 'Restaurar';
      btnMinimize.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="18 15 12 9 6 15"/></svg>';
    } else {
      win.classList.remove('minimized');
      // Si estaba ampliado antes de minimizar, restauramos ese modo.
      if (wasMaximizedBeforeMinimize) {
        win.classList.add('maximized');
        wasMaximizedBeforeMinimize = false;
      }
      win.setAttribute('aria-expanded','true');
      // Al restaurar (solo si la ventana sigue abierta), regresa el overlay.
      if (win.classList.contains('open')) {
        overlay.classList.add('open');
        overlay.setAttribute('aria-hidden','false');
      }
      btnMinimize.title = 'Minimizar';
      btnMinimize.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>';
    }
    saveState();
  }

  btnClose.addEventListener('click', function (e) { e.stopPropagation(); closeCompose(); });
  // Click en el overlay (zona borrosa a los lados): MINIMIZA en lugar de
  // cerrar. Cerrar borraría todo el contenido del correo (destinatario,
  // texto, asunto, programación, ...) — minimizar es la acción no destructiva
  // y consistente con Gmail/Proton. Para cerrar definitivamente está la X.
  overlay.addEventListener('click', function () {
    if (!win.classList.contains('open')) return;
    if (win.classList.contains('minimized')) return;
    setMinimized(true);
  });
  btnMinimize.addEventListener('click', function (e) {
    e.stopPropagation();
    setMinimized(!win.classList.contains('minimized'));
  });
  // Botón "Ampliar" (↗): toggle del modo horizontal/ampliado.
  // - Si está minimizado → restaura Y aplica el modo ampliado.
  // - Si está en tamaño normal → cambia a ampliado.
  // - Si ya está ampliado → vuelve al tamaño normal.
  var btnExpand = document.getElementById('composeExpand');
  if (btnExpand) {
    btnExpand.addEventListener('click', function (e) {
      e.stopPropagation();
      if (win.classList.contains('minimized')) {
        // Restaurar saliendo del modo minimizado y entrar a ampliado
        win.classList.remove('minimized');
        win.setAttribute('aria-expanded', 'true');
        if (win.classList.contains('open')) {
          overlay.classList.add('open');
          overlay.setAttribute('aria-hidden', 'false');
        }
        btnMinimize.title = 'Minimizar';
        btnMinimize.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>';
        win.classList.add('maximized');
      } else {
        // Toggle del modo ampliado
        win.classList.toggle('maximized');
      }
      saveState();
    });
  }
  var composeHead = win.querySelector('.compose-head');
  if (composeHead) {
    composeHead.addEventListener('click', function (e) {
      if (!win.classList.contains('minimized')) return;
      if (e.target.closest('.compose-head-btn')) return;
      // Click en cabecera → restaurar al tamaño NORMAL (sin ampliar).
      // Solo el botón ↗ activa el modo ampliado.
      win.classList.remove('maximized');
      setMinimized(false);
    });
  }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && win.classList.contains('open')) {
      if (win.classList.contains('minimized')) setMinimized(false);
      else closeCompose();
    }
  });

  // ── Submit ──
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!currentAliasId) return;
    clearErrors();
    btnSend.classList.add('loading'); btnSend.disabled = true;
    var fd = new FormData();
    fd.append('to', inputTo.value);
    fd.append('subject', inputSubj.value);
    fd.append('message_html', editor.innerHTML);
    if (inputScheduled && inputScheduled.value) fd.append('scheduled_at', inputScheduled.value);
    attachedFiles.forEach(function (f) { fd.append('attachments', f); });
    fetch('/alias/' + currentAliasId + '/enviar/', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    })
    .then(function (res) { return res.json().then(function (data) { return { status: res.status, data: data }; }); })
    .then(function (r) {
      btnSend.classList.remove('loading'); btnSend.disabled = false;
      if (r.status === 200 && r.data.ok) {
        if (window.showToast) {
          var sent = r.data.message || 'Tu correo salió de DockerShield.';
          var attN = r.data.attachments_sent || 0;
          if (attN) sent += ' Llevó ' + attN + ' adjunto' + (attN === 1 ? '' : 's') + '.';
          var title = r.data.scheduled
            ? 'Correo programado'
            : 'Correo enviado';
          var extra = r.data.scheduled
            ? ' Se enviará automáticamente en la fecha indicada.'
            : ' Lo guardamos en Enviados — el destinatario lo recibirá en breve.';
          window.showToast({
            type:    'success',
            title:   title,
            message: sent + extra,
            duration: 5500,
          });
        }
        /* Disparar evento global con la metadata del correo recién creado.
           La página de /enviados/ lo escucha para insertar la fila al
           instante sin necesidad de recargar. Cualquier otra página puede
           ignorar el evento (no pasa nada). */
        if (r.data.sent) {
          document.dispatchEvent(new CustomEvent('compose:sent', {
            detail: r.data.sent,
          }));
        }
        /* El correo se envió: si existía un borrador asociado, lo
           descartamos para que no aparezca duplicado en /borradores/.
           Vaciamos los campos antes de cerrar para que closeCompose
           NO crea otro borrador "fantasma" al detectar contenido. */
        deleteDraftRemote();
        setToValue('');
        inputSubj.value = '';
        editor.innerHTML = '';
        closeCompose();
      } else {
        if (r.data && r.data.errors) showErrors(r.data.errors);
        else if (r.data && r.data.error) {
          if (window.showToast) window.showToast({ type:'danger', title:'No se pudo enviar', message: r.data.error, duration: 6000 });
        }
      }
    })
    .catch(function () {
      btnSend.classList.remove('loading'); btnSend.disabled = false;
      if (window.showToast) window.showToast({ type:'danger', title:'Error de red', message:'No pudimos conectar con el servidor. Intenta de nuevo.', duration: 6000 });
    });
  });

  // ── Restaurar estado al cargar la página ──
  // Si el usuario estaba con el compose abierto y navegó a otra página,
  // restauramos todo (alias, texto, asunto, programación, minimizado).
  // No restauramos los adjuntos (se pierden al navegar — es el trade-off
  // de no poder serializar `File` objects en sessionStorage).
  function restoreState() {
    var raw = null;
    try { raw = sessionStorage.getItem(STATE_KEY); } catch (e) {}
    if (!raw) return;
    var s; try { s = JSON.parse(raw); } catch (e) { return; }
    if (!s || !s.aliasId) return;

    currentAliasId    = s.aliasId;
    currentAliasAddr  = s.aliasAddress || '';
    currentAliasLabel = s.aliasLabel || '';
    fromAddr.textContent = currentAliasAddr || '—';
    fromAddr.title       = currentAliasLabel ? (currentAliasLabel + ' · ' + currentAliasAddr) : currentAliasAddr;
    setToValue(s.to || '');
    inputSubj.value   = s.subject || '';
    editor.innerHTML  = s.bodyHtml || defaultBody();
    if (s.scheduledAt) {
      try {
        var d = new Date(s.scheduledAt);
        if (!isNaN(d.getTime())) {
          inputScheduled.value = s.scheduledAt;
          var labelText = d.getDate()+' '+MONTHS_ES[d.getMonth()]+' · '+pad2(d.getHours())+':'+pad2(d.getMinutes());
          if (schedLabel) schedLabel.textContent = labelText;
          schedBanner.hidden = false;
          if (sendText) sendText.textContent = 'Programar';
        }
      } catch (e) {}
    }
    // La ventana siempre se marca como "abierta"; el overlay lo decide
    // setMinimized() según el estado guardado: si estaba minimizado al
    // navegar, NO mostramos el overlay (sin borroso, sin bloquear clicks).
    win.classList.add('open');
    win.setAttribute('aria-hidden','false');
    if (s.maximized && !s.minimized) {
      // Estaba ampliado y NO minimizado → aplicamos maximized directamente.
      win.classList.add('maximized');
      wasMaximizedBeforeMinimize = false;
    } else if (s.maximized && s.minimized) {
      // Estaba minimizado pero con intención de ampliado → guardamos la
      // intención para que al des-minimizar vuelva al modo ampliado.
      win.classList.remove('maximized');
      wasMaximizedBeforeMinimize = true;
    } else {
      win.classList.remove('maximized');
      wasMaximizedBeforeMinimize = false;
    }
    setMinimized(!!s.minimized);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', restoreState);
  } else {
    restoreState();
  }
})();
