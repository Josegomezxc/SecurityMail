/* ════════════════════════════════════════════════════════════════════
   ESCANEO DE ADJUNTOS CON DOCKERSHIELD
   Se carga después de compose_modal.js y usa window.__composeApi
   ════════════════════════════════════════════════════════════════════ */
(function () {
  var MAX_FILES = window.__composeApi ? window.__composeApi.MAX_FILES : 5;
  var MAX_TOTAL_BYTES = window.__composeApi ? window.__composeApi.MAX_TOTAL_BYTES : 25 * 1024 * 1024;

  var scanningFiles = [];
  var scanIdCounter = 0;

  var btnAttach = document.getElementById('composeAttachBtn');
  var attachList = document.getElementById('composeAttachments');
  var editor = document.querySelector('#composeWindow [contenteditable]');

  // ── Input propio (no toca el original de compose_modal.js) ──
  var scannerInput = document.createElement('input');
  scannerInput.type = 'file';
  scannerInput.multiple = true;
  scannerInput.style.display = 'none';
  document.body.appendChild(scannerInput);

  // ── Crear error row dinámicamente ──
  var errAtt = null;
  var errMsg = document.getElementById('composeErrMessage');
  if (errMsg && errMsg.parentNode) {
    errAtt = document.createElement('div');
    errAtt.className = 'compose-error-row';
    errAtt.id = 'composeErrAttachments';
    errMsg.parentNode.insertBefore(errAtt, errMsg.nextSibling);
  }

  // ── Limpiar errAtt al abrir el modal (clearErrors nativo no lo cubre) ──
  var _origOpenCompose = window.openCompose;
  if (_origOpenCompose) {
    window.openCompose = function () {
      if (errAtt) { errAtt.classList.remove('show'); errAtt.textContent = ''; }
      return _origOpenCompose.apply(this, arguments);
    };
  }

  // ── stripBidi ──
  function stripBidi(s) {
    return String(s || '').replace(/[\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g, '');
  }

  // ── Patch confirmDialog para cancelText: '' (oculta botón cancelar) ──
  var _origCd = window.confirmDialog;
  if (_origCd) {
    window.confirmDialog = function (opts) {
      var hideCancel = opts && opts.cancelText === '';
      if (hideCancel) opts.cancelText = '\u00A0';
      var promise = _origCd(opts);
      if (hideCancel) {
        setTimeout(function () {
          var btn = document.getElementById('cd-cancel');
          if (btn) btn.style.display = 'none';
        }, 10);
      }
      return promise;
    };
  }

  function getCsrf() {
    if (window.__composeApi && window.__composeApi.getCsrf) return window.__composeApi.getCsrf();
    var m = document.cookie.match(/csrftoken=([^;]+)/);
    return m ? m[1] : '';
  }

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function nextScanId() { return ++scanIdCounter; }

  function updateSendButton() {
    var btn = window.__composeApi ? window.__composeApi.btnSend : document.getElementById('composeSendBtn');
    if (btn) btn.disabled = scanningFiles.length > 0;
  }

  function renderAttachments() {
    var api = window.__composeApi;
    if (!attachList) return;
    var html = '';
    if (api) {
      html += api.getFiles().map(function (f, i) {
        return '<span class="compose-attachment">'
          + '<svg class="compose-attachment-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>'
          + '<span class="compose-attachment-name" title="' + stripBidi(f.name) + '">' + stripBidi(f.name) + '</span>'
          + '<span class="compose-attachment-size">' + fmtSize(f.size) + '</span>'
          + '<span class="compose-attachment-status">Listo ✓</span>'
          + '<button type="button" class="compose-attachment-remove" data-idx="' + i + '" aria-label="Quitar adjunto"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>'
          + '</span>';
      }).join('');
    }
    html += scanningFiles.map(function (s) {
      return '<span class="compose-attachment scanning">'
        + '<svg class="compose-attachment-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>'
        + '<span class="compose-attachment-name" title="' + stripBidi(s.name) + '">' + stripBidi(s.name) + '</span>'
        + '<span class="compose-attachment-size">' + fmtSize(s.size) + '</span>'
        + '<span class="compose-attachment-spinner"><span class="scan-spinner"></span> Analizando adjunto con DockerShield, espera por favor...</span>'
        + '</span>';
    }).join('');
    attachList.innerHTML = html;
  }

  function scanFile(file) {
    var api = window.__composeApi;
    var currentFiles = api ? api.getFiles() : [];
    if (currentFiles.length + scanningFiles.length >= MAX_FILES) return;
    var totalBytes = api ? api.getTotalBytes() : 0;
    if (totalBytes + file.size > MAX_TOTAL_BYTES) {
      if (window.showToast) window.showToast({ type: 'warning', title: 'Adjunto omitido', message: file.name + ' supera el límite total de 25 MB.', duration: 5000 });
      return;
    }

    var scanId = nextScanId();
    scanningFiles.push({ scanId: scanId, file: file, name: file.name, size: file.size });
    updateSendButton();
    renderAttachments();

    var fd = new FormData();
    fd.append('file', file);
    fetch('/alias/attachment-scan/', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': getCsrf(), 'X-Requested-With': 'XMLHttpRequest' },
      body: fd,
    })
    .then(function (res) { return res.json().then(function (data) { return { status: res.status, data: data }; }); })
    .then(function (r) {
      var idx = -1;
      for (var i = 0; i < scanningFiles.length; i++) {
        if (scanningFiles[i].scanId === scanId) { idx = i; break; }
      }
      if (idx !== -1) scanningFiles.splice(idx, 1);
      updateSendButton();

      if (r.status === 200 && r.data.ok) {
        if (api) api.addFile(file);
        if (errAtt) { errAtt.classList.remove('show'); errAtt.textContent = ''; }
        renderAttachments();
      } else if (r.data && r.data.warning) {
        if (window.showToast) {
          window.showToast({ type: 'warning', title: 'Archivo Sospechoso', message: r.data.error, duration: 6000 });
        }
        if (errAtt) { errAtt.textContent = r.data.error; errAtt.classList.add('show'); }
        renderAttachments();
      } else {
        if (r.data && r.data.blocked) {
          var blockMsg = 'Motivo: Intento de adjuntar archivo malicioso repetidamente.\n'
            + 'Archivo: ' + file.name + '\n'
            + 'Amenaza: ' + (r.data.threat_name || 'desconocido') + '\n'
            + 'Score: ' + (r.data.risk_score || '—') + '\n\n'
            + 'Has intentado adjuntar un archivo malicioso repetidamente. '
            + 'Tu cuenta ha sido bloqueada por seguridad. '
            + 'Contacta al administrador para recuperarla.';
          if (window.showMalwareBlockedModal) {
            window.showMalwareBlockedModal(blockMsg);
          }
          renderAttachments();
          return;
        } else if (r.data && !r.data.sandbox_down && r.data.attempts) {
          var threat = r.data.threat_name || 'desconocido';
          var modalMsg = 'El archivo "' + stripBidi(file.name) + '" contiene malware detectado por DockerShield: '
            + stripBidi(threat) + '.\n\n'
            + 'Si vuelves a intentarlo, tu cuenta será bloqueada permanentemente '
            + 'y deberás contactar al administrador para recuperarla.';
          if (window.confirmDialog) {
            window.confirmDialog({
              danger: true,
              icon: 'trash',
              title: 'Archivo Malicioso Detectado',
              message: modalMsg,
              confirmText: 'Entendido',
              cancelText: '',
            });
          }
          if (errAtt) { errAtt.textContent = 'Archivo bloqueado por seguridad.'; errAtt.classList.add('show'); }
        } else {
          var msg = (r.data && r.data.error) || 'El archivo fue detectado como potencialmente malicioso y no se puede adjuntar.';
          var toastTitle = (r.data && r.data.sandbox_down) ? 'DockerShield No Disponible' : 'Archivo Bloqueado por DockerShield';
          if (window.showToast) {
            window.showToast({ type: 'danger', title: toastTitle, message: msg, duration: 6000 });
          }
          if (errAtt) { errAtt.textContent = msg; errAtt.classList.add('show'); }
        }
        renderAttachments();
      }
    })
    .catch(function (err) {
      console.error('[attachment-scan] fetch error:', err);
      var idx = -1;
      for (var i = 0; i < scanningFiles.length; i++) {
        if (scanningFiles[i].scanId === scanId) { idx = i; break; }
      }
      if (idx !== -1) scanningFiles.splice(idx, 1);
      updateSendButton();
      var msg = 'Error al analizar ' + file.name + ' con DockerShield. Intenta de nuevo.';
      if (window.showToast) window.showToast({ type: 'danger', title: 'Error de análisis', message: msg, duration: 5000 });
      renderAttachments();
    });
  }

  function addFiles(files) {
    Array.from(files).forEach(function (f) { scanFile(f); });
  }

  scannerInput.addEventListener('change', function () {
    if (scannerInput.files && scannerInput.files.length) {
      addFiles(scannerInput.files);
      scannerInput.value = '';
    }
  });

  // ── Interceptar btnAttach en capturing phase (se ejecuta ANTES del original) ──
  if (btnAttach) {
    btnAttach.addEventListener('click', function (e) {
      var api = window.__composeApi;
      var currentFiles = api ? api.getFiles() : [];
      if (currentFiles.length + scanningFiles.length >= MAX_FILES) {
        if (window.showToast) window.showToast({ type: 'warning', title: 'Límite de adjuntos', message: 'Máximo ' + MAX_FILES + ' archivos.', duration: 4000 });
        e.stopPropagation();
        e.stopImmediatePropagation();
        return;
      }
      e.stopPropagation();
      e.stopImmediatePropagation();
      scannerInput.value = '';
      scannerInput.click();
    }, true);
  }

  // ── Drag & drop ──
  if (editor) {
    ['dragover', 'drop'].forEach(function (evt) {
      editor.addEventListener(evt, function (e) { e.preventDefault(); });
    });
    editor.addEventListener('drop', function (e) {
      e.preventDefault();
      var api = window.__composeApi;
      var currentFiles = api ? api.getFiles() : [];
      if (currentFiles.length + scanningFiles.length >= MAX_FILES) {
        if (window.showToast) window.showToast({ type: 'warning', title: 'Límite de adjuntos', message: 'Máximo ' + MAX_FILES + ' archivos.', duration: 4000 });
        return;
      }
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
    });
  }

})();
