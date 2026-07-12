document.addEventListener('submit', function (e) {
  var form = e.target.closest('.js-admin-toggle-alias');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();
  if (!window.confirmDialog) { form.submit(); return; }

  var address = form.dataset.address || 'este alias';
  var isActive = form.dataset.active === '1';

  window.confirmDialog({
    danger:      isActive,
    icon:        isActive ? 'warning' : 'question',
    title:       isActive ? 'Desactivar alias' : 'Reactivar alias',
    message:     isActive
      ? 'El alias ' + address + ' dejará de recibir correos. Solo podrás reactivarlo desde aquí. ¿Continuar?'
      : 'El alias ' + address + ' volverá a estar activo y recibirá correos de nuevo. ¿Continuar?',
    confirmText: isActive ? 'Sí, desactivar' : 'Sí, reactivar',
    cancelText:  'Cancelar',
  }).then(function (ok) {
    if (!ok) return;
    form.dataset.confirmed = '1';
    form.submit();
  });
});




function _quotaInputBounds(input) {
  var min = parseInt(input.dataset.min || input.min || '1', 10);
  var max = parseInt(input.dataset.max || input.max || '999', 10);
  return { min: min, max: max };
}

function adjQuota(delta) {
  var input = document.getElementById('newLimitInput');
  if (!input) return;
  var b = _quotaInputBounds(input);
  var v = parseInt(input.value, 10) || b.min;
  input.value = String(Math.max(b.min, Math.min(b.max, v + delta)));
}


function quotaOnlyDigits(e) {

  var ctrl = e.ctrlKey || e.metaKey;
  var allowedKeys = [
    'Backspace', 'Delete', 'Tab', 'Escape', 'Enter',
    'Home', 'End', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown',
  ];
  if (allowedKeys.indexOf(e.key) !== -1) return true;
  if (ctrl && ['a', 'c', 'v', 'x', 'z', 'A', 'C', 'V', 'X', 'Z'].indexOf(e.key) !== -1) return true;
  if (/^[0-9]$/.test(e.key)) return true;
  e.preventDefault();
  return false;
}


function quotaOnPaste(e) {
  e.preventDefault();
  var data = (e.clipboardData || window.clipboardData).getData('text') || '';
  var digits = data.replace(/\D/g, '').slice(0, 3);
  var input = e.target;
  var b = _quotaInputBounds(input);
  var v = parseInt(digits, 10);
  if (!isNaN(v)) input.value = String(Math.max(b.min, Math.min(b.max, v)));
}


document.addEventListener('input', function (e) {
  if (e.target && e.target.id === 'newLimitInput') {

    var cleaned = (e.target.value || '').replace(/\D/g, '').slice(0, 3);
    if (cleaned !== e.target.value) e.target.value = cleaned;

    var b = _quotaInputBounds(e.target);
    var v = parseInt(e.target.value, 10);
    if (!isNaN(v) && v > b.max) e.target.value = String(b.max);
  }
});


document.addEventListener('blur', function (e) {
  if (e.target && e.target.id === 'newLimitInput') {
    var b = _quotaInputBounds(e.target);
    var v = parseInt(e.target.value, 10);
    if (isNaN(v) || v < b.min) e.target.value = String(b.min);
    else if (v > b.max) e.target.value = String(b.max);
  }
}, true);


document.addEventListener('submit', function (e) {
  var form = e.target.closest('.js-toggle-unlimited');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();

  var action = form.dataset.action || 'enable';
  var email  = form.dataset.userEmail || 'este usuario';

  var opts;
  if (action === 'enable') {
    
    opts = {
      danger:      true,
      icon:        'warning',
      title:       '¿Conceder alias ilimitados?',
      message:
        'Estás a punto de darle a ' + email + ' acceso ILIMITADO. ' +
        'Podrá crear todos los alias que quiera sin tope alguno, igual que un administrador. ' +
        'Esto puede saturar tu infraestructura si abusa. ¿Continuar?',
      confirmText: 'Sí, conceder',
      cancelText:  'Cancelar',
    };
  } else {

    opts = {
      danger:      false,
      icon:        'question',
      title:       'Retirar acceso ilimitado',
      message:
        'Vas a quitarle a ' + email + ' el acceso ilimitado. ' +
        'Vuelve a estar sujeto al cupo numérico definido en este panel. ' +
        'Sus alias actuales NO se borran. ¿Continuar?',
      confirmText: 'Sí, retirar',
      cancelText:  'Cancelar',
    };
  }

  if (!window.confirmDialog) {
    if (confirm(opts.title + '\n\n' + opts.message)) {
      form.dataset.confirmed = '1';
      form.submit();
    }
    return;
  }
  window.confirmDialog(opts).then(function (ok) {
    if (!ok) return;
    form.dataset.confirmed = '1';
    form.submit();
  });
});


document.addEventListener('submit', function (e) {
  var form = e.target.closest('form[action*="toggle-staff"]');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();
  if (!window.confirmDialog) { form.dataset.confirmed = '1'; form.submit(); return; }

  var btn = form.querySelector('button');
  var isPromote = !!(btn && btn.textContent.indexOf('Promover') !== -1);
  var email = form.getAttribute('data-user-email') || '';

  window.confirmDialog({
    danger:      true,
    icon:        'warning',
    title:       isPromote ? 'Promover a administrador' : 'Degradar a usuario normal',
    message:     isPromote
      ? '¿Estás seguro de querer promover a ' + email + ' como administrador? Podrá gestionar usuarios, alias y solicitudes.'
      : '¿Estás seguro de querer degradar a ' + email + ' a usuario normal? Perderá todos los privilegios de administrador.',
    confirmText: isPromote ? 'Sí, promover' : 'Sí, degradar',
    cancelText:  'Cancelar',
  }).then(function (ok) {
    if (!ok) return;
    form.dataset.confirmed = '1';
    if (window.dsShowLoader) window.dsShowLoader();
    form.submit();
  });
});
