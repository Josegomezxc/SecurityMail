/* Confirmación bonita antes de desactivar/reactivar un alias del usuario. */
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


/* ════════════════════════════════════════════════════════════════════
   Cupo de alias — botones +/-, solo dígitos en el input, clamp al rango.

   El input es type="text" + inputmode="numeric" (en vez de type="number")
   para tener control TOTAL sobre lo que se puede teclear. Bloqueamos
   letras, "e", "+", "-", ".", y todo lo que no sea 0-9.
   ════════════════════════════════════════════════════════════════════ */

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

/* onkeydown: bloquea cualquier tecla que no sea dígito o tecla de control.
   Devuelve false para cancelar el keypress en navegadores viejos. */
function quotaOnlyDigits(e) {
  /* Permitidas: dígitos 0-9 (top row + numpad), Backspace, Delete, Tab,
     Escape, Enter, Home, End, flechas, copy/cut/paste con Ctrl. */
  var ctrl = e.ctrlKey || e.metaKey;
  var allowedKeys = [
    'Backspace', 'Delete', 'Tab', 'Escape', 'Enter',
    'Home', 'End', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown',
  ];
  if (allowedKeys.indexOf(e.key) !== -1) return true;
  if (ctrl && ['a', 'c', 'v', 'x', 'z', 'A', 'C', 'V', 'X', 'Z'].indexOf(e.key) !== -1) return true;
  /* Solo dígitos */
  if (/^[0-9]$/.test(e.key)) return true;
  e.preventDefault();
  return false;
}

/* onpaste: si el usuario pega texto, dejamos solo los dígitos. */
function quotaOnPaste(e) {
  e.preventDefault();
  var data = (e.clipboardData || window.clipboardData).getData('text') || '';
  var digits = data.replace(/\D/g, '').slice(0, 3);
  var input = e.target;
  var b = _quotaInputBounds(input);
  var v = parseInt(digits, 10);
  if (!isNaN(v)) input.value = String(Math.max(b.min, Math.min(b.max, v)));
}

/* Limpieza final al teclear (defensa adicional) + clamp suave al rango. */
document.addEventListener('input', function (e) {
  if (e.target && e.target.id === 'newLimitInput') {
    /* 1) quita cualquier carácter no dígito que se haya colado */
    var cleaned = (e.target.value || '').replace(/\D/g, '').slice(0, 3);
    if (cleaned !== e.target.value) e.target.value = cleaned;
    /* 2) si supera el max, lo clampeamos. NO clampeamos al min mientras
       teclea porque sería molesto (ej. quieren escribir "10" y al teclear
       "1" les saltaría a "1" sin poder seguir si min=10). El submit del
       backend ya valida y el blur también clampea. */
    var b = _quotaInputBounds(e.target);
    var v = parseInt(e.target.value, 10);
    if (!isNaN(v) && v > b.max) e.target.value = String(b.max);
  }
});

/* Al perder foco, clampeamos al mínimo si quedó vacío o por debajo. */
document.addEventListener('blur', function (e) {
  if (e.target && e.target.id === 'newLimitInput') {
    var b = _quotaInputBounds(e.target);
    var v = parseInt(e.target.value, 10);
    if (isNaN(v) || v < b.min) e.target.value = String(b.min);
    else if (v > b.max) e.target.value = String(b.max);
  }
}, true);


/* ════════════════════════════════════════════════════════════════════
   Toggle "alias ilimitados" — confirmación con confirmDialog antes de
   conceder o retirar el acceso. Reutilizamos el modal global del proyecto.
   ════════════════════════════════════════════════════════════════════ */
document.addEventListener('submit', function (e) {
  var form = e.target.closest('.js-toggle-unlimited');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();

  var action = form.dataset.action || 'enable';
  var email  = form.dataset.userEmail || 'este usuario';

  var opts;
  if (action === 'enable') {
    /* Conceder — advertencia FUERTE (es un permiso elevado). */
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
    /* Revocar — más suave, es la acción "segura". */
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
