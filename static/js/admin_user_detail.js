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
