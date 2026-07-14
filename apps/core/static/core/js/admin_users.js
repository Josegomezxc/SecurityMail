/* Filtros combinados: búsqueda por texto + filtro por rol */
var currentRoleFilter = 'all';
var currentSearch     = '';

function filterUsers(q) {
  currentSearch = (q || '').toLowerCase().trim();
  applyAllFilters();
}

function setRoleFilter(role, btn) {
  currentRoleFilter = role;
  document.querySelectorAll('.users-filter-btn').forEach(function (b) {
    b.classList.toggle('active', b.dataset.roleFilter === role);
  });
  applyAllFilters();
}

function applyAllFilters() {
  var rows = document.querySelectorAll('#usersTbody tr[data-search]');
  var visible = 0;
  rows.forEach(function (r) {
    var matchSearch = currentSearch === '' || r.dataset.search.indexOf(currentSearch) !== -1;
    var matchRole   = true;
    if      (currentRoleFilter === 'admin')   matchRole = r.dataset.role === 'admin';
    else if (currentRoleFilter === 'user')    matchRole = r.dataset.role === 'user';
    else if (currentRoleFilter === 'threats') matchRole = parseInt(r.dataset.threats || '0', 10) > 0;
    var show = matchSearch && matchRole;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('users-empty').style.display =
    (visible === 0 && rows.length > 0) ? 'block' : 'none';
}

/* Calcula los contadores de cada filtro y los muestra en los pills */
(function () {
  var rows = document.querySelectorAll('#usersTbody tr[data-search]');
  var admins = 0, users = 0, threats = 0;
  rows.forEach(function (r) {
    if (r.dataset.role === 'admin') admins++; else users++;
    if (parseInt(r.dataset.threats || '0', 10) > 0) threats++;
  });
  var $a = document.getElementById('cnt-admins');
  var $u = document.getElementById('cnt-users');
  var $t = document.getElementById('cnt-threats');
  if ($a) $a.textContent = admins;
  if ($u) $u.textContent = users;
  if ($t) $t.textContent = threats;

  /* Listeners de los pills */
  document.querySelectorAll('.users-filter-btn').forEach(function (b) {
    b.addEventListener('click', function () { setRoleFilter(b.dataset.roleFilter, b); });
  });
})();

/* Confirmación con modal danger antes de promover/degradar admin */
document.addEventListener('submit', function (e) {
  var form = e.target.closest('form[action*="toggle-staff"]');
  if (!form || form.dataset.confirmed === '1') return;
  e.preventDefault();
  if (!window.confirmDialog) { form.submit(); return; }

  var btn = form.querySelector('.promote, .demote');
  var isPromote = btn && btn.classList.contains('promote');
  var email = (btn && btn.getAttribute('data-user-email')) || '';

  window.confirmDialog({
    danger:      true,
    icon:        'warning',
    title:       isPromote ? 'Promover a administrador' : 'Degradar a usuario normal',
    message:     isPromote
      ? '¿Estás seguro de querer promover a <strong>' + email + '</strong> como administrador? Podrá gestionar usuarios, alias y solicitudes.'
      : '¿Estás seguro de querer degradar a <strong>' + email + '</strong> a usuario normal? Perderá todos los privilegios de administrador.',
    confirmText: isPromote ? 'Sí, promover' : 'Sí, degradar',
    cancelText:  'Cancelar',
  }).then(function (ok) {
    if (!ok) return;
    form.dataset.confirmed = '1';
    if (window.dsShowLoader) window.dsShowLoader();
    form.submit();
  });
});
