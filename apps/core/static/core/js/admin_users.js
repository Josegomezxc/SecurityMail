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
