(function () {
  const form = document.getElementById('recoverForm');
  const btn  = document.getElementById('submit-btn');
  if (!form || !btn) return;
  form.addEventListener('submit', function () {
    btn.classList.add('loading');
    btn.disabled = true;
  });
})();
