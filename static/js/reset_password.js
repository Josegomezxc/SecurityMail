function togglePwd(id, btn) {
  const input = document.getElementById(id);
  const open  = input.type === 'password';
  input.type  = open ? 'text' : 'password';
  btn.querySelector('.eye-open').style.display   = open ? 'none' : '';
  btn.querySelector('.eye-closed').style.display = open ? '' : 'none';
}

// Validación visual en vivo de los requisitos
(function () {
  const p1 = document.getElementById('pwd1');
  const p2 = document.getElementById('pwd2');
  const rules = {
    len:    document.getElementById('rule-len'),
    letter: document.getElementById('rule-letter'),
    num:    document.getElementById('rule-num'),
    match:  document.getElementById('rule-match'),
  };
  function check() {
    const v1 = p1.value, v2 = p2.value;
    rules.len.classList.toggle('ok',    v1.length >= 8);
    rules.letter.classList.toggle('ok', /[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/.test(v1));
    rules.num.classList.toggle('ok',    /\d/.test(v1));
    rules.match.classList.toggle('ok',  v1.length > 0 && v1 === v2);
  }
  p1.addEventListener('input', check);
  p2.addEventListener('input', check);
})();
