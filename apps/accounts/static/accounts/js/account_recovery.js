function recSetReason(btn, text) {
  var ta = document.getElementById('reason-input');
  if (!ta) return;
  ta.value = text;
  document.querySelectorAll('.aliasreq-chip').forEach(function (c) { c.classList.remove('active'); });
  btn.classList.add('active');
  var counter = document.getElementById('reasonCount');
  if (counter) counter.textContent = text.length;
}
