(function () {
  /* Barra de progreso: una sola actualización por frame con rAF.
     Antes: dispara en CADA pixel scrolleado → cientos de updates por segundo. */
  const bar = document.getElementById('readBar');
  let ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () {
      const h = document.documentElement;
      const max = h.scrollHeight - h.clientHeight;
      bar.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + '%';
      ticking = false;
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* Scroll suave al click del TOC */
  const links = document.querySelectorAll('.toc-link');
  links.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const target = document.getElementById(link.dataset.target);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  /* UN SOLO IntersectionObserver para resaltar TOC.
     (Antes: 2 observers — uno para active state, otro para fade-in.) */
  const sections = document.querySelectorAll('.legal-section[id]');
  const obs = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        links.forEach(l => l.classList.toggle('active', l.dataset.target === id));
      }
    });
  }, { rootMargin: '-30% 0px -55% 0px', threshold: 0 });
  sections.forEach(s => obs.observe(s));
})();
