/* HOME: a card body that scrolls inside the card, with up/down buttons (wheel and keyboard work natively on the focusable body). Local only. */
(() => {
  'use strict';
  function start(doc) {
    const win = doc.defaultView;
    const reduce = Boolean(win && win.matchMedia && win.matchMedia('(prefers-reduced-motion: reduce)').matches);
    const cards = Array.from(doc.querySelectorAll('[data-scroll-card]'));
    cards.forEach(card => {
      const body = card.querySelector('.scroll-body');
      const ctl = card.querySelector('.scroll-ctl');
      const up = card.querySelector('[data-scroll="up"]');
      const down = card.querySelector('[data-scroll="down"]');
      if (!body || !ctl || !up || !down) return;
      function update() {
        const overflow = body.scrollHeight > body.clientHeight + 1;
        ctl.hidden = !overflow;
        up.disabled = body.scrollTop <= 0;
        down.disabled = body.scrollTop + body.clientHeight >= body.scrollHeight - 1;
      }
      const step = () => Math.max(80, Math.round(body.clientHeight * 0.6));
      const settle = () => { update(); if (win) { win.setTimeout(update, 120); win.setTimeout(update, 500); } };   // smooth scrolling ends later
      up.addEventListener('click', () => { body.scrollBy({top: -step(), behavior: reduce ? 'auto' : 'smooth'}); settle(); });
      down.addEventListener('click', () => { body.scrollBy({top: step(), behavior: reduce ? 'auto' : 'smooth'}); settle(); });
      body.addEventListener('scroll', update, {passive: true});
      body.addEventListener('scrollend', update);
      if (win) win.addEventListener('resize', update);
      update();
    });
    return {count: cards.length};
  }
  if (typeof module === 'object' && module.exports) module.exports = {start};
  if (typeof document === 'object') start(document);
})();
