/* Carries the selected project (?project=) between HOME, REVIEW and DETAIL. Local only: no network, storage or HTML injection. */
(() => {
  'use strict';
  const PROJECT = /^[a-z0-9-]{1,40}$/;
  const CARRY = ['home', 'review', 'details', 'evidence'];
  function projectFrom(search) {
    const value = new URLSearchParams(search || '').get('project');
    return value && PROJECT.test(value) ? value : '';
  }
  function apply(doc, project) {
    doc.querySelectorAll('.global-nav a[data-nav]').forEach(link => {
      if (!link.hasAttribute('data-base')) link.setAttribute('data-base', link.getAttribute('href').split('?')[0]);
      const base = link.getAttribute('data-base');
      link.setAttribute('href', project && CARRY.includes(link.dataset.nav) ? base + '?project=' + project : base);
    });
  }
  function start(doc) {
    const win = doc.defaultView;
    if (!win) return null;
    apply(doc, projectFrom(win.location.search));
    doc.addEventListener('siteproof:project', event => {
      const project = PROJECT.test(String(event.detail || '')) ? String(event.detail) : '';
      apply(doc, project);
      try {
        const params = new URLSearchParams(win.location.search);
        if (project) params.set('project', project); else params.delete('project');
        const query = params.toString();
        win.history.replaceState(null, '', win.location.pathname + (query ? '?' + query : '') + win.location.hash);
      } catch (_) { /* address bar update is optional */ }
    });
    return {apply};
  }
  if (typeof module === 'object' && module.exports) module.exports = {projectFrom, apply, start};
  if (typeof document === 'object') start(document);
})();
