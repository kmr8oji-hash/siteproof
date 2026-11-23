/* Progressive UI only: no monitoring writes, HTML injection, network or dependencies. */
(() => {
  'use strict';
  const STORAGE_KEY = 'siteproof-home-folders-v1';
  const normalize = value => String(value || '').normalize('NFKC').toLocaleLowerCase('ja-JP').trim();
  function matches(row, query, filter) {
    const needsReview = row.changed === 'true' || row.attention === 'true';
    const byFilter = filter === 'changed' ? row.changed === 'true' : filter === 'attention' ? needsReview : filter === 'up' ? row.httpState === 'UP' : true;
    return byFilter && normalize(row.search).includes(normalize(query));
  }
  function start(doc, storage) {
    const viewed = doc.getElementById('viewed-at');
    if (viewed) viewed.textContent = new Date().toLocaleString('ja-JP', {timeZone: 'Asia/Tokyo'});
    const root = doc.getElementById('project-folders');
    const search = doc.getElementById('folder-search');
    const tools = doc.getElementById('folder-tools');
    const count = doc.getElementById('visible-count');
    const empty = doc.getElementById('folder-empty');
    if (!root || !search || !tools || !count || !empty) return null;
    const folders = Array.from(root.querySelectorAll('[data-project]'));
    const buttons = Array.from(tools.querySelectorAll('[data-filter]'));
    const projectSelect = doc.getElementById('project-select');
    const win = doc.defaultView;
    const params = win ? new URLSearchParams(win.location.search) : new URLSearchParams('');
    let project = '';
    const preferences = new Map();
    const expectedOpen = new Map();
    let saved = null;
    let filter = 'all';
    try {
      saved = storage ? JSON.parse(storage.getItem(STORAGE_KEY) || 'null') : null;
    } catch (_) { /* denied or invalid storage leaves native folders usable */ }
    folders.forEach(folder => {
      const id = folder.dataset.project;
      const value = saved && !Array.isArray(saved) && typeof saved === 'object' &&
        Object.prototype.hasOwnProperty.call(saved, id) && typeof saved[id] === 'boolean'
        ? saved[id] : folder.open;
      preferences.set(id, value);
      folder.addEventListener('toggle', () => {
        // Native toggle events are queued/coalesced. Ignore our own final state,
        // rather than relying on a synchronous "rendering" boolean.
        if (folder.open === expectedOpen.get(id)) return;
        expectedOpen.set(id, folder.open);
        if (normalize(search.value) || filter !== 'all') return;
        preferences.set(id, folder.open);
        try {
          if (storage) storage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(preferences)));
        } catch (_) { /* folder operation does not depend on persistence */ }
      });
    });
    // Links from the summary cards and from other screens arrive as ?filter= / ?project= / ?q=.
    if (['all', 'changed', 'attention', 'up'].includes(params.get('filter'))) filter = params.get('filter');
    const wanted = params.get('project');
    if (projectSelect && wanted && Array.from(projectSelect.options).some(o => o.value === wanted)) { project = wanted; projectSelect.value = wanted; }
    if (params.get('q')) search.value = params.get('q').slice(0, 200);
    function render() {
      const narrowed = Boolean(normalize(search.value)) || filter !== 'all' || Boolean(project);
      let visible = 0;
      let total = 0;
      folders.forEach(folder => {
        const rows = Array.from(folder.querySelectorAll('[data-page-id]'));
        let found = 0;
        const inProject = !project || folder.dataset.project === project;
        rows.forEach(row => {
          row.hidden = !(inProject && matches(row.dataset, search.value, filter));
          if (!row.hidden) found += 1;
        });
        total += rows.length;
        visible += found;
        folder.hidden = found === 0;
        const desired = narrowed && found > 0 ? true : preferences.get(folder.dataset.project);
        expectedOpen.set(folder.dataset.project, desired);
        if (folder.open !== desired) folder.open = desired;
        const label = folder.querySelector('[data-page-count]');
        if (label) label.textContent = found === rows.length ? `${rows.length}ページ` : `${found}/${rows.length}ページ`;
      });
      count.textContent = `表示 ${visible} / ${total} ページ`;
      empty.hidden = visible !== 0;
      buttons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.filter === filter)));
      return {visible, total};
    }
    buttons.forEach(button => button.addEventListener('click', () => {
      if (!['all', 'changed', 'attention', 'up'].includes(button.dataset.filter)) return;
      filter = button.dataset.filter;
      render();
    }));
    search.addEventListener('input', render);
    if (projectSelect) projectSelect.addEventListener('change', () => {
      project = projectSelect.value;
      doc.dispatchEvent(new (win && win.CustomEvent || CustomEvent)('siteproof:project', {detail: project}));
      render();
    });
    render();
    tools.hidden = false;
    return {render};
  }
  if (typeof module === 'object' && module.exports) module.exports = {normalize, matches, start, STORAGE_KEY};
  if (typeof document === 'object') {
    let storage = null;
    try { storage = window.localStorage; } catch (_) { /* file origin/storage policy */ }
    start(document, storage);
  }
})();