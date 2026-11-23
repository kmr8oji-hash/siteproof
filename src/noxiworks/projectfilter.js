/* DETAIL / EVIDENCE: collapsible projects, project select, name search. Filters what is already in the page; no network, storage or HTML injection. */
(() => {
  'use strict';
  const normalize = value => String(value || '').normalize('NFKC').toLocaleLowerCase('ja-JP').trim();
  function openAncestors(element) {
    for (let node = element && element.closest('details'); node; node = node.parentElement && node.parentElement.closest('details')) node.open = true;
  }
  function start(doc) {
    const select = doc.getElementById('detail-project');
    const search = doc.getElementById('detail-search');
    const tools = doc.getElementById('detail-tools');
    const count = doc.getElementById('detail-count');
    const empty = doc.getElementById('detail-empty');
    if (!select || !search || !tools || !count || !empty) return null;
    const sections = Array.from(doc.querySelectorAll('[data-detail-section]'));
    const groups = Array.from(doc.querySelectorAll('[data-project-group]'));
    const win = doc.defaultView;
    const wanted = win ? new URLSearchParams(win.location.search).get('project') : '';
    if (wanted && Array.from(select.options).some(o => o.value === wanted)) select.value = wanted;
    const wantedQuery = win ? new URLSearchParams(win.location.search).get('q') : '';
    if (wantedQuery) search.value = wantedQuery.slice(0, 200);
    function render() {
      const project = select.value, query = normalize(search.value);
      const narrowed = Boolean(project) || Boolean(query);
      let visible = 0;
      sections.forEach(section => {
        const show = (!project || section.dataset.site === project) && normalize(section.dataset.search).includes(query);
        section.hidden = !show;
        if (show) visible += 1;
      });
      groups.forEach(group => {
        const items = Array.from(group.querySelectorAll('[data-detail-section]'));
        const shown = items.filter(item => !item.hidden).length;
        group.hidden = shown === 0;
        if (narrowed && shown > 0) group.open = true;   // a search hit or a chosen project is always expanded
        const label = group.querySelector('[data-group-count]');
        if (label) label.textContent = (shown === items.length ? '' : shown + '/') + items.length + 'ページ' + (label.dataset.extra ? ' · ' + label.dataset.extra : '');
      });
      count.textContent = `表示 ${visible} / ${sections.length} ページ`;
      empty.hidden = visible !== 0;
      return {visible};
    }
    function openHash() {
      const id = win ? decodeURIComponent(win.location.hash.slice(1)) : '';
      const target = id ? doc.getElementById(id) : null;
      if (target) { openAncestors(target); if (target.scrollIntoView) target.scrollIntoView(); }
    }
    select.addEventListener('change', () => {
      doc.dispatchEvent(new (win && win.CustomEvent || CustomEvent)('siteproof:project', {detail: select.value}));
      render();
    });
    search.addEventListener('input', render);
    if (win) win.addEventListener('hashchange', openHash);
    render();
    openHash();
    tools.hidden = false;
    return {render};
  }
  if (typeof module === 'object' && module.exports) module.exports = {normalize, start};
  if (typeof document === 'object') start(document);
})();
