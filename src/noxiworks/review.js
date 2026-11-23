/* Read-only local selection, Desktop/Mobile switch, Baseline comparison views and enlarged view. No services, network, HTML injection or writes. */
(() => {
  'use strict';
  const roles = ['baseline', 'current', 'diff'];
  const KINDS = ['changed', 'unchanged', 'pending', 'unknown', 'none', 'ok'];
  // Per tab: the file names of its current / Baseline / diff image. Anything else is dropped.
  const FILES = {desktop: ['current.png', 'baseline.png', 'diff.png'], current: ['current.png', 'baseline.png', 'diff.png'],
    mobile: ['mobile.png', 'mobile_baseline.png', 'mobile_diff.png']};
  const kindOf = (value, fallback) => KINDS.includes(value) ? value : fallback;
  const text = (value, max = 200) => String(value == null ? '' : value).slice(0, max);
  // Screenshot cards for the stage. Every image path must be this page's own file for that tab: anything else is dropped.
  function cardsOf(d, images, ready) {
    const own = (value, file) => value === 'evidence/' + d.id + '/' + file ? value : null;
    if (d.captures === undefined) {  // data saved without capture records: one plain "latest image"
      return images.current ? [{key:'current', label:'最新の撮影画像', status:'SUCCEEDED', image:images.current, size:'', viewport:'',
        captured:text(d.observed), range:'', frame:'desktop', health:'', baseline:images.baseline, diff:images.diff,
        change:ready ? (d.change === 'CHANGED' ? 'changed' : 'unchanged') : 'none', changeLabel:ready ? (d.change === 'CHANGED' ? '変更あり' : '変更なし') : '比較なし'}] : [];
    }
    let parsed = [];
    try { const raw = JSON.parse(d.captures); if (Array.isArray(raw)) parsed = raw; } catch (_) {}
    return parsed.filter(c => c && Object.hasOwn(FILES, c.key)).slice(0, 2).map(c => {
      const [file, baseFile, diffFile] = FILES[c.key];
      const image = c.status === 'SUCCEEDED' ? own(c.image, file) : null;
      const baseline = ready && image ? own(c.baseline, baseFile) : null, diff = ready && image ? own(c.diff, diffFile) : null;
      const compared = Boolean(baseline && diff);
      return {key:c.key, label:c.key === 'mobile' ? 'Mobile' : c.key === 'current' ? '最新の撮影画像' : 'Desktop',
        status:c.status === 'PLANNED' ? 'PLANNED' : image ? 'SUCCEEDED' : 'FAILED', image, size:text(c.size, 20), viewport:text(c.viewport, 20),
        captured:text(c.captured, 40), range:text(c.range, 80), frame:c.key === 'mobile' ? 'mobile' : 'desktop', health:text(c.health, 120),
        baseline:compared ? baseline : null, diff:compared ? diff : null,
        change:compared ? kindOf(c.change, 'unknown') : 'none', changeLabel:compared ? text(c.change_label, 20) || '判定不能' : '比較なし'};
    });
  }
  function planOf(d) {
    let raw = {};
    try { const parsed = JSON.parse(d.plan || '{}'); if (parsed && typeof parsed === 'object') raw = parsed; } catch (_) {}
    const candidates = Array.isArray(raw.candidates) ? raw.candidates.slice(0, 5).map(c => ({label:text(c && c.label, 60), entry:text(c && c.entry, 200), state:text(c && c.state, 60)})) : [];
    return {role:text(raw.role, 30), roleLabel:text(raw.role_label, 30), stateLabel:text(raw.state_label, 60), profiles:text(raw.profiles, 200),
      why:text(raw.why, 400), candidates};
  }
  // Synthetic offline demo of the approved Baseline (comparison panel only). Every path must be this page's own file for that scenario/tab.
  const DEMO_KEYS = ['unchanged', 'changed', 'unstable'], DEMO_LABELS = {unchanged:'変更なし（合成データ）', changed:'変更あり（合成データ）', unknown:'判定不能（UNKNOWN）'};
  function demoOf(d) {
    if (!d.demo) return null;
    let raw = null;
    try { raw = JSON.parse(d.demo); } catch (_) { return null; }
    if (!raw || !Array.isArray(raw.scenarios)) return null;
    const own = (value, file) => value === 'evidence/' + d.id + '/' + file ? value : null;
    const scenarios = raw.scenarios.filter(s => s && DEMO_KEYS.includes(s.key)).slice(0, 3).map(s => {
      const kinds = {};
      for (const [tab, stage] of [['desktop', 'current.png'], ['mobile', 'mobile.png']]) {
        const k = s.kinds && s.kinds[tab]; if (!k) continue;
        const base = own(k.baseline, stage), after = own(k.after, 'demo_' + s.key + '_' + tab + '.png');
        if (!base || !after) continue;
        const change = ['unchanged', 'changed'].includes(k.change) ? k.change : 'unknown';
        kinds[tab] = {baseline:base, after, diff:change === 'unknown' ? null : own(k.diff, 'demo_' + s.key + '_' + tab + '_diff.png'),
          change, label:DEMO_LABELS[change], detail:text(k.detail, 300), caption:text(k.caption, 200) || '比較用の合成データ（実サイトの撮影ではありません）'};
      }
      return {key:s.key, title:text(s.title, 30), kinds};
    });
    return scenarios.length ? {label:text(raw.label, 120), scenarios} : null;
  }
  function selection(d) {
    if (!d || !/^[a-z0-9-]+$/.test(d.id || '') || d.detail !== 'details.html#' + d.id) return null;
    const asset = (value, role) => value === 'evidence/' + d.id + '/' + role + '.png' ? value : null;
    const images = {current: asset(d.current, 'current'), baseline: asset(d.baselineImage, 'baseline'), diff: asset(d.diff, 'diff')};
    const ready = d.baseline === 'approved' && d.verified === 'true' &&
      ['CHANGED', 'UNCHANGED'].includes(d.change) && roles.every(role => images[role]);
    if (!ready) images.baseline = images.diff = null;
    const kind = ready ? (d.change === 'CHANGED' ? 'changed' : 'unchanged') : 'pending';
    let history = [];
    try { const parsed = JSON.parse(d.history || '[]'); if (Array.isArray(parsed)) history = parsed.filter(x => typeof x === 'string').slice(0, 3); } catch (_) {}
    const cards = cardsOf(d, images, ready);
    const taken = cards.filter(c => c.status !== 'PLANNED');
    const compared = d.compared === 'true';
    const changeKind = ['changed', 'unchanged'].includes(kind) ? kind : kindOf(d.changeKind, compared ? 'unknown' : 'none');
    return {id:d.id, project:d.project || '', label:d.label || '', url:text(d.url, 300), detail:d.detail,
      metadata:'evidence/' + d.id + '/details.json', kind, images, cards, compared, plan:planOf(d),
      compareReason:ready ? '' : text(d.compareReason, 300) || '比較結果がありません（比較未実施）。',
      stateLabel:{CHANGED:'変更あり', UNCHANGED:'変更なし'}[d.change] || '未確認',
      captureLabel:d.captureLabel || (taken.length ? '撮影画像あり' : '未撮影'),
      captureKind:kindOf(d.captureKind, taken.length ? 'ok' : 'none'),
      baselineLabel:d.baseline === 'approved' && d.baselineLabel ? text(d.baselineLabel, 40) : {approved:'承認済み', pending:'未承認'}[d.baseline] || '未取得',
      baselineKind:{approved:'ok', pending:'pending'}[d.baseline] || 'none',
      baselineNote:d.baseline === 'pending' ? (d.baselineNote || '') : '',
      compareLabel:compared ? '実施済み' : d.compareLabel === '実サイト：未実施' ? d.compareLabel : '未実施', compareKind:compared ? 'ok' : 'none',
      changeKind,
      changeLabel:kind === 'changed' ? '変更あり' : kind === 'unchanged' ? '変更なし' : compared ? '判定不能（UNKNOWN）' : '判定なし',
      changeNote:(d.split ? text(d.split, 300) + '。' : '') + (kind === 'changed' ? '画像に差があります（不具合の確定ではありません）'
        : kind === 'unchanged' ? '画像の差は検出されませんでした（品質PASSではありません）'
        : compared ? (d.split ? '変更の有無は確定しません' : '比較結果を確定できません') : '画像比較が未実施のため'),
      evidenceLabel:!images.current && !cards.some(c => c.image) ? '画像未取得' : d.verified === 'true' ? '整合確認済み（記録）' : '未検証',
      visualKind:['changed', 'unchanged', 'unknown', 'legacy', 'none'].includes(d.visualKind) ? d.visualKind : 'unknown',
      visualLabel:d.visualLabel || '未取得', visualDetail:d.visualDetail || '', auditLabel:d.auditLabel || '未取得',
      profileLabel:d.profileLabel || '未認証', observed:d.observed || '未取得',
      message:d.message || '比較未確定', caption:d.caption || '保存画像 / 品質UNKNOWN', history, demo:d.baseline === 'approved' ? demoOf(d) : null};
  }
  function boot(doc) {
    const root = doc.getElementById('review-app'); if (!root) return null;
    const choices = Array.from(root.querySelectorAll('[data-review-choice]'));
    const get = id => doc.getElementById(id);
    const put = (id, value) => { const el = get(id); if (el) el.textContent = value; };
    const chip = (id, value, kind) => { const el = get(id); if (el) { el.textContent = value; el.className = 'review-status ' + kind; } };
    const show = (id, visible) => { const el = get(id); if (el) el.hidden = !visible; };
    let current = null, activeKey = null, lastFocus = null, mode = 'side', source = 'real';
    function picture(role, path, alt, caption) {  // one comparison figure: link + image, or its empty note
      const link = get('review-link-' + role), img = get('review-image-' + role);
      if (!link || !img) return;
      link.hidden = !path; show('review-empty-' + role, !path);
      if (path) { link.setAttribute('href', path); img.setAttribute('src', path); img.setAttribute('alt', alt); }
      else { link.removeAttribute('href'); img.removeAttribute('src'); }
      put('review-caption-' + role, path ? caption : '確定した比較画像はありません');
    }
    // ---- Baseline comparison of the shown tab: side by side / overlay slider / diff only ----
    function paintSources(value) {  // 実サイト / オフライン実証 A-B-C. Hidden for a page without a demo.
      const group = get('review-sources'); if (!group) return;
      group.hidden = !value.demo;
      if (!doc.createElement) return;
      while (group.firstChild) group.removeChild(group.firstChild);
      if (!value.demo) return;
      for (const [key, title] of [['real', '実サイトの比較']].concat(value.demo.scenarios.map(s => [s.key, s.title]))) {
        const b = doc.createElement('button');
        b.type = 'button'; b.dataset.source = key; b.textContent = title;
        b.setAttribute('aria-pressed', String(key === source));
        b.addEventListener('click', () => setSource(key));
        group.appendChild(b);
      }
    }
    function setSource(next) {
      source = current && current.demo && current.demo.scenarios.some(s => s.key === next) ? next : 'real';
      const group = get('review-sources');
      if (group && group.children) for (const b of Array.from(group.children)) b.setAttribute('aria-pressed', String(b.dataset.source === source));
      paintStage();
      return source;
    }
    function paintDemo(card) {  // the shown tab's synthetic comparison; false when this tab has none
      const scenario = current.demo && current.demo.scenarios.find(s => s.key === source);
      const k = scenario && scenario.kinds[card && card.key === 'mobile' ? 'mobile' : 'desktop'];
      if (!k) return false;
      put('review-compare-kind', (card ? card.label : 'Desktop') + '・' + scenario.title);
      chip('review-compare-result', k.label, k.change);
      show('review-compare-empty', false); show('review-compare-body', true); show('review-modes', true);
      show('review-demo-note', true); put('review-compare-detail', k.detail); show('review-compare-detail', true);
      const who = current.label + ' / ' + (card ? card.label : '') + ' / ' + scenario.title;
      picture('baseline', k.baseline, who + ' / 承認済みBaseline', '承認済みBaseline（実際の撮影画像）');
      put('review-title-after', '比較用の画像（合成データ）');
      picture('after', k.after, who + ' / 比較用の画像（合成データ）', k.caption);
      picture('diff', k.diff, who + ' / 差分画像', '差分（合成画像との比較）');
      put('review-empty-diff', k.diff ? '' : '判定不能のため、差分画像は表示しません');
      for (const [id, path] of [['review-slider-before', k.baseline], ['review-slider-after', k.after]]) {
        const img = get(id); if (img) img.setAttribute('src', path);
      }
      setMode(mode);
      return true;
    }
    function paintCompare(card) {
      if (source !== 'real' && paintDemo(card)) return;
      show('review-demo-note', false); show('review-compare-detail', false); put('review-empty-diff', '画像未取得・比較未確定');
      put('review-title-after', '今回の撮影');
      const value = current, has = Boolean(card && card.baseline && card.diff);
      put('review-compare-kind', card ? card.label : 'Desktop');
      chip('review-compare-result', card ? card.changeLabel : '比較なし', card ? card.change : 'none');
      put('review-compare-empty', value.compareReason || 'このプロファイルには確定した比較画像がありません（比較未実施）。');
      show('review-compare-empty', !has); show('review-compare-body', has); show('review-modes', has);
      const base = has ? card.baseline : null, after = has ? card.image : null, diff = has ? card.diff : null;
      const who = value.project + ' / ' + value.label + ' / ' + (card ? card.label : '');
      picture('baseline', base, who + ' / 変更前（Baseline）', value.caption);
      picture('after', after, who + ' / 今回の撮影', value.caption);
      picture('diff', diff, who + ' / 差分画像', value.caption);
      for (const [id, path] of [['review-slider-before', base], ['review-slider-after', after]]) {
        const img = get(id); if (img) { if (path) img.setAttribute('src', path); else img.removeAttribute('src'); }
      }
      setMode(mode);
    }
    function setMode(next) {
      mode = ['side', 'slider', 'diff'].includes(next) ? next : 'side';
      const body = get('review-compare-body'); if (body) body.setAttribute('data-mode', mode);
      const modes = get('review-modes');
      if (modes && modes.children) for (const b of Array.from(modes.children)) b.setAttribute('aria-pressed', String(b.dataset.mode === mode));
    }
    function slide(percent) {  // the top (current) layer shows from the left edge up to `percent`
      const top = get('review-slider-top'), p = Math.max(0, Math.min(100, Number(percent) || 0));
      if (top && top.style) top.style.clipPath = 'inset(0 ' + (100 - p) + '% 0 0)';
      return p;
    }
    // ---- screenshot stage: one big image, Desktop / Mobile tabs, enlarged view ----
    function paintStage() {
      const value = current; if (!value) return;
      const card = value.cards.find(c => c.key === activeKey) || value.cards.find(c => c.image) || value.cards[0] || null;
      activeKey = card ? card.key : null;
      const path = card ? card.image : null, link = get('review-link-current'), img = get('review-image-current');
      if (link) link.hidden = !path;
      put('review-empty-current', !card ? '未撮影：このページはまだ撮影されていません'
        : card.status === 'PLANNED' ? '未撮影：この表示サイズはまだ撮影していません' : '撮影に失敗しました（画像はありません）');
      const empty = get('review-empty-current'); if (empty) empty.hidden = Boolean(path);
      if (path) {
        link.setAttribute('href', path); img.setAttribute('src', path);
        img.setAttribute('alt', value.project + ' / ' + value.label + ' / ' + card.label + ' / ' + value.caption);
      } else if (link) { link.removeAttribute('href'); img.removeAttribute('src'); }
      for (const id of ['review-zoom', 'review-original']) { const el = get(id); if (el) el.hidden = !path; }
      const original = get('review-original'); if (original) { if (path) original.setAttribute('href', path); else original.removeAttribute('href'); }
      put('review-caption-current', path ? value.caption + '・元の画像を加工せずに表示しています' : '撮影画像はありません');
      put('review-shot-title', card ? card.label : '');
      put('review-shot-time', card ? card.captured || '未取得' : '未取得');
      show('review-shot-when', Boolean(card) && card.status !== 'PLANNED');
      put('review-shot-size', card && card.size ? '画像 ' + card.size + ' px' : '');
      put('review-shot-range', card ? card.range : '');
      put('review-shot-health', card ? card.health : '');
      const view = get('review-stage-view'); if (view) view.setAttribute('data-frame', card ? card.frame : 'desktop');
      const tabs = get('review-tabs');
      if (tabs && tabs.children) for (const tab of Array.from(tabs.children)) tab.setAttribute('aria-selected', String(Boolean(card) && tab.dataset.key === card.key));
      paintCompare(card);
    }
    function showCard(key) { activeKey = key; paintStage(); }
    function paintTabs(value) {
      const tabs = get('review-tabs'); if (!tabs || !doc.createElement) return;
      while (tabs.firstChild) tabs.removeChild(tabs.firstChild);
      tabs.hidden = value.cards.length === 0;
      value.cards.forEach(card => {
        const tab = doc.createElement('button'), small = doc.createElement('small');
        tab.type = 'button'; tab.className = 'review-tab'; tab.dataset.key = card.key;
        tab.setAttribute('role', 'tab'); tab.setAttribute('id', 'review-tab-' + card.key); tab.setAttribute('aria-controls', 'review-stage-view');
        small.textContent = card.viewport || card.size;
        tab.appendChild(doc.createTextNode(card.label)); tab.appendChild(small);
        tab.addEventListener('click', () => showCard(card.key));
        tab.addEventListener('keydown', event => {
          const i = value.cards.findIndex(c => c.key === card.key), step = {ArrowRight:1, ArrowLeft:-1}[event.key];
          if (!step) return;
          const next = value.cards[(i + step + value.cards.length) % value.cards.length];
          showCard(next.key); const el = get('review-tab-' + next.key); if (el && el.focus) el.focus(); event.preventDefault();
        });
        tabs.appendChild(tab);
      });
    }
    function paintPlan(plan) {
      show('review-plan', Boolean(plan.role));
      put('review-plan-role', plan.roleLabel); put('review-plan-state', plan.stateLabel);
      put('review-plan-profiles', plan.profiles); put('review-plan-why', plan.why);
      const list = get('review-plan-candidate-list');
      show('review-plan-candidates', plan.candidates.length > 0);
      if (!list || !doc.createElement) return;
      while (list.firstChild) list.removeChild(list.firstChild);
      for (const c of plan.candidates) {
        const li = doc.createElement('li'), strong = doc.createElement('strong');
        strong.textContent = c.label;
        li.appendChild(strong); li.appendChild(doc.createTextNode('：' + c.entry + '（' + c.state + '）'));
        list.appendChild(li);
      }
    }
    function select(choice) {
      const value = selection(choice.dataset); if (!value) return false;
      current = value; activeKey = null; source = 'real';
      put('review-project-title', value.project);
      put('review-page-title', value.label);
      put('review-page-url', value.url);
      chip('review-capture', value.captureLabel, value.captureKind);
      chip('review-baseline', value.baselineLabel, value.baselineKind);
      put('review-baseline-note', value.baselineNote);
      chip('review-compare-state', value.compareLabel, value.compareKind);
      chip('review-change', value.changeLabel, value.changeKind);
      put('review-change-note', value.changeNote);
      put('review-evidence', value.evidenceLabel);
      put('review-profile', value.profileLabel);
      chip('review-visual', value.visualLabel, value.visualKind);
      put('review-visual-detail', value.visualDetail);
      put('review-audit', value.auditLabel);
      put('review-observed', value.observed);
      for (const id of ['review-detail', 'review-detail-tech']) { const el = get(id); if (el) el.setAttribute('href', value.detail); }
      const evidencePage = get('review-evidence-page'); if (evidencePage) evidencePage.setAttribute('href', 'evidence.html#' + value.id);
      get('review-metadata').setAttribute('href', value.metadata);
      get('review-selected').setAttribute('data-selected-id', value.id);
      const message = get('review-message');
      message.textContent = value.message;
      message.className = 'review-message' + (value.kind === 'pending' ? ' pending' : '');
      paintPlan(value.plan);
      paintSources(value); paintTabs(value); paintStage();
      for (let i = 0; i < 3; i++) {
        get('review-history-' + i).textContent = value.history[i] || '';
        get('review-history-' + i).hidden = i >= value.history.length;
      }
      get('review-history-empty').hidden = value.history.length > 0;
      for (const a of choices) { if (a === choice) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }
      const folder = choice.closest('[data-review-project]'); if (folder) folder.open = true;
      get('review-selected-message').textContent = '選択中：' + value.project + ' / ' + value.label;
      return true;
    }
    const modes = get('review-modes');
    if (modes && modes.children) for (const b of Array.from(modes.children)) b.addEventListener('click', () => setMode(b.dataset.mode));
    const range = get('review-slider-range');
    if (range) { range.addEventListener('input', () => slide(range.value)); slide(range.value); }
    // ---- enlarged view (natural size, scrolls; "fit" shrinks to the window) ----
    const box = get('review-lightbox'), body = get('review-lightbox-body'), fit = get('review-lightbox-fit'), close = get('review-lightbox-close');
    function openLightbox() {
      const card = current && current.cards.find(c => c.key === activeKey), path = card && card.image;
      if (!path || !box || !body || !doc.createElement) return false;
      while (body.firstChild) body.removeChild(body.firstChild);
      const img = doc.createElement('img');
      img.setAttribute('src', path); img.setAttribute('alt', current.label + ' / ' + card.label + ' / 拡大表示');
      body.appendChild(img); body.className = 'review-lightbox-body';
      if (fit) fit.textContent = '画面に合わせる';
      put('review-lightbox-title', current.label + ' / ' + card.label + (card.size ? '（' + card.size + ' px・原寸）' : ''));
      lastFocus = doc.activeElement || null; box.hidden = false;
      if (doc.body && doc.body.classList) doc.body.classList.add('review-lightbox-open');
      if (close && close.focus) close.focus();
      return true;
    }
    function closeLightbox() {
      if (!box || box.hidden) return false;
      box.hidden = true;
      if (doc.body && doc.body.classList) doc.body.classList.remove('review-lightbox-open');
      if (lastFocus && lastFocus.focus) lastFocus.focus();
      return true;
    }
    function toggleFit() {
      if (!body) return;
      const fitted = body.className.includes('fit');
      body.className = 'review-lightbox-body' + (fitted ? '' : ' fit');
      if (fit) fit.textContent = fitted ? '画面に合わせる' : '原寸（100%）で見る';
    }
    const zoom = get('review-zoom'), shot = get('review-link-current');
    if (zoom) zoom.addEventListener('click', openLightbox);
    if (shot) shot.addEventListener('click', event => {
      if (event.button || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      if (openLightbox()) event.preventDefault();
    });
    if (close) close.addEventListener('click', closeLightbox);
    if (fit) fit.addEventListener('click', toggleFit);
    if (box) box.addEventListener('click', event => { if (event.target === box) closeLightbox(); });
    doc.addEventListener && doc.addEventListener('keydown', event => {
      if (!box || box.hidden) return;
      if (event.key === 'Escape') { closeLightbox(); event.preventDefault(); return; }
      if (event.key === 'Tab') {  // keep focus inside the dialog
        const order = [fit, close, body].filter(Boolean), at = order.indexOf(doc.activeElement);
        const next = order[(at + (event.shiftKey ? -1 : 1) + order.length) % order.length];
        if (next && next.focus) { next.focus(); event.preventDefault(); }
      }
    });
    // Project / name filter over the page list. Selection always stays inside what is shown.
    const projectSelect = get('review-project'), searchBox = get('review-search'), tools = get('review-tools');
    const normalize = value => String(value || '').normalize('NFKC').toLocaleLowerCase('ja-JP').trim();
    function filterList() {
      const project = projectSelect ? projectSelect.value : '', query = searchBox ? normalize(searchBox.value) : '';
      let visible = 0;
      for (const a of choices) {
        const show = (!project || a.dataset.site === project) && normalize(a.dataset.search).includes(query);
        a.hidden = !show; if (show) visible += 1;
      }
      for (const folder of Array.from(root.querySelectorAll('[data-review-project]'))) {
        const any = Array.from(folder.querySelectorAll('[data-review-choice]')).some(a => !a.hidden);
        folder.hidden = !any; if (any && (project || query)) folder.open = true;
      }
      const count = get('review-list-count'), emptyList = get('review-list-empty');
      if (count) count.textContent = '表示 ' + visible + ' / ' + choices.length + ' ページ';
      if (emptyList) emptyList.hidden = visible !== 0;
      const now = choices.find(a => a.getAttribute('aria-current') === 'page');
      if (!now || now.hidden) { const next = choices.find(a => !a.hidden); if (next) select(next); }
      return visible;
    }
    const win = doc.defaultView;
    const wanted = win ? new URLSearchParams(win.location.search).get('project') : '';
    if (projectSelect && wanted && Array.from(projectSelect.options).some(o => o.value === wanted)) projectSelect.value = wanted;
    if (projectSelect) projectSelect.addEventListener('change', () => {
      doc.dispatchEvent(new (win && win.CustomEvent || CustomEvent)('siteproof:project', {detail: projectSelect.value}));
      filterList();
    });
    if (searchBox) searchBox.addEventListener('input', filterList);
    for (const choice of choices) choice.addEventListener('click', event => {
      if (event.button || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      if (select(choice)) event.preventDefault();
    });
    // review.html#<page-id> (links from HOME / ACTIVITY) opens that page; otherwise the page the server marked current.
    const hashed = win && win.location && win.location.hash ? choices.find(a => '#' + a.dataset.id === win.location.hash) : null;
    const first = hashed || choices.find(a => a.getAttribute('aria-current') === 'page') || choices[0];
    if (first) select(first);
    if (projectSelect || searchBox) { filterList(); if (tools) tools.hidden = false; }
    return {select, filterList, showCard, setMode, setSource, slide, openLightbox, closeLightbox, state: () => ({current, activeKey, mode, source})};
  }
  if (typeof module === 'object' && module.exports) module.exports = {selection, boot};
  if (typeof document === 'object') boot(document);
})();
