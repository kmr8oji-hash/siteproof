// SiteProof local app: HOME panels (サイトを追加 / 監視中のサイト / 合成デモの検査). Served only by src/noxiworks/app.py (never in the static export).
(function () {
  'use strict';
  var VERDICT = {NO_VISUAL_CHANGE_DETECTED: '変更なし', VISUAL_CHANGED: '変更あり', UNKNOWN: '判定不能'};
  var REASON = {CAPTURE_UNSTABLE: '撮影が安定していません'};
  var SIZES = {Desktop: 'Desktop（1440×900・ページ全体）', Mobile: 'Mobile（390×844・ページ全体）'};
  var OUTCOME_CLASS = {CHANGED: 'is-changed', UNKNOWN: 'is-warn', FAILED: 'is-error', NO_BASELINE: 'is-warn', UNCHANGED: 'is-ok', BASELINE_CREATED: 'is-ok',
                       DISK_FULL: 'is-error', REAL_NOT_READY: 'is-warn'};
  var DISPLAY = {OFFLINE_DEMO: ['オフラインデモ監視中', 'is-on'], REAL_PENDING: ['実サイト監視の準備待ち', 'is-off'], REAL_MONITORING: ['実サイト監視中', 'is-on'],
                 PAUSED: ['一時停止', 'is-off'], FAILED: ['検査失敗', 'is-bad'], SETUP_NEEDED: ['初回セットアップが必要', 'is-off'],
                 SETUP_RUNNING: ['セットアップ中', 'is-off'], EXPIRED: ['監視許可の期限切れ（更新が必要）', 'is-bad']};
  function mb(n) { return (n / 1048576).toLocaleString('ja-JP', {maximumFractionDigits: 1}) + ' MB'; }
  var path = location.pathname;
  // A page of one registered site lives under /site/<site id>/ (its first page) or /site/<site id>/page/<page id>/ (a further page);
  // `rel` is the page's own path inside it ('/' , '/review.html', ...).
  var siteMatch = /^\/site\/(site-[0-9a-f]{8})\/(?:page\/(site-[0-9a-f]{8}-p[2-9])\/)?/.exec(path);
  var siteId = siteMatch ? siteMatch[1] : null;
  var pageId = siteMatch && siteMatch[2] ? siteMatch[2] : null;
  var rel = siteId ? path.slice(('/site/' + siteId + (pageId ? '/page/' + pageId : '')).length) : path;
  var pageSite = siteId;  // the site this page is about (set from the session when the page is the only site's HOME); every action names it
  var pageUnit = pageId || siteId;  // the page of that site (its folder name: the site id for the first page); every action names it too
  var OWN_PAGE = /^\/site\/site-[0-9a-f]{8}\/(?:page\/site-[0-9a-f]{8}-p[2-9]\/)?$/;  // the only addresses this script ever navigates to
  var isDemo = path === '/demo/' || path.indexOf('/demo/') === 0;
  var isHome = ['/', '/index.html', '/demo/', '/demo/index.html'].indexOf(rel) >= 0;

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text != null) node.textContent = text;
    return node;
  }
  function add(parent) { for (var i = 1; i < arguments.length; i++) if (arguments[i]) parent.appendChild(arguments[i]); return parent; }
  function para(cls, text) { return el('p', {'class': cls}, text); }
  function jst(utc) {
    if (!utc) return '—';
    var d = new Date(utc);
    return d.toLocaleString('ja-JP', {timeZone: 'Asia/Tokyo', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'}) + ' JST';
  }

  // The ONE place that reads (GET) from the app; the session and the on-demand 導入環境の確認 both come through it.
  async function read(url) {
    var res = await fetch(url, {headers: {'X-SiteProof-App': '1'}, cache: 'no-store'});
    if (!res.ok) throw new Error(url.split('?')[0].split('/').pop() + ' ' + res.status);
    return res.json();
  }
  async function session() {
    return read('/app/api/session' + (siteId ? '?site=' + siteId + (pageId ? '&page=' + pageId : '') : ''));
  }
  // The ONE place that sends a POST. Every action about a site names that site and its page (the page's own, unless the caller names another one, as the
  // all-sites list does for its own cards), so a stale tab can never act on a different site or page.
  async function post(route, body) {
    var fresh = await session();
    var own = route !== '/app/api/site/register' && pageSite ? {site_id: pageSite, unit: pageUnit} : {};
    var res = await fetch(route, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-SiteProof-App': '1'},
      body: JSON.stringify(Object.assign({token: fresh.token}, own, body))});
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data.result;
  }
  // Run one action from a form: disable it, show progress, reload on success, show the reason on failure.
  // Feedback is always one of three, in the status line next to the button: working, done (only after the SERVER answered success), failed with the
  // server's reason. One request at a time: the controls stay disabled while it runs and after a success (until the reload).
  // go (optional): a function result -> URL to open instead of reloading, or the string 'stay' (show the result, re-enable the controls, no reload).
  function action(form, status, busyText, route, body, doneText, go) {
    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (form.dataset.busy === '1') return;  // a second click / Enter while the first request is open
      form.dataset.busy = '1';
      var controls = form.querySelectorAll('button, select, input');
      var was = Array.prototype.map.call(controls, function (c) { return c.disabled; });
      controls.forEach(function (c) { c.disabled = true; });
      form.setAttribute('aria-busy', 'true');
      status.classList.remove('is-error', 'is-ok'); status.textContent = '⏳ ' + busyText;
      try {
        var result = await post(route, body(event));
        status.classList.add('is-ok');
        var text = typeof doneText === 'function' ? doneText(result) : doneText;
        if (go === 'stay') {
          status.textContent = '✓ ' + text;
          controls.forEach(function (c, i) { c.disabled = was[i]; });
          form.dataset.busy = '0'; form.removeAttribute('aria-busy');
          return;
        }
        var target = typeof go === 'function' ? go(result) : null;
        if (target && OWN_PAGE.test(target)) {  // only ever one of this app's own site pages
          status.textContent = '✓ ' + text + 'そのサイトの画面へ移動します…';
          setTimeout(function () { location.href = target; }, 800);
          return;
        }
        status.textContent = '✓ ' + text + '画面を更新します…';
        setTimeout(function () { location.reload(); }, 800);
      } catch (error) {
        status.classList.add('is-error');
        status.textContent = '✗ 失敗しました：' + error.message;
        controls.forEach(function (c, i) { c.disabled = was[i]; });
        form.dataset.busy = '0'; form.removeAttribute('aria-busy');
      }
    });
  }
  function panel(id, title, tag) {
    var section = el('section', {'class': 'panel app-run-panel', id: id, 'aria-labelledby': id + '-heading'});
    var head = add(el('div', {'class': 'app-run-head'}), el('h2', {id: id + '-heading'}, title));
    if (tag) head.appendChild(el('span', {'class': 'app-run-tag'}, tag));
    section.appendChild(head);
    return section;
  }
  function describe(profiles) {
    return Object.keys(profiles).map(function (kind) {
      var p = profiles[kind];
      if (p.compared === false) return kind + '：撮影済み（比較なし）' + (p.stability && p.stability !== 'STABLE' ? '・撮影が安定していません' : '');
      var reasons = (p.reasons || []).map(function (r) { return REASON[r] || r; });
      // Image comparison and inspection quality apart: "0 px changed" stays visible when the verdict is UNKNOWN (older log lines lack the labels).
      var image = p.image_label || (typeof p.changed_pixels === 'number' ? '画像比較：' + (p.changed_pixels > 0 ? '変更あり（' : '変更なし（') + p.changed_pixels.toLocaleString('ja-JP') + 'px）' : '');
      var quality = qualityText(p.quality_label || (p.verdict === 'UNKNOWN' ? '検査品質：判定不能（' + (reasons.join('／') || '理由不明') + '）' : '検査品質：問題なし'));
      return kind + '：' + (VERDICT[p.verdict] || p.verdict) + (image ? '（' + image + '／' + quality + '）' : (reasons.length ? '・' + reasons.join('・') : ''));
    }).join(' ／ ');
  }

  // ---- 1. no site yet: サイトを追加
  function addSitePanel(state) {
    var known = (state.sites || []).length;
    var p = panel('site-add', 'サイトを追加', known ? '' : '最初にここから');
    if (known && known >= state.max_sites) {
      p.appendChild(para('app-run-note', '登録できるサイトは' + state.max_sites + '個までです。'));
      return p;
    }
    p.appendChild(para('app-run-note', '監視したい自分のWebサイトを登録します。実サイト監視の条件（所有権の確認・監視の許可・撮影環境など）が整うと、SiteProofが自動で初回撮影・Baseline作成・定期撮影・比較を行います。登録するのはサイトの最初のページです（同じサイトのページは、登録後に最大5ページまで追加できます）。サイトは複数登録できます。'));
    p.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: '/demo/'}, '登録せずに合成デモ（固定のサンプル）を見る ›')));
    var open = el('button', {type: 'button', id: 'site-add-open', 'class': 'app-run-button'}, 'サイトを追加');
    var form = el('form', {'class': 'app-site-form', id: 'site-add-form', hidden: ''});
    var name = el('input', {id: 'site-name', type: 'text', maxlength: '60', required: '', autocomplete: 'off', placeholder: '例：マイポートフォリオ'});
    var url = el('input', {id: 'site-url', type: 'url', required: '', autocomplete: 'off', placeholder: 'https://example.com/', inputmode: 'url'});
    add(form, add(el('div', {'class': 'app-field'}), el('label', {'for': 'site-name'}, '1. サイト名'), name),
        add(el('div', {'class': 'app-field'}), el('label', {'for': 'site-url'}, '2. 監視するページのURL（https://）'), url));
    var kinds = add(el('fieldset', {'class': 'app-field'}), el('legend', {}, '3. 撮影する画面サイズ'));
    ['Desktop', 'Mobile'].forEach(function (k) {
      var box = el('input', {type: 'checkbox', id: 'site-kind-' + k, value: k, checked: ''});
      kinds.appendChild(add(el('label', {'class': 'app-check', 'for': 'site-kind-' + k}), box, document.createTextNode(' ' + SIZES[k])));
    });
    form.appendChild(kinds);
    var interval = el('select', {id: 'site-interval-new'});
    [[900, '15分ごと'], [3600, '1時間ごと'], [21600, '6時間ごと'], [86400, '24時間ごと']].forEach(function (o) {
      var opt = el('option', {value: o[0]}, o[1]); if (o[0] === 3600) opt.selected = true; interval.appendChild(opt);
    });
    form.appendChild(add(el('div', {'class': 'app-field'}), el('label', {'for': 'site-interval-new'}, '4. 監視間隔'), interval));
    var confirm = add(el('fieldset', {'class': 'app-field app-confirm'}), el('legend', {}, '5. 登録の前に確認してください'));
    var owner = el('input', {type: 'checkbox', id: 'site-owner'});
    add(confirm,
        add(el('label', {'class': 'app-check', 'for': 'site-owner'}), owner, document.createTextNode(' このサイトは自分が管理しています（他人のサイトは登録しないでください）')),
        para('app-run-note', '所有権の確認：自己申告だけでは実サイトを撮影・検査しません。実サイトの監視には、DNSのTXTレコードによる確認（どのサイトでも可）、またはworkers.devのサイトに限りCloudflareアカウントの管理権限で所有権を確認した記録が必要です（登録後にHOMEで案内します）。'),
        para('app-run-note', '監視の許可：このサイトへの通信はまだ承認されていません。承認されるまで撮影しません（実サイトにアクセスせず、合成画像も作りません）。必要な条件は登録後にHOMEで案内します。'),
        para('app-run-note', '登録すると監視が自動で始まります：すぐに初回検査を行い、安定して撮影できた画像を初期Baseline（比較の基準）として自動作成します。その後は選んだ間隔で検査し、Baselineと比較します。変更を検知してもBaselineは自動で書き換えません。'));
    form.appendChild(confirm);
    form.appendChild(el('button', {type: 'submit', id: 'site-add-submit', 'class': 'app-run-button'}, '登録して監視を始める'));
    var status = el('p', {id: 'site-add-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(p, open, form, status);
    open.addEventListener('click', function () { form.hidden = false; open.hidden = true; name.focus(); });
    action(form, status, '登録しています…', '/app/api/site/register', function () {
      return {name: name.value, url: url.value, owner_confirmed: owner.checked, interval_seconds: +interval.value,
              kinds: ['Desktop', 'Mobile'].filter(function (k) { return document.getElementById('site-kind-' + k).checked; })};
    }, '登録しました。', function (r) { return known && r && r.href ? r.href : null; });  // with other sites already there: open the new one
    return p;
  }

  // ---- 2. the registered site: monitoring status at a glance; auxiliary actions folded away
  // "Runs again" is promised only while that is true: monitoring on AND every real-capture condition (permit period / runs, ...) holds.
  function again(s, whenAuto) {
    if (!s.monitor.enabled) return '監視は停止中のため、自動では再実行しません。';
    if (!s.real_capture_available) return '実サイト撮影の条件（許可の期限・残り回数など）が整っていないため、自動では再実行しません。下の「実サイト監視の準備」を確認してください。';
    return whenAuto;
  }

  function notice(s) {
    var last = s.monitor.last;
    if (s.monitor.running) return ['is-info', kindsLabel(s) + '検査中です…'];
    if (!last) return ['is-info', !s.monitor.enabled ? '監視は停止中です。' : s.real_capture_available ? 'まもなく初回撮影を開始します。'
      : '実サイト監視の準備待ちです。下の「実サイト監視の準備」の条件がすべて整うと、自動で初回撮影を始めます。それまで撮影はしません。'];
    var at = jst(last.finished_at);
    if (last.outcome === 'CHANGED') return ['is-changed', '変更を検知しました（' + at + '）。差分レビューで変化した部分を確認してください。Baselineは自動では更新しません。'];
    if (last.outcome === 'UNKNOWN') return ['is-warn', '判定できませんでした（' + at + '）：' + describe(last.profiles) + '。' + again(s, '次の検査で再確認します。')];
    if (last.outcome === 'FAILED') return ['is-error', (s.monitor_view && s.monitor_view.failure ? s.monitor_view.failure.message : '検査に失敗しました。') + '（' + at + '）' + again(s, '次の予定時刻に再実行します。')];
    if (last.outcome === 'DISK_FULL') return ['is-error', '保存容量の上限に達したため、監視を一時停止しました（' + at + '）。保存済みの検査は削除していません。容量を確保してから補助操作で再開してください。'];
    if (last.outcome === 'REAL_NOT_READY') return ['is-warn', (last.error || '実サイト撮影の条件が整っていません') + '（' + at + '）。下の「実サイト監視の準備」を確認してください。'];
    if (last.outcome === 'NO_BASELINE') return ['is-warn', '初回の撮影が安定しなかったため、Baselineをまだ作成していません（' + at + '）。' + again(s, '次の検査で再度試します。')];
    if (last.outcome === 'BASELINE_CREATED') return ['is-ok', '初回検査が完了し、初期Baselineを自動作成しました（' + at + '）。以後は定期的に比較します。'];
    return ['is-ok', '変更はありません（' + at + '）。'];
  }
  function kindsLabel(s) {  // from the real plan of this site: never "Desktop・Mobile" for a Desktop-only site
    var k = (s.kinds || []).filter(function (x) { return x === 'Desktop' || x === 'Mobile'; });
    return k.length ? k.join('・') : '';
  }
  var STATE_ICON = {ok: '●', info: '◐', warn: '⏸', error: '■'};
  // ---- the top line of HOME: is it running, is anything wrong, when was the last inspection, what must the USER do next
  function summaryBar(s, state) {
    var mv = s.monitor_view, last = s.monitor.last;
    var problem = mv.state === 'FAILED' ? '検査に失敗しました' : mv.kind === 'error' ? mv.label : mv.state === 'WAITING' || mv.state === 'NOT_READY' || (!mv.can_start && mv.start_block) ? '撮影を始める条件が未完了' : 'なし';
    var next = !mv.can_start && mv.start_block ? mv.start_block : mv.next;
    var bar = el('div', {'class': 'app-summary is-' + mv.kind, id: 'site-summary', role: 'group', 'aria-label': '監視のまとめ'});
    [['監視', mv.state === 'MONITORING' || mv.state === 'RUNNING' ? '動いています' : '止まっています', 'site-summary-running'],
     ['問題', problem, 'site-summary-problem'],
     ['最後に検査', last ? jst(last.finished_at) : 'まだありません', 'site-summary-last'],
     ['次にすること', next || '—', 'site-summary-next']].forEach(function (x) {
      add(bar, add(el('div', {'class': 'app-summary-item', id: x[2]}), el('span', {'class': 'app-summary-label'}, x[0]), el('strong', {}, x[1])));
    });
    return bar;
  }
  // ---- HOME: monitoring state + the one main control (start / stop), in plain view
  function controlBlock(s, state) {
    var mv = s.monitor_view, m = s.monitor, last = m.last;
    var box = el('section', {'class': 'app-control is-' + mv.kind, id: 'site-control', 'aria-labelledby': 'site-control-title', 'data-state': mv.state});
    add(box, el('h3', {id: 'site-control-title'}, '監視の状態と操作'));
    add(box, add(el('p', {'class': 'app-control-state', id: 'site-control-state'}), el('span', {'aria-hidden': 'true'}, (STATE_ICON[mv.kind] || '●') + ' '), document.createTextNode(mv.label)));
    add(box, para('app-control-reason', mv.reason));
    if (mv.state === 'FAILED' && mv.failure) {  // the sentence above; the internal text stays available, folded
      var det = add(el('details', {'class': 'app-ready', id: 'site-failure-detail'}), el('summary', {}, '詳細を見る（技術情報）'),
                    para('app-run-note', mv.failure.detail), para('app-run-note', mv.failure.code ? 'コード：' + mv.failure.code : ''));
      box.appendChild(det);
    }
    var facts = add(el('dl', {'class': 'app-facts'}),
      el('dt', {}, '最終検査'), el('dd', {id: 'site-fact-last'}, last ? jst(last.finished_at) + '・' + (state.site.outcomes[last.outcome] || last.outcome) : 'まだありません'),
      el('dt', {}, '次回検査予定'), el('dd', {id: 'site-fact-next'}, m.enabled ? (m.running ? '検査中' : jst(m.next_due_at)) : '—（停止中のため、自動では検査しません）'),
      el('dt', {}, '現在のBaseline'), el('dd', {id: 'site-fact-baseline'}, {NONE: '未作成', AUTO: '自動作成・未確認', CONFIRMED: '自動作成・USER確認済み', USER: '正式承認済み'}[s.baseline.state] + versionText(s.baseline.versions)),
      el('dt', {}, '検査の対象'), el('dd', {}, kindsLabel(s) + '（' + (m.interval_label || '') + '）'));
    box.appendChild(facts);
    var form = el('form', {'class': 'app-run-form app-control-form', id: 'site-toggle-form'});
    var status = el('p', {id: 'site-control-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    if (mv.state === 'RUNNING') {
      add(form, el('button', {type: 'button', id: 'site-toggle-button', 'class': 'app-run-button app-primary', disabled: ''}, '検査中です'));
    } else if (m.enabled) {
      add(form, el('button', {type: 'submit', id: 'site-toggle-button', 'class': 'app-run-button app-primary is-stop'}, '監視を停止'));
      action(form, status, '停止しています…', '/app/api/site/monitor', function () { return {enabled: false}; }, '監視を停止しました。');
    } else {
      var go = el('button', {type: 'submit', id: 'site-toggle-button', 'class': 'app-run-button app-primary'}, '監視を開始');
      if (!mv.can_start) go.setAttribute('disabled', '');
      add(form, go);
      action(form, status, '開始しています…', '/app/api/site/monitor', function () { return {enabled: true}; }, '監視を開始しました。次の検査は予定の時刻に始まります。');
    }
    box.appendChild(form);
    if (!m.enabled && !mv.can_start && mv.start_block) box.appendChild(para('app-run-note is-warn', '開始できない理由：' + mv.start_block));
    if (mv.state === 'WAIT_BASELINE' || mv.state === 'WAIT_CHANGE' || mv.state === 'WAIT_DECISION')
      box.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: 'review.html', 'class': 'app-link-button'}, '差分レビューを開いて確認する ›')));
    box.appendChild(status);
    return box;
  }
  // ---- HOME: monitoring while the app is closed is a DIFFERENT setting from starting / stopping monitoring
  function backgroundBlock(s) {
    var on = s.background === true;
    var box = el('section', {'class': 'app-background', id: 'site-background', 'data-state': String(s.background), 'aria-labelledby': 'site-background-title'});
    add(box, el('h3', {id: 'site-background-title'}, 'アプリを閉じている間の監視（バックグラウンド監視）'));
    add(box, para('app-run-note', '上の「監視を開始・停止」とは別の設定です。「監視を開始」はサイトを定期的に検査する設定、こちらはSiteProofの画面を閉じても監視を続けるための設定です。'
      + 'こちらを有効にしても、上で停止している監視が勝手に始まることはありません（停止中は、予定があっても撮影しません）。'));
    add(box, add(el('p', {'class': 'app-control-state'}), document.createTextNode('いまの設定：' + (on ? '有効（アプリを閉じても、15分ごとに予定を確認します）' : s.background === false ? '無効' : '状態を確認できません'))));
    var form = el('form', {'class': 'app-run-form', id: 'site-background-form'});
    var status = el('p', {id: 'site-background-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(form, el('button', {type: 'submit', 'class': 'app-run-button', id: on ? 'site-background-stop' : 'site-background-start'}, on ? 'バックグラウンド監視を解除する' : 'アプリを閉じても監視する'));
    action(form, status, on ? '解除しています…' : '登録しています…', '/app/api/site/setup', function () { return {step: on ? 'background-remove' : 'background'}; }, function (r) { return r.note; });
    add(box, form, status);
    return box;
  }
  // The same for the HTTP check: a task of its own (every 5 minutes), no Docker and no browser; independent of the image task above.
  function backgroundHttpBlock(s) {
    var on = s.background_http === true;
    var box = el('section', {'class': 'app-background', id: 'site-background-http', 'data-state': String(s.background_http), 'aria-labelledby': 'site-background-http-title'});
    add(box, el('h3', {id: 'site-background-http-title'}, 'アプリを閉じている間のHTTP監視'));
    add(box, para('app-run-note', 'サイトの死活（HTTP）を、5分ごとに確認するWindowsのタスクです。' + boundaryText((s.http || {}).boundary) + 'ブラウザは使いません。Docker Desktopが起動しているときだけ検査します（HTTP監視のためにDockerを起動することはありません）。'
      + '上のバックグラウンド監視（画像）とは別のタスクで、片方を解除してももう片方は続きます（タスクはサイトごとで、サイトの全ページを確認します）。'
      + 'どちらも、停止している監視を勝手に始めることはありません。HTTP監視の許可（署名）が有効なときだけ検査します。'));
    add(box, add(el('p', {'class': 'app-control-state'}), document.createTextNode('いまの設定：' + (on ? '有効（アプリを閉じても、5分ごとに予定を確認します）' : s.background_http === false ? '無効' : '状態を確認できません'))));
    var form = el('form', {'class': 'app-run-form', id: 'site-background-http-form'});
    var status = el('p', {id: 'site-background-http-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(form, el('button', {type: 'submit', 'class': 'app-run-button', id: on ? 'site-background-http-stop' : 'site-background-http-start'}, on ? 'HTTPのバックグラウンド監視を解除する' : 'アプリを閉じてもHTTP監視する'));
    action(form, status, on ? '解除しています…' : '登録しています…', '/app/api/site/setup', function () { return {step: on ? 'background-http-remove' : 'background-http'}; }, function (r) { return r.note; });
    add(box, form, status);
    return box;
  }

  function cell(label, value, cls, id) {
    return add(el('div', {'class': 'app-stat ' + (cls || ''), id: id || null}), el('span', {'class': 'app-stat-label'}, label), el('strong', {}, value));
  }
  function sitePanel(state) {
    var s = state.site, m = s.monitor;
    var d = DISPLAY[s.display] || [s.display, ''];
    if (s.display === 'EXPIRED' && s.permit && s.permit.state === 'EXHAUSTED') d = ['許可回数を使い切りました（更新が必要）', 'is-bad'];  // the period is still open
    if (s.monitor_view) d = [s.monitor_view.label, {ok: 'is-on', info: 'is-on', warn: 'is-off', error: 'is-bad'}[s.monitor_view.kind] || ''];
    var p = panel('site-panel', '画像監視：' + s.name, d[0]);  // the screenshot comparison; the HTTP check has its own panel below
    p.querySelector('.app-run-tag').classList.add(d[1]);
    p.querySelector('.app-run-tag').id = 'site-display';
    p.appendChild(para('app-run-note', '画面の見た目の変化を、承認済みのBaselineと画像で比べる監視です（サイトの死活を調べるHTTP監視とは別です）。'));
    if (s.permit_notice) p.appendChild(para('app-notice ' + (s.permit_notice.level === 'error' ? 'is-error' : 'is-warn'), s.permit_notice.text));
    if (!m.enabled && s.stop_text) p.appendChild(el('p', {'class': 'app-run-note', id: 'site-stop-text'}, s.stop_text));
    p.appendChild(controlBlock(s, state));
    p.appendChild(backgroundBlock(s));
    var n = notice(s);
    p.appendChild(el('p', {'class': 'app-notice ' + n[0], id: 'site-notice', role: 'status'}, n[1]));
    var last = m.last;
    var baseline = {NONE: '未作成（最初の撮影から自動作成）', AUTO: '自動作成（未確認）', CONFIRMED: '自動作成（確認済み）', USER: '利用者が正式承認'}[s.baseline.state] + versionText(s.baseline.versions);
    var grid = add(el('div', {'class': 'app-stats'}),
      cell('監視', m.enabled ? '自動監視中（' + (m.override ? m.interval_seconds + '秒ごと・テスト' : m.interval_label) + '）' : '停止中' + pausedWhy(s.paused_reason), m.enabled ? 'is-ok' : 'is-warn', 'site-stat-monitor'),
      cell('最終検査', last ? jst(last.finished_at) : 'まだありません', '', 'site-stat-last'),
      cell('次回検査予定', m.enabled ? (m.running ? '検査中' : jst(m.next_due_at)) : '—（停止中）', '', 'site-stat-next'),
      cell('最終結果', last ? state.site.outcomes[last.outcome] : '—', last ? OUTCOME_CLASS[last.outcome] : '', 'site-stat-result'),
      cell('Baseline', baseline + (s.mode === 'REAL' ? '・実撮影' : ''), s.baseline.state === 'AUTO' ? 'is-warn' : s.baseline.state === 'NONE' ? '' : 'is-ok', 'site-stat-baseline'),
      cell('保存容量', mb(s.disk.used) + ' / ' + mb(s.disk.limit), s.disk.full ? 'is-error' : s.disk.warn ? 'is-warn' : '', 'site-stat-disk'));
    p.appendChild(grid);
    if (last && last.profiles) p.appendChild(para('app-run-note', '最終検査の内訳：' + describe(last.profiles)));
    if (s.disk.warn && !s.disk.full) p.appendChild(para('app-notice is-warn', '保存容量が上限の80%を超えました。上限に達すると監視を一時停止します（保存済みの検査は削除しません）。'));
    var bu = s.baseline_update || {};
    if (bu.state === 'SWITCH_PENDING') p.appendChild(add(el('p', {'class': 'app-notice is-error', id: 'site-switch-pending'}),
      document.createTextNode(bu.reason + '　'), el('a', {href: 'review.html'}, '差分レビューで再試行 ›')));
    if (bu.state === 'AVAILABLE') p.appendChild(add(el('p', {'class': 'app-notice is-warn', id: 'site-update-pending'}),
      document.createTextNode('変更を検知しました。内容を「差分レビュー」で確認し、問題なければ新しい基準にできます（承認するまで、これまでのBaselineで監視を続けます）。'),
      el('a', {href: 'review.html'}, '差分レビューを開く ›')));
    p.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: 'review.html'}, '差分レビューで確認 ›'), document.createTextNode('　'),
                      el('a', {href: 'activity.html'}, '履歴・通知を見る ›')));
    if (s.log.length) {
      var log = add(el('details', {'class': 'app-ready', id: 'site-log'}), el('summary', {}, '最近の監視ログ（' + s.log.length + '件）'));
      var ul = el('ul', {});
      s.log.forEach(function (e) {
        ul.appendChild(el('li', {'class': OUTCOME_CLASS[e.outcome] || '', title: e.error || ''}, jst(e.finished_at) + '　' + state.site.outcomes[e.outcome]
          + '（' + {SCHEDULE: '定期', MANUAL: '手動'}[e.trigger] + '）' + (e.explained ? '：' + e.explained.message : e.error ? '：' + e.error : '')));
      });
      add(log, ul);
      p.appendChild(log);
    }

    // auxiliary operations: not needed for normal monitoring
    var aux = add(el('details', {'class': 'app-ready', id: 'site-aux'}), el('summary', {}, 'その他の設定（検査間隔・今すぐ再検査）'));
    var status = el('p', {id: 'site-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    if (s.error) { status.textContent = s.error; status.classList.add('is-error'); }
    var interval = el('form', {'class': 'app-run-form', id: 'site-interval-form'});
    var sel = el('select', {id: 'site-interval'});
    Object.keys(s.intervals).forEach(function (k) { var o = el('option', {value: k}, s.intervals[k]); if (+k === (m.override ? -1 : m.interval_seconds)) o.selected = true; sel.appendChild(o); });
    add(interval, el('label', {'for': 'site-interval'}, '検査間隔'), sel, el('button', {type: 'submit', 'class': 'app-run-button'}, '変更'));
    action(interval, status, '変更しています…', '/app/api/site/monitor', function () { return {interval_seconds: +sel.value}; }, '検査間隔を変更しました。');
    var now = el('form', {'class': 'app-run-form', id: 'site-inspect-form'});
    now.appendChild(el('button', {type: 'submit', id: 'site-inspect-button', 'class': 'app-run-button'}, '今すぐ再検査'));
    action(now, status, '検査しています…（15秒ほど）', '/app/api/site/inspect', function () { return {}; }, function (r) { return '検査しました：' + state.site.outcomes[r.outcome] + '。'; });
    add(aux, interval, now);
    if (s.baseline.state === 'AUTO') {
      var conf = el('form', {'class': 'app-run-form', id: 'site-confirm-form'});
      add(conf, el('span', {}, '初期Baselineは自動作成です。差分レビューで画像を確認したら：'),
          el('button', {type: 'submit', id: 'site-confirm-button', 'class': 'app-run-button'}, 'Baselineを確認済みにする'));
      action(conf, status, '記録しています…', '/app/api/site/confirm', function () { return {}; }, 'Baselineを確認済みにしました。');
      aux.appendChild(conf);
    }
    var fx = el('form', {'class': 'app-run-form', id: 'site-fixture-form'});
    var fsel = el('select', {id: 'site-fixture'});
    Object.keys(s.fixtures).forEach(function (k) { var o = el('option', {value: k}, s.fixtures[k]); if (k === m.offline_fixture) o.selected = true; fsel.appendChild(o); });
    add(fx, el('label', {'for': 'site-fixture'}, 'オフラインfixtureの撮影画像（動作確認用）'), fsel, el('button', {type: 'submit', 'class': 'app-run-button'}, '設定'));
    action(fx, status, '設定しています…', '/app/api/site/monitor', function () { return {offline_fixture: fsel.value}; }, '次の検査から使う画像を変更しました。');
    if (s.fixture_capture) aux.appendChild(fx);  // engine tests only: a normal site never uses synthetic images
    add(aux, para('app-run-note', 'Baselineの更新（変更後の画面を新しい基準にする）は、差分レビューの画面で行います。'), status);
    p.appendChild(aux);

    var done = s.readiness.filter(function (r) { return r.ok; }).length;
    var ready = add(el('details', {'class': 'app-ready', id: 'site-readiness'}),
                    el('summary', {}, '実サイト監視の準備（' + done + ' / ' + s.readiness.length + ' 完了）' + (s.real_capture_available ? '：準備完了' : '')));
    if (['REAL_PENDING', 'SETUP_NEEDED', 'SETUP_RUNNING', 'EXPIRED'].indexOf(s.display) >= 0 || (s.setup && s.setup.state !== 'DONE') || (s.permit && (s.permit.warning || s.permit.expired))) ready.setAttribute('open', '');
    var rl = el('ul', {});
    s.readiness.forEach(function (r) {
      rl.appendChild(add(el('li', {}), add(el('strong', {}), document.createTextNode((r.ok ? '✓ ' : '✗ ') + r.label + '：' + r.state)), para('app-run-note', r.guide)));
    });
    // First-time setup / renewal from the screen: each button starts an existing tool (the app holds no key and never signs).
    var host = String(s.url).split('/')[2] || '';
    var workersDev = /^[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev$/.test(host);
    var envOk = s.readiness.some(function (r) { return r.key === 'environment' && r.ok; });
    var setupStatus = el('p', {'class': 'app-run-status', id: 'site-setup-status', role: 'status', 'aria-live': 'polite'});
    var su = s.setup || {};
    var SETUP = {LAUNCHED: ['セットアップ中：別のウィンドウが開きます。そこで内容を確認して署名してください', 'is-warn'],
                 RUNNING: ['セットアップ中：別のウィンドウで操作しています（終わるとこの画面が自動で更新されます）', 'is-warn'],
                 DONE: ['セットアップ完了：実サイト監視の準備ができました', 'is-ok'],
                 NOT_READY: ['セットアップは終わりましたが、整っていない項目があります：', 'is-error'],
                 FAILED: ['セットアップは完了しませんでした：', 'is-error']};
    if (SETUP[su.state]) {
      var shownMsg = (su.state === 'NOT_READY' || su.state === 'FAILED') ? SETUP[su.state][0] + (su.message || '') : SETUP[su.state][0];
      add(rl, add(el('li', {'class': 'app-setup-state ' + SETUP[su.state][1], id: 'site-setup-state', 'data-state': su.state}),
                  document.createTextNode(shownMsg + '（' + jst(su.at) + '）')));
    }
    var pm = s.permit;
    if (pm) {
      var pmText = '監視許可：' + jst(pm.valid_until) + ' まで（残り ' + (pm.days_left != null ? pm.days_left : '—') + ' 日・撮影 ' + pm.remaining_runs + ' 回）';
      add(rl, add(el('li', {'class': 'app-permit' + (pm.warning || pm.expired ? ' is-warn' : ''), id: 'site-permit', 'data-warning': String(!!(pm.warning || pm.expired))}),
                  document.createTextNode(pmText + (pm.state === 'EXHAUSTED' ? '：許可回数を使い切りました（期限はまだ残っています）。「監視設定を更新」で更新してください'
                                                    : pm.expired ? '：期限切れです。「監視設定を更新」で更新してください'
                                                    : pm.warning ? '：まもなく期限です。「監視設定を更新」で更新してください' : ''))));
    }
    var renew = !!pm;  // a valid signature exists: the same tool renews it (the Baseline is carried over under the new signature)
    if (s.unit === s.site_id && (!s.real_capture_available || renew)) {  // the image permit is the first page's only
      var sf = el('form', {'class': 'app-run-form app-setup-form', id: 'site-setup-form'});
      var own = el('select', {id: 'site-setup-ownership'});
      // Only methods that can really be verified are selectable. The two others stay listed (so the user sees why) but disabled.
      var dnsDone = (s.ownership || {}).method === 'DNS_TXT_CHALLENGE' && (s.ownership || {}).status === 'VERIFIED';
      (s.ownership_evidence ? [['reuse', '前回の所有権の確認記録を使う']] : [])
        .concat(dnsDone ? [['dns', 'DNSのTXTレコードの確認記録を使う（確認済み・下の「所有権の確認」）']] : [])
        .concat(workersDev ? [['cloudflare', 'Cloudflareのアカウントで確認（workers.dev・自動）']] : [])
        .forEach(function (o) { own.appendChild(el('option', {value: o[0]}, o[1])); });
      [['well-known-file', 'サイトに確認用ファイルを置く'], ['dns-txt', 'DNSのTXTレコードを設定したと申告する（自己申告）']].forEach(function (o) {
        own.appendChild(el('option', {value: o[0], disabled: 'disabled'}, o[1] + '（現在この確認方法には対応していません）'));
      });
      var usable = own.querySelector('option:not([disabled])');
      if (usable) { own.value = usable.value; } else { own.selectedIndex = -1; own.disabled = true; }
      var busy = su.state === 'LAUNCHED' || su.state === 'RUNNING';
      var startAttrs = {type: 'submit', 'class': 'app-run-button', id: 'site-setup-start'};
      if (!usable) { startAttrs.disabled = 'disabled'; }
      var start = el('button', startAttrs, renew ? '監視設定を更新' : '初回セットアップを開始');
      add(sf, el('label', {'for': 'site-setup-ownership'}, '所有権の確認方法'), own, start);
      if (!usable) {
        add(sf, el('p', {'class': 'app-run-note is-warn', id: 'site-setup-no-method'},
                   'このサイトで使える所有権の確認記録は、まだありません。下の「所有権の確認」でDNSのTXTレコードによる確認を済ませるか（どのサイトでも可）、workers.devのサイトではCloudflareのアカウントで確認してください。確認できるまで、実サイトの撮影は始められません（登録した内容はそのまま残ります）。'));
      }
      action(sf, setupStatus, 'セットアップの画面を開いています…', '/app/api/site/setup', function () {
        return {step: 'setup', ownership: own.value};
      }, function (r) { return r.note; });
      add(rl, add(el('li', {'class': 'app-setup'}), add(el('strong', {}), document.createTextNode(renew ? '監視設定を更新（期間・回数の延長）' : '初回セットアップ')), sf,
                  para('app-run-note', (busy ? 'セットアップの画面がまだ開いています。閉じてしまった場合は、もう一度押してください。' : '')
                       + '別のウィンドウが開き、鍵の作成・所有権の確認・監視許可の内容を表示します。内容を確認して「y」で署名してください（鍵にパスフレーズがあれば、そこで入力します）。'
                       + '署名は利用者の鍵で行い、アプリは署名しません。終わるとこの画面が自動で更新されます。')));
    }
    if (!envOk) {
      var df = add(el('form', {'class': 'app-run-form', id: 'site-docker-form'}), el('button', {type: 'submit', 'class': 'app-run-button', id: 'site-docker-start'}, 'Docker Desktopを起動'));
      action(df, setupStatus, '起動しています…', '/app/api/site/setup', function () { return {step: 'docker'}; }, function (r) { return r.note; });
      add(rl, add(el('li', {'class': 'app-setup'}), add(el('strong', {}), document.createTextNode('撮影環境')), df));
    }
    add(rl, add(el('li', {}), setupStatus));
    add(ready, rl, para('app-run-note', 'すべての条件が整うまで、実サイトへはアクセスしません。条件が整うと、次の定期検査から自動で実サイトを撮影し、最初の安定した撮影からBaselineを作り、その後は同じBaselineと自動で比較します（許可の期間・回数の範囲内）。監視許可は「初回セットアップ」の別ウィンドウで、利用者が自分の鍵で署名します。アプリは許可を発行できず、検証するだけです。'));
    p.appendChild(ready);
    if ((state.sites || []).length < state.max_sites) {  // another site: folded away, until the maximum
      p.appendChild(add(el('details', {'class': 'app-ready', id: 'site-add-more'}), el('summary', {}, '別のサイトを追加'), addSitePanel(state)));
    }
    p.appendChild(para('app-run-foot', '保存済みの検査 ' + s.runs + '件 ／ データ：' + state.data));
    p.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: '/demo/'}, '合成デモ（固定のサンプル）を見る ›')));
    return p;
  }

  // ---- several pages of one site: the list, 「ページを追加」, and the one confirmed stop of the whole site. Each page is a unit of its own (own settings,
  // Baseline, history, permit / grant); only the site's ownership evidence and e-mail switch are shared.
  function pagesPanel(state) {
    var s = state.site, list = s.pages || [];
    var p = panel('pages-panel', 'このサイトのページ', list.length + ' / ' + (s.max_pages || 5) + 'ページ');
    p.appendChild(para('app-run-note', '1つのサイトには、最初のページを含めて最大' + (s.max_pages || 5) + 'ページまで登録できます。ページごとに、設定・Baseline・履歴・通知・許可は別々です（あるページの許可が、別のページに効くことはありません）。'
      + '画像の撮影が扱えるのはトップページ（/）だけです。追加したページはHTTP監視だけが使えます（画像監視は停止のまま、別のページの画像で代用することもしません）。'));
    var ul = el('ul', {id: 'site-pages'});
    list.forEach(function (x) {
      var li = el('li', {'class': x.current ? 'is-current' : ''});
      if (OWN_PAGE.test(x.href)) li.appendChild(el('a', {href: x.href}, x.label)); else li.appendChild(document.createTextNode(x.label));
      li.appendChild(document.createTextNode('　' + x.url + (x.current ? '（表示中）' : '')));
      ul.appendChild(li);
    });
    p.appendChild(ul);
    var status = el('p', {id: 'page-add-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    if (list.length >= (s.max_pages || 5)) {
      p.appendChild(el('p', {'class': 'app-run-note', id: 'page-add-limit'}, 'これ以上ページを追加できません（上限に達しています）。'));
    } else {
      var more = el('details', {'class': 'app-ready', id: 'page-add-more'});
      add(more, el('summary', {}, 'ページを追加'));
      var form = el('form', {'class': 'app-site-form', id: 'page-add-form'});
      var path = el('input', {id: 'page-path', type: 'text', maxlength: '200', required: '', autocomplete: 'off', placeholder: '/about'});
      var label = el('input', {id: 'page-label', type: 'text', maxlength: '60', autocomplete: 'off', placeholder: '例：会社概要（空欄ならパス）'});
      add(form, add(el('div', {'class': 'app-field'}), el('label', {'for': 'page-path'}, 'ページのパス（同じサイトの https://…/ からあとの部分）'), path),
          add(el('div', {'class': 'app-field'}), el('label', {'for': 'page-label'}, 'ページの名前'), label));
      var kinds = add(el('fieldset', {'class': 'app-field'}), el('legend', {}, '画面サイズ'));
      ['Desktop', 'Mobile'].forEach(function (k) {
        var box = el('input', {type: 'checkbox', id: 'page-kind-' + k, value: k, checked: ''});
        kinds.appendChild(add(el('label', {'class': 'app-check', 'for': 'page-kind-' + k}), box, document.createTextNode(' ' + SIZES[k])));
      });
      add(form, kinds, el('button', {type: 'submit', id: 'page-add-submit', 'class': 'app-run-button'}, 'ページを追加'));
      action(form, status, '追加しています…', '/app/api/site/add-page', function () {
        return {path: path.value, label: label.value, kinds: ['Desktop', 'Mobile'].filter(function (k) { return document.getElementById('page-kind-' + k).checked; })};
      }, '追加しました。', function (r) { return r && r.href ? r.href : null; });
      add(more, form);
      p.appendChild(more);
    }
    p.appendChild(status);
    var sf = el('form', {'class': 'app-run-form', id: 'site-stop-all-form'});
    var ok = el('input', {type: 'checkbox', id: 'site-stop-all-ok'});
    var button = el('button', {type: 'submit', id: 'site-stop-all-button', 'class': 'app-run-button is-stop', disabled: ''}, 'このサイトの監視をすべて停止');
    ok.addEventListener('change', function () { if (ok.checked) button.removeAttribute('disabled'); else button.setAttribute('disabled', ''); });
    var stopStatus = el('p', {id: 'site-stop-all-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(sf, add(el('label', {'class': 'app-check', 'for': 'site-stop-all-ok'}), ok, document.createTextNode(' このサイトの全ページの画像監視とHTTP監視を止めることを確認しました')), button);
    action(sf, stopStatus, '停止しています…', '/app/api/site/stop-site', function () { return {confirmed: ok.checked}; }, 'このサイトの監視をすべて停止しました。');
    add(p, sf, stopStatus, para('app-run-note', '他のサイトの監視は止まりません。再開は、ページごとの「監視を開始」で行います（まとめて開始する操作はありません）。'));
    return p;
  }

  // ---- ownership of the site's host by DNS TXT challenge. A record that was only issued is never shown as confirmed.
  var OWNERSHIP_STATUS = {NONE: ['未確認', 'is-off'], CHALLENGE: ['確認待ち（TXTレコードの登録待ち）', 'is-off'], VERIFIED: ['確認済み', 'is-on'], EXPIRED: ['期限切れ', 'is-bad'], REVOKED: ['取り消し済み', 'is-bad']};
  var OWNERSHIP_METHOD = {CLOUDFLARE_ACCOUNT_CONTROL: 'Cloudflareのアカウント確認（workers.dev）', DNS_TXT_CHALLENGE: 'DNSのTXTレコード'};
  function ownershipPanel(state) {
    var o = state.site.ownership || {status: 'NONE'};
    var st = OWNERSHIP_STATUS[o.status] || [o.status, ''];
    var p = panel('ownership-panel', '所有権の確認（DNSのTXTレコード）', st[0]);
    p.querySelector('.app-run-tag').classList.add(st[1]);
    p.querySelector('.app-run-tag').id = 'ownership-state';
    p.querySelector('.app-run-tag').dataset.state = o.status;
    p.appendChild(para('app-run-note', 'このサイトのホスト（' + (o.host || '—') + '）を自分が管理していることを、DNSにTXTレコードを置いて確認します。実サイトの監視・検査には、この確認（またはworkers.devのCloudflare確認）が必要です。'
      + 'レコードは、このホストの名前でだけ有効です（親ドメイン・別のホスト・別のサイトの記録は使えません）。'));
    if (o.guidance) p.appendChild(el('p', {'class': 'app-run-note', id: 'ownership-guidance'}, o.guidance));
    var rows = [['確認方法', OWNERSHIP_METHOD[o.method] || '—'], ['状態', st[0]]];
    if (o.checked_at) rows.push(['確認した日時', jst(o.checked_at)], ['有効期限', jst(o.valid_until) + (o.days_left != null ? '（あと' + o.days_left + '日・最長90日）' : '')]);
    p.appendChild(facts(rows, 'ownership-facts'));
    if (o.record_value) {  // the record to publish: copy-friendly
      add(p, el('h3', {}, '登録するTXTレコード（有効期限 ' + jst(o.expires_at) + '）'),
          para('app-run-note', '名前（ホスト）'), el('pre', {'class': 'app-cmd', id: 'ownership-record-name'}, o.record_name),
          para('app-run-note', '値（TXT）'), el('pre', {'class': 'app-cmd', id: 'ownership-record-value'}, o.record_value),
          para('app-run-note', '値は、この1つのサイト・このホスト専用のものです。登録しただけでは「確認済み」になりません。'));
    }
    var status = el('p', {id: 'ownership-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    var iform = el('form', {'class': 'app-run-form', id: 'ownership-issue-form'});
    add(iform, el('button', {type: 'submit', id: 'ownership-issue', 'class': 'app-run-button'}, o.record_value ? '確認用の記録をもう一度表示' : '確認用の記録を発行'));
    action(iform, status, '発行しています…', '/app/api/site/setup', function () { return {step: 'dns-issue'}; }, function (r) { return r.note; });
    var cform = el('form', {'class': 'app-run-form', id: 'ownership-check-form'});
    var check = el('button', {type: 'submit', id: 'ownership-check', 'class': 'app-run-button'}, 'DNSで確認する（別のウィンドウ）');
    if (!o.record_value) check.setAttribute('disabled', '');
    add(cform, check);
    action(cform, status, '確認の画面を開いています…', '/app/api/site/setup', function () { return {step: 'dns-check'}; }, function (r) { return r.note; });
    add(p, add(el('div', {'class': 'app-run-form', id: 'ownership-controls'}), iform, cform), status);
    p.appendChild(el('p', {'class': 'app-run-note' + (o.dns_check_enabled ? '' : ' is-warn'), id: 'ownership-dns-note'},
      'この確認は、監視とは別に、あなたが始めるDNSの照会（TXTレコード）です。別のウィンドウで実行し、許可・監視の設定は読まず、何も開始しません。'
      + (o.dns_check_enabled ? '' : 'いまは、承認されるまで無効です（ボタンを押しても、何も問い合わせません）。')));
    return p;
  }

  // ---- HTTP (死活) monitoring: a channel of its own, apart from the image monitor. This PC's observations only (never the AWS-B archive).
  var HTTP_STATE = {OK: 'is-ok', DOWN: 'is-error', UNKNOWN: 'is-warn', NOT_MONITORED: '', STALE: 'is-warn', STOPPED: 'is-warn'};
  var HTTP_EVENT = {DOWN: 'is-error', RECOVERED: 'is-ok', UNKNOWN: 'is-warn', OK: 'is-ok'};
  var TLS_NOTE = {OK: '問題なし', WARN: '期限が近い（14日以内）', CRITICAL: '期限が近い（3日以内）', EXPIRED: '期限切れ', UNKNOWN: '未取得'};
  var TLS_CLASS = {OK: 'is-ok', WARN: 'is-warn', CRITICAL: 'is-error', EXPIRED: 'is-error', UNKNOWN: ''};
  var NOT_RUN_REASON = {ENGINE_UNAVAILABLE: 'Docker Desktopが起動していません', IMAGE_UNAVAILABLE: '撮影イメージがこのPCにありません', BUSY: '別の検査が動いていました', SETUP_FAILED: '検査の準備に失敗しました'};
  // A check that was NOT made (Docker not running, ...): said as such, with the reason. Never "障害" (the site is down) or "判定不能" (a check was made and could not decide).
  function notRunNotice(nr) {
    return add(el('p', {'class': 'app-notice is-info', id: 'http-not-run', 'data-code': String(nr.code || '')}, null),
               el('strong', {}, '検査していません'), document.createTextNode('：' + (nr.message || NOT_RUN_REASON[nr.code] || '検査を始められませんでした')
                 + '（' + jst(nr.at) + '）。サイトの障害とは限りません（検査自体を行っていないためです）。'));
  }
  function httpPanel(state) {
    var h = state.site.http;
    var p = panel('http-panel', 'HTTP監視（サイトの死活）', h && h.state_label ? h.state_label : '');
    if (!h || h.error) { p.appendChild(para('app-notice is-error', 'HTTP監視の状態を読み取れません：' + ((h && h.error) || ''))); return p; }
    var tag = p.querySelector('.app-run-tag');
    tag.id = 'http-state'; tag.dataset.state = h.state; if (HTTP_STATE[h.state]) tag.classList.add(HTTP_STATE[h.state]);
    p.appendChild(para('app-run-note', '画像監視とは別の監視です（別の間隔・別の許可）。このPCで観測した結果だけを表示し、AWSの保存結果とは混ぜません。'));
    p.appendChild(el('p', {'class': 'app-run-note', id: 'http-docker-note'}, '検査は1回ごとに隔離コンテナを1つ起動して行うため、Docker Desktopが起動している必要があります（HTTP監視のためにDockerを起動することはありません）。'
      + '起動していないと検査せず、「検査していません」と表示します（サイトの障害や判定不能とは別です）。'));
    if (h.not_run) p.appendChild(notRunNotice(h.not_run));
    if (!h.external_enabled) p.appendChild(para('app-notice is-warn', 'HTTP監視の外部通信は、実サイトでの試験とUSERの承認が済むまで無効です（検査の隔離は模擬環境で実測済み）。いまは何も検査していません。'));
    if (h.grant_notice) p.appendChild(el('p', {'class': 'app-notice ' + (h.grant_notice.level === 'error' ? 'is-error' : 'is-warn'), id: 'http-grant-notice'}, h.grant_notice.text));
    if (!h.enabled && h.stop_text) p.appendChild(el('p', {'class': 'app-run-note', id: 'http-stop-text'}, h.stop_text));
    if (h.paused_reason === 'BLOCKED') p.appendChild(para('app-notice is-warn', 'HTTP監視は停止しました：' + (h.paused_detail || '許可の確認ができませんでした')));
    if (h.state === 'STALE') p.appendChild(para('app-notice is-warn', '最後の観測が古いため、現在の状態は不明です（最後の観測は参考表示です）。'));
    if (h.state === 'STOPPED' && h.last) p.appendChild(para('app-run-note', '監視は停止中です。下の結果は、停止前の最後の観測です。'));
    var last = h.last, tls = h.tls || {};
    p.appendChild(add(el('div', {'class': 'app-stats'}),
      cell('状態', h.state_label, HTTP_STATE[h.state], 'http-stat-state'),
      cell('最新HTTPステータス', last && last.http_status != null ? String(last.http_status) : '—', last && last.outcome === 'FAIL' ? 'is-error' : '', 'http-stat-status'),
      cell('応答時間', last && last.elapsed_ms != null ? last.elapsed_ms.toLocaleString('ja-JP') + ' ms' : '—', '', 'http-stat-time'),
      cell('TLS証明書の期限', tls.not_after ? jst(tls.not_after) + '（残り' + tls.days_left + '日・' + TLS_NOTE[tls.level] + '）' : '—', TLS_CLASS[tls.level] || '', 'http-stat-tls'),
      cell('最終観測', last ? jst(last.at) + (last.outcome !== 'PASS' && last.reason ? '・' + (last.reason_label || last.reason) : '') : 'まだありません', '', 'http-stat-last'),
      cell('次回予定', h.enabled ? jst(h.next_due_at) : '—（停止中）', '', 'http-stat-next'),
      cell('監視間隔', h.interval_label || '—', '', 'http-stat-interval')));
    var controls = el('div', {'class': 'app-run-form', id: 'http-controls'});
    var form = el('form', {'class': 'app-run-form', id: 'http-toggle-form'});
    var status = el('p', {id: 'http-status-line', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    var toggle = el('button', {type: 'submit', id: 'http-toggle', 'class': 'app-run-button'}, h.enabled ? 'HTTP監視を停止' : 'HTTP監視を開始');
    if (!h.enabled && !h.can_start) toggle.setAttribute('disabled', '');
    add(form, toggle);
    action(form, status, h.enabled ? '停止しています…' : '開始しています…', '/app/api/site/http', function () { return {what: h.enabled ? 'stop' : 'start'}; },
           h.enabled ? 'HTTP監視を停止しました。' : 'HTTP監視を開始しました。');
    var iform = el('form', {'class': 'app-run-form', id: 'http-interval-form'});
    var sel = el('select', {id: 'http-interval'});
    Object.keys(h.intervals).forEach(function (k) { var o = el('option', {value: k}, h.intervals[k]); if (Number(k) === h.interval_seconds) o.selected = true; sel.appendChild(o); });
    add(iform, el('label', {'for': 'http-interval'}, 'HTTP監視の間隔'), sel, el('button', {type: 'submit', id: 'http-interval-button', 'class': 'app-run-button'}, '間隔を変更'));
    action(iform, status, '変更しています…', '/app/api/site/http', function () { return {what: 'interval', interval_seconds: Number(sel.value)}; }, '間隔を変更しました。');
    var cform = el('form', {'class': 'app-run-form', id: 'http-check-form'});  // one manual check: it uses up one request of the grant
    var check = el('button', {type: 'submit', id: 'http-check', 'class': 'app-run-button'}, '今すぐ検査');
    if (h.start_block) check.setAttribute('disabled', '');  // the same reasons as for starting (grant, boundary, history); a running monitor has none
    add(cform, check, el('span', {'class': 'app-run-note'}, '許可された回数のうち1回を使います'));
    action(cform, status, '検査しています…', '/app/api/site/http', function () { return {what: 'check'}; }, '検査しました。');
    add(controls, form, iform, cform);
    p.appendChild(controls);
    p.appendChild(status);
    if (!h.enabled && h.start_block) p.appendChild(para('app-run-note', '開始できない理由：' + h.start_block));
    p.appendChild(backgroundHttpBlock(state.site));  // the HTTP task is the HTTP channel's: it lives with the HTTP check, not with the image monitor
    p.appendChild(httpGrantBlock(h));
    var gapList = el('ul', {id: 'http-gaps'});
    (h.gaps || []).forEach(function (x) {
      gapList.appendChild(el('li', {'class': x.open ? 'is-warn' : ''}, jst(x.from) + ' 〜 ' + (x.open ? '現在まで（観測がないまま続いています）' : jst(x.to)) + '：約' + x.missed + '回分の観測がありません'));
    });
    p.appendChild(add(el('details', {'class': 'app-ready', id: 'http-gaps-details'}), el('summary', {}, '観測がない期間（' + (h.gaps || []).length + '件）'),
                      para('app-run-note', 'PCの電源が切れていた・監視を止めていた期間などです。抜けた回の検査は、あとから取り戻しません。'),
                      (h.gaps || []).length ? gapList : para('app-run-note', 'ありません。')));
    if (h.days_unobserved != null && h.days_unobserved >= 1) p.appendChild(para('app-run-note is-warn', '最後の観測から ' + h.days_unobserved + ' 日たっています。'));
    p.appendChild(httpMaintenance(h));
    p.appendChild(para('app-run-note', boundaryText(h.boundary) + (h.boundary && h.boundary.process_guard ? '検査はアプリの中の見張り（接続先・回数・時間）で守っています。' : '')));
    var ev = el('ul', {id: 'http-events'});
    h.events.slice(0, 8).forEach(function (e) { ev.appendChild(el('li', {'class': HTTP_EVENT[e.type] || ''}, jst(e.at) + '　' + e.label + (e.http_status ? '（HTTP ' + e.http_status + '）' : e.reason && e.type !== 'RECOVERED' ? '（' + (e.reason_label || e.reason) + '）' : ''))); });
    p.appendChild(add(el('details', {'class': 'app-ready', id: 'http-history', open: ''}), el('summary', {}, '障害・復旧の履歴（' + h.events.length + '件）'),
                      h.events.length ? ev : para('app-run-note', 'まだ記録がありません。')));
    return p;
  }
  function facts(rows, id) {
    var dl = el('dl', {'class': 'app-facts', id: id});
    rows.forEach(function (r) { add(dl, el('dt', {}, r[0]), el('dd', {}, r[1])); });
    return dl;
  }
  var GRANT_STATE = {VALID: '有効', MISSING: '未署名（許可がありません）', EXPIRED: '期限切れ', EXHAUSTED: '回数を使い切りました', INVALID: '無効'};
  var PURPOSE = {LIMITED_TRIAL: '限定試験', MONITOR: '常時監視'};
  // The HTTP grant as the USER signed it: period, requests left, shortest interval, purpose. The app only shows it; the USER signs in a window of their own.
  function httpGrantBlock(h) {
    var g = h.grant || {};
    var box = el('section', {'class': 'app-background', id: 'http-grant', 'data-state': g.state || ''});
    add(box, el('h3', {}, 'HTTP監視の許可'));
    var rows = [['許可の状態', GRANT_STATE[g.state] || g.state || '—']];
    if (g.valid_until) {
      rows.push(['目的', PURPOSE[g.purpose] || g.purpose || '—'], ['期限', jst(g.valid_until) + (g.days_left != null ? '（残り' + g.days_left + '日）' : '')],
                ['残り回数', g.used == null ? '読み取れません' : g.remaining + ' / ' + g.max_requests + '回（使用 ' + g.used + '回）'],
                ['最短の間隔', g.min_interval_seconds != null ? g.min_interval_seconds + '秒' : '—']);
    }
    add(box, facts(rows, 'http-grant-facts'));
    if (g.state !== 'VALID' && g.problems && g.problems.length) {
      var list = el('ul', {id: 'http-grant-problems'});
      g.problems.forEach(function (t) { list.appendChild(el('li', {}, t)); });
      box.appendChild(list);
    }
    var form = el('form', {'class': 'app-run-form', id: 'http-grant-form'});
    var status = el('p', {id: 'http-grant-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(form, el('button', {type: 'submit', id: 'http-grant-sign', 'class': 'app-run-button'}, 'HTTP監視の許可に署名する'));
    action(form, status, '署名の画面を開いています…', '/app/api/site/setup', function () { return {step: 'http-grant'}; }, function (r) { return r.note; });
    add(box, form, para('app-run-note', '別のウィンドウが開きます。許可の内容を確認して、あなたが自分の鍵で署名します（アプリは署名しません。署名しても、監視は始まりません）。'), status);
    return box;
  }
  // The USER's explicit tidy-up: a confirmation box, then one button. Records are MOVED to another file, never deleted.
  function archiveForm(id, checkText, buttonText, what, doneText) {
    var form = el('form', {'class': 'app-run-form', id: id + '-form'});
    var ok = el('input', {type: 'checkbox', id: id + '-ok'});
    var button = el('button', {type: 'submit', id: id + '-button', 'class': 'app-run-button', disabled: ''}, buttonText);
    ok.addEventListener('change', function () { if (ok.checked) button.removeAttribute('disabled'); else button.setAttribute('disabled', ''); });
    var status = el('p', {id: id + '-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(form, add(el('label', {'class': 'app-check', 'for': id + '-ok'}), ok, document.createTextNode(' ' + checkText)), button);
    action(form, status, '整理しています…', '/app/api/site/maintenance', function () { return {what: what, confirmed: ok.checked}; }, doneText);
    return add(el('div', {}), form, status);
  }
  function httpMaintenance(h) {
    var u = h.history_usage || {bytes: 0, limit_bytes: 1};
    var d = el('details', {'class': 'app-ready', id: 'http-maintenance'});
    if (u.warn) d.setAttribute('open', '');
    add(d, el('summary', {}, 'HTTP監視の履歴の容量と整理'),
        el('p', {'class': 'app-run-note' + (u.warn ? ' is-warn' : ''), id: 'http-history-usage'},
           '履歴：' + mb(u.bytes) + ' / ' + mb(u.limit_bytes) + (u.full ? '（上限に達しました。整理するまで開始できません）' : u.warn ? '（上限の80%を超えました。早めに整理してください）' : '')),
        archiveForm('http-archive', '履歴を別のファイルへ移すことを確認しました（削除はしません。古い履歴はアーカイブに残ります）', '履歴を整理（別ファイルへ移す）', 'archive-http',
                    function (r) { return r && r.archived ? '履歴を別ファイルへ移しました（' + r.records + '件）。削除はしていません。' : '移す履歴はありませんでした。'; }));
    return d;
  }
  // HTTP checks run one at a time in an isolated one-shot container (Docker Desktop must already be running); what is NOT known is said, never implied.
  function boundaryText(b) {
    if (!b || b.mode !== 'DOCKER_NETNS') return '検査の隔離の方式を確認できません。';
    return '隔離コンテナで1回ずつ実行します（コンテナの境界は' + (b.measured ? '実測済み' : b.fixture_measured ? '外部ネットワークのない模擬環境で実測済み・実サイトでは未実測' : '未実測') + 'です）。';
  }
  function qualityText(label) {
    return label === '検査品質：問題なし' ? '検査品質：比較に使えます（正式な品質認証は未確認）' : label;
  }

  // ---- e-mail notification: a channel of its own (own signed grant, own switches). A send that was accepted is never shown as received.
  var NOTIFY_CLASS = {ACCEPTED: 'is-ok', PARTIAL: 'is-warn', REJECTED: 'is-error', TEMPORARY: 'is-warn', UNCERTAIN: 'is-warn', REFUSED: 'is-warn', GAVE_UP: 'is-error'};
  function notifyPanel(state) {
    var n = state.site.notify;
    var p = panel('notify-panel', 'メール通知', n && !n.error ? (n.active ? '有効' : '無効') : '');
    if (!n || n.error) { p.appendChild(para('app-notice is-error', 'メール通知の状態を読み取れません：' + ((n && n.error) || ''))); return p; }
    var g = n.grant || {};
    p.querySelector('.app-run-tag').classList.add(n.active ? 'is-on' : 'is-off');
    p.appendChild(para('app-run-note', 'アプリの画面への通知は、いつも記録されます。メールは、あなたが署名した許可と、ここでの有効化があるときだけ送られます。'
      + '「送信受付済み」はメールサーバーが受け付けたという意味で、受信を保証しません。有効にした時点より前の通知は送りません。'));
    if (!n.external_enabled) p.appendChild(para('app-notice is-warn', 'メールの外部通信は、安全境界の実測とUSERの承認が済むまで無効です。いまは何も送っていません。'));
    if (n.block_reason && !n.active) p.appendChild(el('p', {'class': 'app-notice is-warn', id: 'notify-block'}, '有効にできない理由：' + n.block_reason));
    if (g.valid && g.days_left != null && g.days_left <= 7) {
      p.appendChild(el('p', {'class': 'app-notice is-warn', id: 'notify-expiry'}, 'メール通知の許可は、あと' + g.days_left + '日で期限です。止まる前に、tools/notify_grant.py で許可を作り直して（署名して）ください。'));
    }
    var rows = [['共通のスイッチ（全サイト）', n.enabled ? '有効' : '無効'], ['このサイトのスイッチ', n.site_enabled ? '有効' : '無効']];
    if (g.valid) {
      rows.push(['サーバー', g.host + ':' + g.port + '（' + g.security + '）'], ['宛先', (g.recipients || []).join('、')],
                ['許可の期限', jst(g.valid_until) + '（残り' + g.days_left + '日）'],
                ['残りの通数', g.remaining_total == null ? '—' : '合計あと' + g.remaining_total + '通・今日はあと' + g.remaining_today + '通']);
    } else {
      rows.push(['通知の許可', '使えません']);
    }
    rows.push(['送信待ちの通知', n.pending + '件']);
    p.appendChild(facts(rows, 'notify-facts'));
    if (!g.valid && (g.problems || []).length) {
      var pl = el('ul', {id: 'notify-problems'});
      g.problems.forEach(function (t) { pl.appendChild(el('li', {}, t)); });
      p.appendChild(pl);
    }
    var status = el('p', {id: 'notify-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    var toggles = el('div', {'class': 'app-run-form', id: 'notify-controls'});
    [['channel', 'notify-channel', n.enabled, 'メール通知（全サイト共通）を', '有効にする', '無効にする'], ['site', 'notify-site', n.site_enabled, 'このサイトのメール通知を', '有効にする', '無効にする']].forEach(function (t) {
      var form = el('form', {'class': 'app-run-form', id: t[1] + '-form'});
      var btn = el('button', {type: 'submit', id: t[1] + '-button', 'class': 'app-run-button'}, t[3] + (t[2] ? t[5] : t[4]));
      if (!t[2] && !n.can_enable) btn.setAttribute('disabled', '');
      add(form, btn);
      action(form, status, '切り替えています…', '/app/api/site/notify', function () { return {what: t[0], enabled: !t[2]}; }, t[2] ? '無効にしました。' : '有効にしました。');
      toggles.appendChild(form);
    });
    p.appendChild(toggles);
    var kf = el('form', {'class': 'app-run-form', id: 'notify-kinds-form'});
    var boxes = [];
    Object.keys(n.kind_labels || {}).forEach(function (k) {
      var box = el('input', {type: 'checkbox', id: 'notify-kind-' + k, value: k});
      if ((n.kinds || []).indexOf(k) >= 0) box.setAttribute('checked', '');
      boxes.push(box);
      kf.appendChild(add(el('label', {'class': 'app-check', 'for': 'notify-kind-' + k}), box, document.createTextNode(' ' + n.kind_labels[k])));
    });
    add(kf, el('button', {type: 'submit', id: 'notify-kinds-button', 'class': 'app-run-button'}, '通知する種類を保存'));
    action(kf, status, '保存しています…', '/app/api/site/notify', function () { return {what: 'kinds', kinds: boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; })}; }, '通知する種類を保存しました。');
    p.appendChild(add(el('fieldset', {'class': 'app-field'}), el('legend', {}, '通知する種類（全サイト共通）'), kf));
    var tf = el('form', {'class': 'app-run-form', id: 'notify-test-form'});
    var test = el('button', {type: 'submit', id: 'notify-test', 'class': 'app-run-button'}, 'テスト通知を送る');
    if (!g.valid || !n.external_enabled) test.setAttribute('disabled', '');
    add(tf, test, el('span', {'class': 'app-run-note'}, '許可された通数のうち1通を使います。1分に1回までです。'));
    action(tf, status, '送信しています…', '/app/api/site/notify', function () { return {what: 'test'}; }, function (r) { return 'テスト通知：' + (r && r.label ? r.label : '送信しました') + '。'; });
    add(p, tf, status);
    var list = el('ul', {id: 'notify-recent'});
    (n.recent || []).slice(0, 8).forEach(function (e) {
      list.appendChild(el('li', {'class': NOTIFY_CLASS[e.result] || ''}, jst(e.at) + '　' + (e.test ? 'テスト送信' : (e.title || '通知')) + '：' + e.label));
    });
    p.appendChild(add(el('details', {'class': 'app-ready', id: 'notify-history'}), el('summary', {}, 'メールの送信の記録（' + (n.recent || []).length + '件）'),
                      (n.recent || []).length ? list : para('app-run-note', 'まだ送信の記録はありません。')));
    p.appendChild(add(el('details', {'class': 'app-ready', id: 'notify-setup'}), el('summary', {}, '使い始めるには（あなたが行う準備）'),
      para('app-run-note', '1. メールのユーザー名とパスワードは、Windowsの「資格情報マネージャー」に、あなたが「SiteProof-SMTP-…」という名前の汎用資格情報として登録します。SiteProofは送信の瞬間にだけ読み取り、どのファイルにも保存・表示しません。'),
      para('app-run-note', '2. 次のコマンドで、あなたが許可（サーバー・送信元・宛先・期間・通数）に署名します。アプリは署名しません。署名しても、メールは始まりません。'),
      el('pre', {'class': 'app-cmd', id: 'notify-grant-command'}, 'py -3.15 -B tools/notify_grant.py --data "' + state.data + '" --host <SMTPサーバー> --port 587 --sender <送信元> --recipient <宛先> --credential-ref SiteProof-SMTP-main --days 30'),
      para('app-run-note', '3. この画面で、全サイト共通とこのサイトのスイッチを有効にし、テスト通知で確認します。')));
    return p;
  }

  // ---- storage and backup: how much is used, tidy-up (moves, never deletes), local copies (nothing is uploaded)
  function storagePanel(state) {
    var s = state.site, st = state.storage || {};
    var d = el('details', {'class': 'app-ready', id: 'storage-panel'});
    add(d, el('summary', {}, '保存容量・整理・バックアップ'));
    var rows = ((s.usage || {}).areas || []).map(function (a) { return [a.label, mb(a.bytes)]; });
    rows.push(['このサイトの合計', mb((s.usage || {}).total || 0)]);
    add(d, el('h3', {}, 'このサイトの保存容量'), facts(rows, 'storage-site-facts'));
    var all = [['全データの合計', mb(st.total || 0)], ['ディスクの空き', st.free_bytes == null ? '—' : mb(st.free_bytes)],
               ['バックアップの数', (st.backups || 0) + '件' + (st.last_backup ? '（最新：' + st.last_backup + '）' : '')], ['バックアップの保存先', st.backup_folder || '—']];
    add(d, el('h3', {}, '全データ'), facts(all, 'storage-all-facts'));
    var nu = (s.http && s.http.notification_usage) || {};
    var note = nu.notifications || {count: 0, bytes: 0};
    add(d, el('h3', {}, '通知の履歴'),
        el('p', {'class': 'app-run-note' + (note.warn ? ' is-warn' : ''), id: 'storage-notification-usage'},
           '通知 ' + note.count + '件（' + mb(note.bytes) + '）・送信の記録 ' + ((nu.deliveries || {}).count || 0) + '件' + (note.warn ? '：増えてきました。整理をおすすめします。' : '')),
        archiveForm('notice-archive', '通知と送信の記録を別のファイルへ移すことを確認しました（削除はしません。過去の通知が、もう一度届くこともありません）', '通知の履歴を整理',
                    'archive-notifications', function (r) { return r && r.notifications && r.notifications.archived ? '通知の履歴を別ファイルへ移しました。削除はしていません。' : '移す履歴はありませんでした。'; }),
        para('app-run-note', '24時間以内の通知があるあいだは整理できません（まだ送信待ちの可能性があるため）。'));
    var status = el('p', {id: 'backup-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    var text = function (r) {
      return 'バックアップを作りました：' + r.files + 'ファイル・確認' + (r.verified ? '済み' : '：失敗（作り直してください）') + (r.skipped && r.skipped.length ? '・コピーしなかったもの ' + r.skipped.length + '件' : '')
        + (r.changed && r.changed.length ? '・コピー中に変わったもの ' + r.changed.length + '件' : '') + '（' + r.path + '）。';
    };
    var forms = el('div', {'class': 'app-run-form', id: 'backup-controls'});
    [['backup-all', '全データをバックアップ', {scope: 'all'}], ['backup-site', 'このサイトだけバックアップ', {scope: 'site', site_id: s.site_id}]].forEach(function (b) {
      var form = el('form', {'class': 'app-run-form', id: b[0] + '-form'});
      add(form, el('button', {type: 'submit', id: b[0] + '-button', 'class': 'app-run-button'}, b[1]));
      action(form, status, 'バックアップを作っています…（しばらくかかることがあります）', '/app/api/site/backup', function () { return b[2]; }, text, 'stay');
      forms.appendChild(form);
    });
    add(d, el('h3', {}, 'バックアップ'), forms, status,
        para('app-run-note', 'データフォルダの隣の新しいフォルダへ、ファイルを写して確認します。どこにも送信しません。既存のデータは削除しません。復元は手動です（確認したうえで、新しいフォルダへコピーします）。'));
    return d;
  }

  // ---- several sites: the list of all of them (「全サイトの状態」), the switcher on a site's pages
  var BASELINE_LABEL = {NONE: '未作成', AUTO: '自動作成・未確認', CONFIRMED: '自動作成・USER確認済み', USER: '正式承認済み'};
  function siteCard(o) {
    var agg = o.aggregate || null;
    var attention = agg ? agg.attention || [] : o.attention || [];
    var att = attention.length > 0, im = o.image, ht = o.http;
    var card = el('article', {'class': 'app-site-card' + (att ? ' is-attention' : (agg ? agg.state === 'OK' : im && im.kind === 'ok' && ht && ht.state === 'OK') ? ' is-ok' : ''), id: 'site-card-' + o.site_id, 'data-site': o.site_id});
    add(card, el('h3', {}, o.name), el('p', {'class': 'app-run-note'}, o.url));
    if (o.error) card.appendChild(para('app-notice is-error', 'このサイトの状態を読み取れません：' + o.error));
    var rows = [];
    if (agg) rows.push(['サイト全体の状態（' + agg.units + 'ページ）', agg.state_label + (agg.stopped ? '・停止中のページ ' + agg.stopped + 'つ' : '')]);
    if (im) {
      rows.push(['画像監視', im.label], ['最後の検査', im.last_at ? jst(im.last_at) + (im.outcome ? '・' + im.outcome : '') : 'まだありません'],
                ['次回の検査', im.enabled ? (im.running ? '検査中' : jst(im.next_due_at)) : '—（停止中）']);
    }
    if (ht && !ht.error) {
      rows.push(['HTTP監視', ht.state_label], ['最後の観測', ht.last_at ? jst(ht.last_at) + (ht.http_status ? '・HTTP ' + ht.http_status : '') : 'まだありません']);
      if (ht.not_run) rows.push(['HTTP監視の検査', '検査していません（' + (ht.not_run.message || NOT_RUN_REASON[ht.not_run.code] || '理由は画面で確認') + '）']);
    } else if (ht) {
      rows.push(['HTTP監視', '状態を読み取れません：' + ht.error]);
    }
    if (o.baseline) rows.push(['Baseline', BASELINE_LABEL[o.baseline] || o.baseline]);
    rows.push(['許可の期限', cardPermits(o)]);
    card.appendChild(facts(rows, 'site-card-facts-' + o.site_id));
    if (agg && (o.pages || []).length > 1) {  // every page with its own image / HTTP state
      var pl = el('ul', {'class': 'app-card-pages', id: 'site-card-pages-' + o.site_id});
      o.pages.forEach(function (x) {
        var line = (x.unit_label || x.label) + '：画像監視 ' + (x.image ? x.image.label : '—') + ' ／ HTTP監視 ' + (x.http && !x.http.error ? x.http.state_label : '—');
        var li = el('li', {'class': x.error ? 'is-warn' : ''});
        if (OWN_PAGE.test(x.href || '')) li.appendChild(el('a', {href: x.href}, line)); else li.appendChild(document.createTextNode(line));
        pl.appendChild(li);
      });
      card.appendChild(pl);
    }
    var need = el('div', {'class': 'app-card-attention', id: 'site-card-attention-' + o.site_id});
    if (att) {
      var ul = el('ul', {});
      attention.forEach(function (t) { ul.appendChild(el('li', {'class': 'is-warn'}, t)); });
      add(need, el('strong', {}, '確認が必要なもの'), ul);
    } else {
      need.appendChild(para('app-run-note', '確認が必要なものはありません'));
    }
    card.appendChild(need);
    var status = el('p', {'class': 'app-run-status', role: 'status', 'aria-live': 'polite', id: 'site-card-status-' + o.site_id});
    var forms = el('div', {'class': 'app-run-form'});
    if (im) {
      var f1 = el('form', {'class': 'app-run-form', id: 'site-card-image-' + o.site_id});
      var b1 = el('button', {type: 'submit', 'class': 'app-run-button'}, im.enabled ? '画像監視を停止' : '画像監視を開始');
      if (!im.enabled && !im.can_start || im.running) b1.setAttribute('disabled', '');
      add(f1, b1);
      action(f1, status, '切り替えています…', '/app/api/site/monitor', function () { return {site_id: o.site_id, unit: o.unit, enabled: !im.enabled}; }, im.enabled ? '画像監視を停止しました。' : '画像監視を開始しました。');
      forms.appendChild(f1);
      if (!im.enabled && !im.can_start && im.start_block) card.appendChild(para('app-run-note is-warn', '画像監視を開始できない理由：' + im.start_block));
    }
    if (ht && !ht.error) {
      var f2 = el('form', {'class': 'app-run-form', id: 'site-card-http-' + o.site_id});
      var b2 = el('button', {type: 'submit', 'class': 'app-run-button'}, ht.enabled ? 'HTTP監視を停止' : 'HTTP監視を開始');
      if (!ht.enabled && !ht.can_start) b2.setAttribute('disabled', '');
      add(f2, b2);
      action(f2, status, '切り替えています…', '/app/api/site/http', function () { return {site_id: o.site_id, unit: o.unit, what: ht.enabled ? 'stop' : 'start'}; }, ht.enabled ? 'HTTP監視を停止しました。' : 'HTTP監視を開始しました。');
      forms.appendChild(f2);
      if (!ht.enabled && !ht.can_start && ht.start_block) card.appendChild(para('app-run-note is-warn', 'HTTP監視を開始できない理由：' + ht.start_block));
    }
    add(card, forms, status, add(el('p', {'class': 'app-run-links'}), el('a', {href: o.href, 'class': 'app-link-button'}, 'このサイトを開く ›')));
    return card;
  }
  // The signed permits at a glance on the card: expired and near-expiry are said in words (and marked), not by colour alone.
  function cardPermits(o) {
    var parts = [];
    var pm = o.permit, g = o.http_grant;
    parts.push('画像撮影：' + (!pm ? '許可なし（未署名）' : LEVEL_MARK[permitLevel(pm)] + ' ' + (pm.state === 'EXHAUSTED' ? '回数を使い切りました' : pm.state === 'EXPIRED' ? '期限切れ'
      : 'あと' + (pm.days_left != null ? pm.days_left : '—') + '日・' + pm.remaining_runs + '回' + (pm.warning ? '（まもなく期限・回数）' : ''))));
    if (g && g.state) parts.push('HTTP監視：' + (g.state === 'VALID' ? LEVEL_MARK[grantLevel(g)] + ' あと' + (g.days_left != null ? g.days_left : '—') + '日' + (grantLevel(g) === 'warn' ? '（まもなく期限・回数）' : '')
      : g.state === 'MISSING' ? '許可なし（未署名）' : '✗ ' + (GRANT_STATE[g.state] || g.state)));
    return parts.join(' ／ ');
  }
  // The all-sites HOME is the empty export, whose header knows no site: fill "最後の監視" from the sites' own observations
  // (an image inspection that really ran, an HTTP observation) instead of leaving "未取得" next to sites that were checked.
  function sitesHeader(state) {
    var times = [];
    state.sites.forEach(function (o) {
      if (o.image && o.image.last_at && (o.runs || 0) > 0) times.push(o.image.last_at);
      [o].concat(o.pages || []).forEach(function (q) { if (q.http && q.http.last_at) times.push(q.http.last_at); });
    });
    var latest = times.sort().pop();
    var t = document.querySelector('.site-header .updated time');
    if (t) t.textContent = latest ? jst(latest) : '未取得';
    var badge = document.querySelector('.data-strip .badge');
    if (badge) badge.textContent = latest ? 'このPCの監視結果（' + state.sites.length + 'サイト）' : '監視結果は未取得です';
  }
  function sitesPanel(state) {
    var p = panel('sites-panel', '全サイトの状態', state.sites.length + 'サイト');
    p.appendChild(para('app-run-note', 'サイトごとに、画像監視とHTTP監視の状態を表示します。確認が必要なサイトを上に並べています。停止中・未観測・長期間未観測を「正常」とは表示しません。'));
    var needs = function (o) { return (o.aggregate ? (o.aggregate.attention || []).length > 0 || o.aggregate.state !== 'OK' : false); };
    var list = state.sites.slice().sort(function (a, b) { return ((b.attention || []).length > 0) - ((a.attention || []).length > 0) || needs(b) - needs(a); });
    var cards = el('div', {'class': 'app-site-cards', id: 'site-cards'});
    list.forEach(function (o) { cards.appendChild(siteCard(o)); });
    p.appendChild(cards);
    if ((state.site_problems || []).length) {
      var pl = el('ul', {id: 'site-problems'});
      state.site_problems.forEach(function (x) { pl.appendChild(el('li', {'class': 'is-warn'}, x.folder + '：' + x.reason)); });
      p.appendChild(add(el('details', {'class': 'app-ready', id: 'site-problems-details', open: ''}), el('summary', {}, '使われていないフォルダ（' + state.site_problems.length + '件）'),
                        para('app-run-note', '次のフォルダは、サイトとして使っていません（何も変更・削除していません）。'), pl));
    }
    p.appendChild(para('app-run-foot', 'データ：' + state.data));
    return p;
  }
  function switcher(state) {
    var nav = el('nav', {'class': 'app-site-switcher', id: 'site-switcher', 'aria-label': 'サイトの切り替え'});
    var sel = el('select', {id: 'site-switcher-select'});
    state.sites.forEach(function (o) {
      var opt = el('option', {value: o.href}, o.name + '（' + o.url + '）');
      if (o.site_id === state.site.site_id) opt.selected = true;
      sel.appendChild(opt);
    });
    sel.addEventListener('change', function () { if (OWN_PAGE.test(sel.value)) location.href = sel.value; });
    return add(nav, el('label', {'for': 'site-switcher-select'}, 'サイト：'), sel, document.createTextNode('　'), el('a', {href: '/'}, '‹ 全サイトの状態'));
  }
  // the pages of the site on every one of its screens: the same screen of another page (HOME, 差分レビュー, 履歴)
  function pageSwitcher(state) {
    var nav = el('nav', {'class': 'app-site-switcher app-page-switcher', id: 'page-switcher', 'aria-label': 'ページの切り替え'});
    var sub = {'/review': 'review.html', '/review.html': 'review.html', '/activity': 'activity.html', '/activity.html': 'activity.html'}[rel] || '';
    add(nav, document.createTextNode('ページ：'));
    state.site.pages.forEach(function (x) {
      if (!OWN_PAGE.test(x.href)) return;
      var link = el('a', {href: x.href + sub, 'class': 'app-page-link' + (x.current ? ' is-current' : '')}, x.label);
      if (x.current) link.setAttribute('aria-current', 'page');
      add(nav, link, document.createTextNode('　'));
    });
    return nav;
  }

  // ---- the site screen, in the order a person needs it: 1 要約  2 画像監視  3 HTTP監視  4 通知  5 所有権と許可  6 保存・導入.
  // Everything below is derived from what the server reports; a step or a permit is never shown as fine when the server did not say so.
  var LEVEL_MARK = {ok: '✓', warn: '⚠', error: '✗', none: '—'};
  var LEVEL_TEXT = {ok: '問題なし', warn: '期限・回数が近い', error: '使えません（期限切れ・回数切れなど）', none: '未設定'};
  var LEVEL_RANK = {ok: 0, none: 1, warn: 2, error: 3};
  function permitLevel(pm, notice) {  // the image permit (period, runs)
    if (!pm) return 'none';
    if (pm.expired || (notice && notice.level === 'error')) return 'error';
    return pm.warning || notice ? 'warn' : 'ok';
  }
  function grantLevel(g, notice) {  // the HTTP grant of one page
    if (!g || !g.state || g.state === 'MISSING') return 'none';
    if (g.state !== 'VALID' || (notice && notice.level === 'error')) return 'error';
    if (notice || (g.days_left != null && g.days_left <= 7) || (g.remaining != null && g.remaining <= 5)) return 'warn';
    return 'ok';
  }
  function notifyLevel(g) {  // the e-mail grant: there is no server notice for it, so the days and the count decide
    if (!g || !g.valid) return 'none';
    if ((g.days_left != null && g.days_left <= 0) || g.remaining_total === 0) return 'error';
    return (g.days_left != null && g.days_left <= 7) || (g.remaining_total != null && g.remaining_total <= 5) ? 'warn' : 'ok';
  }
  function ownershipLevel(o) {
    if (o.status === 'VERIFIED') return o.days_left != null && o.days_left <= 7 ? 'warn' : 'ok';
    return o.status === 'EXPIRED' || o.status === 'REVOKED' ? 'error' : 'none';
  }
  function permitRows(s) {
    var h = s.http || {}, n = s.notify || {}, o = s.ownership || {status: 'NONE'}, g = h.grant || {}, ng = n.grant || {}, pm = s.permit, top = s.unit === s.site_id;
    var ownState = OWNERSHIP_STATUS[o.status] || [o.status, ''];
    var days = function (d) { return d == null ? '' : d > 0 ? '（あと' + d + '日）' : '（期限を過ぎています）'; };
    return [
      {key: 'ownership', label: '所有権の確認（このサイトのホスト）', level: ownershipLevel(o), state: ownState[0] + (o.method ? '（' + (OWNERSHIP_METHOD[o.method] || o.method) + '）' : ''),
       until: o.valid_until ? jst(o.valid_until) + days(o.days_left) : '—', left: '—', extra: '画像撮影・HTTP監視の前提です'},
      {key: 'image', label: '画像撮影の許可（トップページ）', level: top ? permitLevel(pm, s.permit_notice) : 'none',
       state: !top ? 'このページは画像撮影の対象外です' : !pm ? '未署名（許可がありません）' : ({ACTIVE: '有効', EXHAUSTED: '回数を使い切りました', EXPIRED: '期限切れ'}[pm.state] || pm.state),
       until: top && pm ? jst(pm.valid_until) + days(pm.days_left) : '—', left: top && pm ? pm.remaining_runs + '回' : '—', extra: '回数は撮影ごとに減ります'},
      {key: 'http', label: 'HTTP監視の許可（このページ）', level: grantLevel(g, h.grant_notice), state: GRANT_STATE[g.state] || g.state || '—',
       until: g.valid_until ? jst(g.valid_until) + days(g.days_left) : '—', left: g.valid_until ? (g.used == null ? '読み取れません' : g.remaining + ' / ' + g.max_requests + '回') : '—',
       extra: g.valid_until ? (PURPOSE[g.purpose] || g.purpose || '—') + '・許可の最短間隔 ' + (g.min_interval_seconds != null ? g.min_interval_seconds + '秒' : '—') + (h.interval_label ? '・いまの間隔 ' + h.interval_label : '') : '署名すると、期間・回数・間隔がここに出ます'},
      {key: 'notify', label: 'メール通知の許可（サイト共通）', level: notifyLevel(ng), state: ng.valid ? '有効' : '使えません（署名がない、または無効）',
       until: ng.valid ? jst(ng.valid_until) + days(ng.days_left) : '—', left: ng.valid ? (ng.remaining_total == null ? '—' : '合計あと' + ng.remaining_total + '通・今日あと' + ng.remaining_today + '通') : '—',
       extra: ng.valid ? '宛先 ' + (ng.recipients || []).length + '件' : '署名しない限り、メールは送りません'}];
  }
  function worstLevel(rows) {
    return rows.reduce(function (w, r) { return LEVEL_RANK[r.level] > LEVEL_RANK[w] ? r.level : w; }, 'ok');
  }
  function groupHeading(id, text) {
    return el('h2', {'class': 'app-group', id: id}, text);
  }
  // A link inside the page that also opens the folds on the way and moves the focus (keyboard users land on the panel).
  function jump(id, text) {
    var a = el('a', {href: '#' + id, 'class': 'app-jump'}, text);
    a.addEventListener('click', function (event) {
      var target = document.getElementById(id);
      if (!target) return;
      event.preventDefault();
      for (var n = target; n; n = n.parentElement) if (n.tagName === 'DETAILS') n.open = true;
      target.scrollIntoView({block: 'start'});
      target.setAttribute('tabindex', '-1');
      target.focus({preventScroll: true});
    });
    return a;
  }
  function captureText(s) {
    return s.display === 'REAL_MONITORING' ? '実サイト（承認済みの撮影ハーネス・隔離環境）' : s.fixture_capture && s.mode !== 'REAL' ? 'オフラインfixture（テスト用の合成画像）'
      : '準備待ち（条件が整うまで撮影しません。合成画像も作りません）';
  }
  // One line while HTTP / メール / DNS確認 are switched off in the program: which ones, and that they send and ask nothing. Not an alarm.
  function externalBanner(s) {
    var h = s.http, n = s.notify, o = s.ownership;
    var off = [['HTTP監視', h && !h.error ? h.external_enabled : null], ['メール', n && !n.error ? n.external_enabled : null], ['DNS確認', o ? o.dns_check_enabled : null]]
      .filter(function (x) { return x[1] === false; }).map(function (x) { return x[0]; });
    if (!off.length) return null;
    return el('p', {'class': 'app-run-note app-external', id: 'external-panel'}, '外部への通信：' + off.join('・') + 'は無効です。無効なものは、何も送信・問い合わせしていません'
      + '（有効にするには、実環境での確認とあなたの承認が必要です）。画像の撮影は、署名付きの許可がそろったときだけ行います。');
  }
  function overviewItem(label, anchor, level, text) {
    return add(el('li', {'class': 'app-overview-' + level}), el('strong', {}, label), document.createTextNode('：' + LEVEL_MARK[level] + ' ' + text + '　'), jump(anchor, '詳しく ›'));
  }
  function summaryPanel(state) {
    var s = state.site, h = s.http || {}, n = s.notify || {}, m = s.monitor, mv = s.monitor_view || {};
    var p = panel('site-overview', '要約：' + s.name, kindsLabel(s));
    p.appendChild(para('app-run-note', s.url + ' ／ ' + s.kinds.join('・') + ' ／ 撮影：' + captureText(s)));
    p.appendChild(summaryBar(s, state));
    var banner = externalBanner(s);
    if (banner) p.appendChild(banner);
    var last = m.last;
    var httpText = h.error ? '状態を読み取れません' : h.not_run ? '検査していません（' + (h.not_run.message || NOT_RUN_REASON[h.not_run.code] || '理由は下の画面') + '）' : (h.state_label || '—');
    var worst = worstLevel(permitRows(s));
    var list = add(el('ul', {id: 'site-overview-list', 'class': 'app-overview'}),
      overviewItem('画像監視', 'site-panel', {ok: 'ok', info: 'ok', warn: 'warn', error: 'error'}[mv.kind] || 'none', (mv.label || '—') + (last ? '・最後の結果：' + s.outcomes[last.outcome] : '')),
      overviewItem('HTTP監視', 'http-panel', h.error ? 'error' : h.not_run ? 'warn' : h.state === 'OK' ? 'ok' : h.state === 'DOWN' || h.state === 'UNKNOWN' || h.state === 'STALE' ? 'warn' : 'none', httpText),
      overviewItem('通知', 'notify-panel', n.error ? 'error' : n.active ? 'ok' : 'none', n.error ? '状態を読み取れません' : (n.active ? 'メールは有効' : 'メールは無効（画面への通知は常に記録）') + '・最近の通知 ' + (s.notice_history || []).length + '件'),
      overviewItem('許可の期限', 'permits-panel', worst, worst === 'ok' ? '期限・回数に問題はありません' : LEVEL_TEXT[worst] + '（所有権・画像撮影・HTTP監視・メールの一覧で確認）'));
    p.appendChild(list);
    return p;
  }
  // ---- 5. 所有権と許可: one compact table (ownership, image permit, the HTTP grant of THIS page, the e-mail grant) with the level in words and a mark
  function permitsPanel(state) {
    var s = state.site, rows = permitRows(s), worst = worstLevel(rows);
    var p = panel('permits-panel', '所有権と許可の一覧', LEVEL_MARK[worst] + ' ' + LEVEL_TEXT[worst]);
    p.appendChild(para('app-run-note', 'あなたが署名した許可と、所有権の確認の、期間・残り・間隔をまとめて見る一覧です（この一覧は読むだけで、署名はしません）。許可は、サイト・ページごとに別々です。'));
    var table = el('table', {'class': 'app-table', id: 'permits-table'});
    add(table, el('caption', {'class': 'app-sr-only'}, '所有権と許可の一覧'));
    var head = el('tr', {});
    ['種類', '状態', '期限', '残り', '間隔・目的・備考'].forEach(function (t) { head.appendChild(el('th', {scope: 'col'}, t)); });
    table.appendChild(add(el('thead', {}), head));
    var body = el('tbody', {});
    rows.forEach(function (r) {
      var tr = el('tr', {'class': 'app-level-' + r.level, id: 'permit-row-' + r.key, 'data-level': r.level});
      add(tr, el('th', {scope: 'row', 'data-label': '種類'}, r.label), el('td', {'data-label': '状態'}, LEVEL_MARK[r.level] + ' ' + r.state + (r.level === 'warn' ? '（' + LEVEL_TEXT.warn + '）' : '')),
          el('td', {'data-label': '期限'}, r.until), el('td', {'data-label': '残り'}, r.left), el('td', {'data-label': '間隔・目的・備考'}, r.extra));
      body.appendChild(tr);
    });
    table.appendChild(body);
    p.appendChild(add(el('div', {'class': 'app-table-wrap'}), table));
    var h = s.http || {}, n = (s.notify || {}).grant || {};
    var texts = [s.permit_notice, h.grant_notice].filter(Boolean).map(function (x) { return [x.level, x.text]; });
    if (n.valid && n.days_left != null && n.days_left <= 7) texts.push(['warn', 'メール通知の許可は、あと' + n.days_left + '日で期限です。tools/notify_grant.py で許可を作り直して（署名して）ください。']);
    if (s.ownership && s.ownership.guidance && s.ownership.status !== 'VERIFIED') texts.push(['warn', s.ownership.guidance]);
    if (texts.length) {
      var ul = el('ul', {id: 'permits-notices'});
      texts.forEach(function (x) { ul.appendChild(el('li', {'class': x[0] === 'error' ? 'is-error' : 'is-warn'}, (x[0] === 'error' ? '✗ ' : '⚠ ') + x[1])); });
      p.appendChild(ul);
    }
    return p;
  }
  // ---- 4. 通知: the last notices of this page, filtered by kind in the browser; the delivery wording comes from the server (it never says "received")
  var SEVERITY_TEXT = {critical: ['✗', '重大', 'is-error'], warn: ['⚠', '注意', 'is-warn'], info: ['✓', '情報', 'is-ok']};
  function noticeHistoryPanel(state) {
    var list = state.site.notice_history || [];
    var p = panel('notice-history-panel', '通知の履歴（このページ）', list.length + '件');
    var wrap = el('div', {id: 'notice-history'});
    p.appendChild(para('app-run-note', 'このページの最近の通知です。同じ異常が続く間は、通知を繰り返しません。「送信先へ引き渡し済み（受信は未確認）」「送信受付済み（受信は未確認）」は、受け付けられたという意味で、受信を保証しません。'));
    if (!list.length) {
      wrap.appendChild(para('app-run-note', 'まだ通知はありません。'));
      p.appendChild(wrap);
      return p;
    }
    var kinds = {};
    list.forEach(function (x) { kinds[x.kind] = x.kind_label; });
    var sel = el('select', {id: 'notice-filter'});
    sel.appendChild(el('option', {value: ''}, 'すべての種類'));
    Object.keys(kinds).forEach(function (k) { sel.appendChild(el('option', {value: k}, kinds[k])); });
    var count = el('p', {id: 'notice-filter-count', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'}, list.length + '件を表示');
    var ul = el('ul', {id: 'http-notifications'});
    list.forEach(function (x) {
      var sv = SEVERITY_TEXT[x.severity] || SEVERITY_TEXT.info;
      ul.appendChild(el('li', {'class': sv[2], 'data-kind': x.kind}, sv[0] + ' ' + sv[1] + '　' + jst(x.at) + '　' + x.title + '（' + x.delivery_label + '）'));
    });
    sel.addEventListener('change', function () {
      var shown = 0;
      Array.prototype.forEach.call(ul.children, function (li) {
        li.hidden = !!sel.value && li.getAttribute('data-kind') !== sel.value;
        if (!li.hidden) shown++;
      });
      count.textContent = shown + '件を表示' + (sel.value ? '（' + kinds[sel.value] + '）' : '');
    });
    add(wrap, add(el('div', {'class': 'app-run-form'}), el('label', {'for': 'notice-filter'}, '種類で絞り込む'), sel), count, ul);
    p.appendChild(wrap);
    return p;
  }
  // ---- 1. はじめの手順: a checklist made from what the server reports (環境 → サイト登録 → 所有権 → 許可の署名 → 監視の開始 → アプリを閉じても監視 → メール). Dismissible per viewer.
  var STEPS_KEY = 'siteproof-first-steps-hidden';
  function stepsHidden() {
    try { return window.localStorage.getItem(STEPS_KEY) === '1'; } catch (e) { return false; }
  }
  function rememberStepsHidden(hidden) {
    try { if (hidden) window.localStorage.setItem(STEPS_KEY, '1'); else window.localStorage.removeItem(STEPS_KEY); } catch (e) { /* storage may be blocked: it then only holds for this view */ }
  }
  function firstSteps(s) {
    var m = s.monitor, pm = s.permit, n = s.notify || {}, o = s.ownership || {}, top = s.unit === s.site_id;
    var env = (s.readiness || []).filter(function (r) { return r.key === 'environment'; })[0];
    var mv = s.monitor_view || {};
    return [
      {key: 'environment', name: '導入環境', done: !!(env && env.ok), skip: false, text: '「導入環境の確認」で、足りないものを確認します' + (env && !env.ok ? '（いまの確認：' + env.state + '）' : ''), link: 'environment-panel'},
      {key: 'site', name: 'サイト登録', done: !!s.site_id, skip: false, text: 'サイトを登録します', link: 'site-overview'},
      {key: 'ownership', name: '所有権の確認', done: o.status === 'VERIFIED', skip: false, text: 'DNSのTXTレコード（またはworkers.devのCloudflare確認）で、自分のサイトであることを確認します', link: 'ownership-panel'},
      {key: 'permit', name: '許可の署名', done: top && !!pm && !pm.expired, skip: !top, skipText: '画像撮影の許可はトップページだけの設定です（このページは対象外）',
       text: pm && pm.expired ? '許可が切れています。「監視設定を更新」で署名し直します' : '「初回セットアップ」で、許可の内容を確認して自分の鍵で署名します', link: 'site-readiness'},
      {key: 'monitor', name: '監視の開始', done: !!m.enabled, skip: false, text: '「監視を開始」を押します' + (mv.start_block && !m.enabled ? '（いまは開始できません：' + mv.start_block + '）' : ''), link: 'site-control'},
      {key: 'background', name: 'アプリを閉じても監視', done: s.background === true, skip: !m.enabled || s.background === null,
       skipText: s.background === null ? 'Windowsのタスクに問い合わせられないため、確認できません' : '監視を始めてから、必要なら設定します（任意）', text: '必要なら「アプリを閉じても監視する」を押します（任意）', link: 'site-background'},
      {key: 'mail', name: 'メール通知', done: !!n.active, skip: true, skipText: '任意です。使うときだけ、許可の署名と有効化を行います', text: '', link: 'notify-panel'}];
  }
  // before any site is registered: only what comes first can be next; nothing is claimed as done
  function firstStepsEmpty() {
    var later = function (key, name) { return {key: key, name: name, done: false, skip: true, skipText: 'サイトを登録したあとに案内します', text: '', link: ''}; };
    return [{key: 'environment', name: '導入環境', done: false, skip: false, text: '「導入環境の確認」を開いて、足りないものを確認します', link: 'environment-panel'},
            {key: 'site', name: 'サイト登録', done: false, skip: false, text: '「サイトを追加」から、自分が管理するサイトを登録します', link: 'site-add'},
            later('ownership', '所有権の確認'), later('permit', '許可の署名'), later('monitor', '監視の開始'), later('background', 'アプリを閉じても監視'), later('mail', 'メール通知')];
  }
  function firstStepsPanel(state) {
    var steps = state.site ? firstSteps(state.site) : firstStepsEmpty();
    var need = steps.filter(function (x) { return !x.done && !x.skip; }).length;
    var p = panel('first-steps', 'はじめの手順（導入のチェックリスト）', need ? 'あと' + need + '件' : 'すべて済み');
    var list = el('ol', {id: 'first-steps-list', 'class': 'app-steps-list'});
    steps.forEach(function (x) {
      var li = el('li', {'class': x.done ? 'is-done' : x.skip ? 'is-skip' : 'is-next', 'data-step': x.key, 'data-state': x.done ? 'done' : x.skip ? 'skip' : 'next'});
      add(li, el('strong', {}, x.name), document.createTextNode('　' + (x.done ? '✓ 済み' : x.skip ? '— 不要・必要なときだけ：' + x.skipText : '→ 次にすること：' + x.text) + '　'));
      if (!x.done && !x.skip) li.appendChild(jump(x.link, '開く ›'));
      list.appendChild(li);
    });
    var hidden = stepsHidden();
    list.hidden = hidden;
    var toggle = el('button', {type: 'button', id: 'first-steps-toggle', 'class': 'app-run-button', 'aria-controls': 'first-steps-list', 'aria-expanded': String(!hidden)}, hidden ? '手順を表示する' : 'この手順を閉じる');
    toggle.addEventListener('click', function () {
      var now = !list.hidden;
      list.hidden = now;
      rememberStepsHidden(now);
      toggle.textContent = now ? '手順を表示する' : 'この手順を閉じる';
      toggle.setAttribute('aria-expanded', String(!now));
    });
    add(p, para('app-run-note', 'サーバーが確認できたことだけで「済み」を表示します。確認できないものは、済みにしません。閉じても、この画面だけの設定です（何も変更しません）。'), list, toggle);
    return p;
  }
  // ---- 6. 導入環境の確認: loaded only when it is opened (the same read-only report as tools/doctor.py)
  var ENV_MARK = {OK: '✓ OK', MISSING: '✗ ない', WARN: '⚠ 注意', UNKNOWN: '？ 不明'};
  function environmentPanel(state) {
    var d = el('details', {'class': 'app-ready', id: 'environment-panel'});
    add(d, el('summary', {}, '導入環境の確認'));
    var body = el('div', {id: 'environment-body'});
    var status = el('p', {id: 'environment-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(body, para('app-run-note', 'このPCに、SiteProofを動かすものが揃っているかを、読み取りだけで確認します（何も起動・インストール・登録・変更しません）。開くと確認を始めます。結果は1分ほど使い回します。'));
    var table = el('div', {id: 'environment-result'});
    var again = el('button', {type: 'button', id: 'environment-again', 'class': 'app-run-button'}, 'もう一度確認');
    var loaded = false;
    function show(result) {
      while (table.firstChild) table.removeChild(table.firstChild);
      var t = el('table', {'class': 'app-table', id: 'environment-table'});
      add(t, el('caption', {'class': 'app-sr-only'}, '導入環境の確認結果'));
      var head = el('tr', {});
      ['項目', '結果', '内容', '次にすること'].forEach(function (x) { head.appendChild(el('th', {scope: 'col'}, x)); });
      t.appendChild(add(el('thead', {}), head));
      var tb = el('tbody', {});
      result.items.forEach(function (i) {
        add(tb, add(el('tr', {'class': 'app-env-' + i.status.toLowerCase(), 'data-key': i.key}), el('th', {scope: 'row', 'data-label': '項目'}, i.label), el('td', {'data-label': '結果'}, ENV_MARK[i.status] || i.status),
                    el('td', {'data-label': '内容'}, i.detail), el('td', {'data-label': '次にすること'}, i.next || '—')));
      });
      t.appendChild(tb);
      var c = result.counts;
      add(table, para('app-run-note', 'OK ' + c.OK + '・ない ' + c.MISSING + '・注意 ' + c.WARN + '・不明 ' + c.UNKNOWN + '（確認した時刻：' + jst(result.checked_at) + '）'), add(el('div', {'class': 'app-table-wrap'}), t));
    }
    async function load() {
      again.disabled = true;
      status.classList.remove('is-error');
      status.textContent = '⏳ 確認しています…（Dockerの確認に数秒かかることがあります）';
      try {
        show(await read('/app/api/environment'));
        loaded = true;
        status.textContent = '✓ 確認しました（読み取りだけです）';
      } catch (error) {
        status.classList.add('is-error');
        status.textContent = '✗ 確認できませんでした：' + error.message;
      }
      again.disabled = false;
    }
    again.addEventListener('click', load);
    d.addEventListener('toggle', function () { if (d.open && !loaded && !again.disabled) load(); });
    add(body, status, table, again);
    d.appendChild(body);
    return d;
  }
  function siteScreen(state) {
    return [groupHeading('group-summary', '1. 要約'), summaryPanel(state), firstStepsPanel(state), pagesPanel(state),
            groupHeading('group-image', '2. 画像監視（画面の見た目の変化）'), sitePanel(state),
            groupHeading('group-http', '3. HTTP監視（サイトの死活）'), httpPanel(state),
            groupHeading('group-notify', '4. 通知'), notifyPanel(state), noticeHistoryPanel(state),
            groupHeading('group-permits', '5. 所有権と許可'), permitsPanel(state), ownershipPanel(state),
            groupHeading('group-storage', '6. 保存・導入'), storagePanel(state), environmentPanel(state)];
  }

  // ---- 3. the synthetic demo inspection
  function demoPanel(state) {
    var p = panel('app-run', 'オフライン検査（合成デモ）', '合成fixture・外部通信なし');
    p.appendChild(para('app-run-note', 'Tokyo Trouble Navi / トップページを模した合成画像と、承認済みBaseline（合成）を、製品と同じ処理（撮影Job → 証拠保存 → 比較）で検査します。'
      + 'Desktop と Mobile の2件を実行し、結果は保存されて差分レビューと履歴に表示されます。実サイトにはアクセスしません。'));
    var form = el('form', {'class': 'app-run-form', id: 'app-run-form'});
    var select = el('select', {id: 'app-run-fixture', name: 'fixture'});
    Object.keys(state.fixtures).forEach(function (key) { select.appendChild(el('option', {value: key}, state.fixtures[key])); });
    add(form, el('label', {'for': 'app-run-fixture'}, '検査する画像'), select, el('button', {type: 'submit', id: 'app-run-button', 'class': 'app-run-button'}, '検査を開始'));
    var status = el('p', {id: 'app-run-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(p, form, status, add(el('p', {'class': 'app-run-links'}), el('a', {href: 'review.html'}, '差分レビューで確認 ›'), document.createTextNode('　'),
        el('a', {href: 'activity.html'}, '履歴・通知を見る ›')),
        para('app-run-foot', '保存済みの検査：' + state.runs + '件 ／ データ：' + state.data));
    if (state.site) p.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: '/'}, '‹ 監視中のサイト（' + state.site.name + '）に戻る')));
    if (state.running) status.textContent = '検査を実行中です…（別の画面で開始された検査）';
    else if (state.error) { status.textContent = '検査に失敗しました：' + state.error; status.classList.add('is-error'); }
    else if (state.last) status.textContent = '前回の検査（' + state.last.finished_at + '）：' + describe(state.last.profiles);
    else status.textContent = 'まだ検査していません。画像を選んで「検査を開始」を押してください。';
    action(form, status, '検査を実行中です…（Desktop・Mobile、30秒ほどかかります）', '/app/api/run', function () { return {fixture: select.value}; },
           function (r) { return '検査が完了しました：' + describe(r.profiles) + '。'; });
    return p;
  }

  // HOME follows the monitor by itself: reload when an inspection finishes or starts, unless the user is typing / a menu is open.
  function watch(state) {
    var siteKey = function (s) {
      var h = s.http || {}, n = s.notify || {}, last = n.last_result || {};
      return [s.runs, s.monitor.running, (s.monitor.last || {}).finished_at, s.monitor.enabled, (s.setup || {}).state, (s.setup || {}).at,
              (s.permit || {}).permit_id, (s.monitor_view || {}).state, s.readiness.filter(function (r) { return r.ok; }).length, s.background, s.background_http, s.display,
              h.last_at, h.state, h.enabled, h.paused_reason, (h.grant || {}).state, n.enabled, n.site_enabled, n.active, last.at, last.result,
              (s.pages || []).length, (s.ownership || {}).status, (h.not_run || {}).at, (s.notice_history || []).length].join('|');  // also: setup progress, a new permit, the HTTP and e-mail state, pages, ownership
    };
    var listKey = function (sites) {  // all sites at a glance: only what the cards show
      return (sites || []).map(function (o) {
        var i = o.image || {}, h = o.http || {};
        return [o.site_id, i.state, i.last_at, i.enabled, h.state, h.last_at, h.enabled, (o.attention || []).length, o.error || '', (o.aggregate || {}).state,
                (o.pages || []).map(function (x) { return [x.unit, x.state, (x.image || {}).last_at, (x.http || {}).last_at].join(':'); }).join('+')].join(',');
      }).join(';');
    };
    var key = function (st) { return st.site ? siteKey(st.site) : listKey(st.sites); };
    var seen = key(state);
    setInterval(async function () {
      var busy = document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
      // an opened fold, a half-filled form or a request in flight must not be wiped by a reload
      var open = document.querySelector('#site-aux[open], #storage-panel[open], #environment-panel[open], #site-add-more[open], #page-add-more[open], #http-maintenance[open], #notify-setup[open], #site-add-form:not([hidden]), form[aria-busy]');
      try {
        var now = key(await session());
        if (now !== seen && !busy && !open) location.reload();
      } catch (e) { /* the app was stopped: keep the page */ }
    }, 3000);
  }

  function pausedWhy(reason) {
    if (!reason) return '';
    var map = {RESTORED: 'バックアップから復元したコピーのため停止', ON_HOLD: 'Baselineの判断待ち', COMPLETE: '予定した検査を完了', 'DECISION:BASELINE_CREATED': 'Baselineの正式承認待ち', 'DECISION:CHANGED': '変更の確認待ち',
               DISK_FULL: '保存容量の上限'};
    return '（' + (map[reason] || (reason.indexOf('ANOMALY:') === 0 ? '異常のため停止：' + reason.slice(8) : reason)) + '）';
  }

  function versionText(v) {
    var kinds = v ? Object.keys(v) : [];
    return kinds.length ? '・' + kinds.map(function (k) { return k + ' v' + v[k]; }).join(' / ') : '';
  }

  // REVIEW: the USER's two explicit decisions, as two clearly different sections.
  //   1. 初回Baselineを承認する      -- the automatic first Baseline, approved AS IT IS (version unchanged)
  //   2. 変更を確認してBaselineを更新する -- a detected change becomes the next version
  // Both need the checkbox, the session token and the exact Baseline on screen; nothing here approves by itself.
  function decision(id, title, lead, checkText, buttonText, route, body, doneText) {
    var sec = el('section', {'class': 'app-decision', id: id, 'aria-labelledby': id + '-title'});
    add(sec, el('h3', {id: id + '-title'}, title), para('app-decision-lead', lead));
    var form = el('form', {'class': 'app-run-form app-decision-form', id: id + '-form'});
    var ok = el('input', {type: 'checkbox', id: id + '-ok', 'class': 'app-bigcheck'});
    var button = el('button', {type: 'submit', id: id + '-button', 'class': 'app-run-button app-primary', disabled: ''}, buttonText);
    ok.addEventListener('change', function () { if (ok.checked) button.removeAttribute('disabled'); else button.setAttribute('disabled', ''); });
    var status = el('p', {id: id + '-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
    add(form, add(el('label', {'class': 'app-bigcheck-label', 'for': id + '-ok'}), ok, el('span', {}, checkText)), button,
        para('app-run-note', 'チェックを入れると、ボタンが押せるようになります。'));
    action(form, status, '承認しています…', route, function () { return body(ok.checked); }, doneText);
    add(sec, form, status);
    return sec;
  }
  function updatePanel(state) {
    var s = state.site, bu = s.baseline_update || {};
    var p = el('section', {'class': 'app-run app-update', id: 'baseline-update-panel', 'aria-labelledby': 'baseline-panel-title'});
    add(p, el('h2', {id: 'baseline-panel-title'}, 'Baselineの承認'));
    var NAME = {NONE: 'なし', AUTO: '自動作成・未確認', CONFIRMED: '自動作成・USER確認済み', USER: '正式承認済み'};
    add(p, para('app-run-note', '現在のBaseline：' + NAME[s.baseline.state] + versionText(s.baseline.versions) + '（作成 ' + jst(s.baseline.approved_at) + '）。過去のBaselineは履歴として保存され、削除しません。'));
    var targets = s.baseline.targets;  // present only while the Baseline is automatic: the USER may approve exactly this one, as it is
    var shown = false;
    if (targets && bu.state !== 'SWITCH_PENDING') {
      var list = Object.keys(targets).map(function (k) { return k + ' v' + targets[k].version + '（候補ID ' + targets[k].candidate_id.slice(0, 22) + '… ／ 画像 ' + targets[k].png_sha256.slice(0, 12) + '…）'; }).join(' ／ ');
      add(p, decision('baseline-approve', '初回Baselineを承認する',
        'このBaselineはSiteProofが最初の撮影から自動作成したもので、正式な承認ではありません（確認済みでも同じです）。上の「撮影画像」が、いまの基準です。対象：' + list,
        '上の画像を確認しました。このBaselineを、そのまま（バージョンは変わりません）正式に承認します。', 'このBaselineを正式承認', '/app/api/site/baseline-approve',
        function (checked) { return {confirmed: checked, expected: targets}; }, 'このBaselineを正式承認しました。'));
      shown = true;
    }
    if (bu.state === 'SWITCH_PENDING') {  // approved, but the switch did not finish: not a success, not lost
      add(p, para('app-notice is-error', bu.reason));
      var retry = el('form', {'class': 'app-run-form', id: 'baseline-switch-form'});
      var rstatus = el('p', {id: 'baseline-switch-status', 'class': 'app-run-status', role: 'status', 'aria-live': 'polite'});
      add(retry, el('button', {type: 'submit', id: 'baseline-switch-button', 'class': 'app-run-button app-primary'}, '切替を完了する'));
      action(retry, rstatus, '切替を完了しています…', '/app/api/site/baseline-update', function () { return {run_id: bu.run_id, expected_versions: bu.versions, confirmed: true}; },
             function (r) { return '切替を完了しました（Baseline ' + versionText(r.versions).replace('・', '') + '）。'; });
      add(p, retry, rstatus);
      return p;
    }
    if (bu.state === 'AVAILABLE') {
      var changed = Object.keys(bu.profiles).map(function (k) { return k + '：' + (bu.profiles[k].image_label || bu.profiles[k].verdict); }).join(' ／ ');
      var next = Object.keys(bu.versions).map(function (k) { return k + ' v' + bu.versions[k] + ' → v' + (bu.versions[k] + 1); }).join(' ／ ');
      add(p, decision('baseline-update', '変更を確認してBaselineを更新する',
        '変更を検知しました（' + changed + '）。上の「Baselineとの比較」で、旧Baseline・今回の撮影・差分画像を確認してください。承認すると、今回の撮影が次のバージョンのBaselineになります（' + next + '）。旧版は履歴に残ります。承認するまで、これまでのBaselineで監視を続けます。',
        '差分を確認しました。今回の撮影を新しいBaselineとして正式に承認します。', '新しい基準にする', '/app/api/site/baseline-update',
        function (checked) { return {run_id: bu.run_id, expected_versions: bu.versions, confirmed: checked}; },
        function (r) { return '新しいBaseline（' + versionText(r.versions).replace('・', '') + '）を承認し、切替を完了しました。次回の検査から使います。'; }));
      shown = true;
    } else if (bu.state === 'BLOCKED') {
      add(p, para('app-notice is-warn', bu.reason));
    } else if (!shown) {
      add(p, para('app-run-note', '変更を検知した検査の後に、ここから「新しい基準にする」ことができます。いま承認が必要なものはありません。'));
    }
    return p;
  }

  function withSwitcher(state, main) {  // several sites: a compact way to move between them on every page of a site
    if (state.site && (state.site.pages || []).length > 1) main.insertBefore(pageSwitcher(state), main.firstChild);
    if (state.site && (state.sites || []).length > 1) main.insertBefore(switcher(state), main.firstChild);
  }
  function render(state) {
    var main = document.getElementById('main');
    if (state.site) { pageSite = state.site.site_id; pageUnit = state.site.unit || state.site.site_id; }
    var several = (state.sites || []).length > 1 && !state.site;
    if (main && !isDemo && !isHome && state.site && /^\/review(\.html)?$/.test(rel)) {
      // right under the comparison (Baseline / this capture / difference) the USER is asked to look at
      var body = document.getElementById('review-compare-body');
      if (body) body.parentNode.insertBefore(updatePanel(state), body.nextSibling); else main.appendChild(updatePanel(state));
      var bu0 = state.site.baseline_update || {};
      var need = state.site.baseline.targets ? '初回Baselineの承認が必要です' : bu0.state === 'AVAILABLE' ? '変更の確認とBaselineの更新が必要です' : bu0.state === 'SWITCH_PENDING' ? 'Baselineの切替が未完了です' : '';
      var layout = document.getElementById('review-app');
      if (need && layout) layout.parentNode.insertBefore(add(el('p', {'class': 'app-notice is-warn', id: 'review-action-needed'}, need + '。'), el('a', {href: '#baseline-update-panel'}, '　承認の操作へ移動 ›')), layout);
      withSwitcher(state, main);
      return;
    }
    if (main && !isDemo && !isHome && state.site && /^\/(activity|details)(\.html)?$/.test(rel)) { main.insertBefore(httpPanel(state), main.firstChild); withSwitcher(state, main); return; }
    if (!main || !isHome || !document.body.classList.contains('dashboard-home')) return;
    var panels = isDemo ? [demoPanel(state)] : state.site ? siteScreen(state)
      : several ? [sitesPanel(state), addSitePanel(state)] : [firstStepsPanel(state), addSitePanel(state), environmentPanel(state)];
    if (!isDemo && (state.site || several)) document.body.classList.add('app-user-site');
    if (several) { document.body.classList.add('app-all-sites'); sitesHeader(state); }
    panels.reverse().forEach(function (p) { main.insertBefore(p, main.firstChild); });
    if (!isDemo) withSwitcher(state, main);
    if (!isDemo && (state.site || several)) watch(state);
  }

  async function start() {
    try { render(await session()); } catch (error) { /* not served by the app: leave the page exactly as exported */ }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
