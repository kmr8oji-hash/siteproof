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
  var isDemo = path === '/demo/' || path.indexOf('/demo/') === 0;
  var isHome = ['/', '/index.html', '/demo/', '/demo/index.html'].indexOf(path) >= 0;

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

  async function session() {
    var res = await fetch('/app/api/session', {headers: {'X-SiteProof-App': '1'}, cache: 'no-store'});
    if (!res.ok) throw new Error('session ' + res.status);
    return res.json();
  }
  async function post(route, body) {
    var fresh = await session();
    var res = await fetch(route, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-SiteProof-App': '1'},
      body: JSON.stringify(Object.assign({token: fresh.token}, body))});
    var data = await res.json();
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data.result;
  }
  // Run one action from a form: disable it, show progress, reload on success, show the reason on failure.
  // Feedback is always one of three, in the status line next to the button: working, done (only after the SERVER answered success), failed with the
  // server's reason. One request at a time: the controls stay disabled while it runs and after a success (until the reload).
  function action(form, status, busyText, route, body, doneText) {
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
        status.textContent = '✓ ' + (typeof doneText === 'function' ? doneText(result) : doneText) + '画面を更新します…';
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
      var quality = p.quality_label || (p.verdict === 'UNKNOWN' ? '検査品質：判定不能（' + (reasons.join('／') || '理由不明') + '）' : '検査品質：問題なし');
      return kind + '：' + (VERDICT[p.verdict] || p.verdict) + (image ? '（' + image + '／' + quality + '）' : (reasons.length ? '・' + reasons.join('・') : ''));
    }).join(' ／ ');
  }

  // ---- 1. no site yet: サイトを追加
  function addSitePanel(state) {
    var p = panel('site-add', 'サイトを追加', '最初にここから');
    p.appendChild(para('app-run-note', '監視したい自分のWebサイトを登録します。実サイト監視の条件（所有権の確認・監視の許可・撮影環境など）が整うと、SiteProofが自動で初回撮影・Baseline作成・定期撮影・比較を行います。登録できるのは1サイト・1ページです。'));
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
        para('app-run-note', '所有権の確認：自己申告だけでは実サイトを撮影しません。実サイトの監視には、サイトに確認用ファイルを置く方法、DNS、またはworkers.devのサイトに限りCloudflareアカウントの管理権限で所有権を確認した記録が必要です（登録後にHOMEで案内します）。'),
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
    }, '登録しました。');
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

  function cell(label, value, cls, id) {
    return add(el('div', {'class': 'app-stat ' + (cls || ''), id: id || null}), el('span', {'class': 'app-stat-label'}, label), el('strong', {}, value));
  }
  function sitePanel(state) {
    var s = state.site, m = s.monitor;
    var d = DISPLAY[s.display] || [s.display, ''];
    if (s.display === 'EXPIRED' && s.permit && s.permit.state === 'EXHAUSTED') d = ['許可回数を使い切りました（更新が必要）', 'is-bad'];  // the period is still open
    if (s.monitor_view) d = [s.monitor_view.label, {ok: 'is-on', info: 'is-on', warn: 'is-off', error: 'is-bad'}[s.monitor_view.kind] || ''];
    var p = panel('site-panel', s.name, d[0]);
    p.querySelector('.app-run-tag').classList.add(d[1]);
    p.querySelector('.app-run-tag').id = 'site-display';
    p.appendChild(para('app-run-note', s.url + ' ／ ' + s.kinds.join('・') + ' ／ 撮影：'
      + (s.display === 'REAL_MONITORING' ? '実サイト（承認済みの撮影ハーネス・隔離環境）' : s.fixture_capture && s.mode !== 'REAL' ? 'オフラインfixture（テスト用の合成画像）'
         : '準備待ち（条件が整うまで撮影しません。合成画像も作りません）')));
    p.appendChild(summaryBar(s, state));
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
    if (!s.real_capture_available || renew) {
      var sf = el('form', {'class': 'app-run-form app-setup-form', id: 'site-setup-form'});
      var own = el('select', {id: 'site-setup-ownership'});
      (s.ownership_evidence ? [['reuse', '前回の所有権の確認記録を使う']] : [])
        .concat(workersDev ? [['cloudflare', 'Cloudflareのアカウントで確認（workers.dev・自動）']] : [])
        .concat([['well-known-file', 'サイトに確認用ファイルを置いた'], ['dns-txt', 'DNSのTXTレコードを設定した']])
        .forEach(function (o) { own.appendChild(el('option', {value: o[0]}, o[1])); });
      var confirmed = el('input', {type: 'checkbox', id: 'site-setup-confirmed'});
      var busy = su.state === 'LAUNCHED' || su.state === 'RUNNING';
      var start = el('button', {type: 'submit', 'class': 'app-run-button', id: 'site-setup-start'}, renew ? '監視設定を更新' : '初回セットアップを開始');
      add(sf, el('label', {'for': 'site-setup-ownership'}, '所有権の確認方法'), own,
          add(el('label', {'class': 'app-check', id: 'site-setup-confirmed-label'}), confirmed, document.createTextNode(' 自分で確認しました（ファイル・TXTレコードの場合）')),
          start);
      action(sf, setupStatus, 'セットアップの画面を開いています…', '/app/api/site/setup', function () {
        return {step: 'setup', ownership: own.value, confirmed: confirmed.checked};
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
    p.appendChild(para('app-run-foot', '保存済みの検査 ' + s.runs + '件 ／ データ：' + state.data));
    p.appendChild(add(el('p', {'class': 'app-run-links'}), el('a', {href: '/demo/'}, '合成デモ（固定のサンプル）を見る ›')));
    return p;
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
    var key = function (s) { return s ? [s.runs, s.monitor.running, (s.monitor.last || {}).finished_at, s.monitor.enabled, (s.setup || {}).state, (s.setup || {}).at,
                                        (s.permit || {}).permit_id, (s.monitor_view || {}).state, s.readiness.filter(function (r) { return r.ok; }).length, s.background, s.display].join('|') : ''; };  // also: setup progress, a new permit
    var seen = key(state.site);
    setInterval(async function () {
      var busy = document.activeElement && /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
      var open = document.querySelector('#site-aux[open]');
      try {
        var now = key((await session()).site);
        if (now !== seen && !busy && !open) location.reload();
      } catch (e) { /* the app was stopped: keep the page */ }
    }, 3000);
  }

  function pausedWhy(reason) {
    if (!reason) return '';
    var map = {ON_HOLD: 'Baselineの判断待ち', COMPLETE: '予定した検査を完了', 'DECISION:BASELINE_CREATED': 'Baselineの正式承認待ち', 'DECISION:CHANGED': '変更の確認待ち',
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

  function render(state) {
    var main = document.getElementById('main');
    if (main && !isDemo && !isHome && state.site && /^\/review(\.html)?$/.test(path)) {
      // right under the comparison (Baseline / this capture / difference) the USER is asked to look at
      var body = document.getElementById('review-compare-body');
      if (body) body.parentNode.insertBefore(updatePanel(state), body.nextSibling); else main.appendChild(updatePanel(state));
      var bu0 = state.site.baseline_update || {};
      var need = state.site.baseline.targets ? '初回Baselineの承認が必要です' : bu0.state === 'AVAILABLE' ? '変更の確認とBaselineの更新が必要です' : bu0.state === 'SWITCH_PENDING' ? 'Baselineの切替が未完了です' : '';
      var layout = document.getElementById('review-app');
      if (need && layout) layout.parentNode.insertBefore(add(el('p', {'class': 'app-notice is-warn', id: 'review-action-needed'}, need + '。'), el('a', {href: '#baseline-update-panel'}, '　承認の操作へ移動 ›')), layout);
      return;
    }
    if (!main || !isHome || !document.body.classList.contains('dashboard-home')) return;
    var panels = isDemo ? [demoPanel(state)] : state.site ? [sitePanel(state)] : [addSitePanel(state)];
    if (!isDemo && state.site) document.body.classList.add('app-user-site');
    panels.reverse().forEach(function (p) { main.insertBefore(p, main.firstChild); });
    if (!isDemo && state.site) watch(state);
  }

  async function start() {
    try { render(await session()); } catch (error) { /* not served by the app: leave the page exactly as exported */ }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
