(function () {
  'use strict';

  // Local-only sample dialogs. Reads sample text already present in the page;
  // performs no actions and keeps no state beyond the open dialog.
  var dialog = document.getElementById('sample-dialog');
  var titleEl = document.getElementById('sample-dialog-title');
  var bodyEl = document.getElementById('sample-dialog-body');
  var closeBtn = document.getElementById('sample-dialog-close');
  if (!dialog || !titleEl || !bodyEl || !closeBtn) { return; }

  var root = document.documentElement;
  root.classList.add('js');

  var FOCUSABLE = 'button:not([disabled]), [tabindex]:not([tabindex="-1"]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';
  var backgrounds = document.querySelectorAll('[data-dialog-background]');
  var savedBackground = [];
  var lastTrigger = null;
  var isOpen = false;
  var guardActive = false;
  // Set once the dialog could not be opened; the static detail list stays visible.
  var dialogBroken = false;

  function restoreAttribute(el, name, value) {
    if (value === null) {
      el.removeAttribute(name);
    } else {
      el.setAttribute(name, value);
    }
  }

  // Remembers the original attributes so closing restores them exactly.
  function setBackgroundInert(inert) {
    var i;
    if (inert) {
      savedBackground = [];
      for (i = 0; i < backgrounds.length; i++) {
        savedBackground.push({
          el: backgrounds[i],
          inert: backgrounds[i].getAttribute('inert'),
          hidden: backgrounds[i].getAttribute('aria-hidden')
        });
        backgrounds[i].setAttribute('inert', '');
        backgrounds[i].setAttribute('aria-hidden', 'true');
      }
    } else {
      for (i = 0; i < savedBackground.length; i++) {
        restoreAttribute(savedBackground[i].el, 'inert', savedBackground[i].inert);
        restoreAttribute(savedBackground[i].el, 'aria-hidden', savedBackground[i].hidden);
      }
      savedBackground = [];
    }
  }

  function fillDialog(detail) {
    titleEl.textContent = detail.getAttribute('data-title') || 'サンプル詳細';
    bodyEl.textContent = '';
    var children = detail.children;
    for (var i = 0; i < children.length; i++) {
      if (children[i].classList.contains('detail-heading')) { continue; }
      bodyEl.appendChild(children[i].cloneNode(true));
    }
  }

  function trapTab(event) {
    var items = dialog.querySelectorAll(FOCUSABLE);
    if (!items.length) {
      event.preventDefault();
      return;
    }
    var first = items[0];
    var last = items[items.length - 1];
    var active = document.activeElement;
    if (event.shiftKey && (active === first || !dialog.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !dialog.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  }

  // Document-level guard, only used when there is no native modal dialog or
  // no inert support: keeps keyboard and focus inside the open dialog.
  function guardKeydown(event) {
    if (!isOpen) { return; }
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      closeSample();
    } else if (event.key === 'Tab') {
      event.stopPropagation();
      trapTab(event);
    }
  }

  function guardFocusIn(event) {
    if (isOpen && !dialog.contains(event.target)) {
      closeBtn.focus();
    }
  }

  function setGuard(on) {
    if (on === guardActive) { return; }
    guardActive = on;
    if (on) {
      document.addEventListener('keydown', guardKeydown, true);
      document.addEventListener('focusin', guardFocusIn, true);
    } else {
      document.removeEventListener('keydown', guardKeydown, true);
      document.removeEventListener('focusin', guardFocusIn, true);
    }
  }

  // Puts the dialog element back to its closed, attribute-free state.
  function resetDialogElement() {
    try {
      if (typeof dialog.close === 'function' && dialog.open) { dialog.close(); }
    } catch (err) {
      // Fall through to the attribute cleanup below.
    }
    dialog.removeAttribute('open');
    dialog.removeAttribute('aria-modal');
    bodyEl.textContent = '';
  }

  function focusElement(el) {
    if (el && typeof el.focus === 'function') {
      el.focus();
    }
  }

  function showFallback(detail, trigger) {
    dialogBroken = true;
    root.classList.remove('js');
    if (detail) {
      detail.setAttribute('tabindex', '-1');
      focusElement(detail);
      if (document.activeElement !== detail) { focusElement(trigger); }
    } else {
      focusElement(trigger);
    }
  }

  function openSample(targetId, trigger) {
    var detail = document.getElementById(targetId);
    if (!detail || isOpen) { return; }
    if (dialogBroken) {
      showFallback(detail, trigger);
      return;
    }
    lastTrigger = trigger;
    var native = typeof dialog.showModal === 'function';
    try {
      fillDialog(detail);
      if (native) {
        dialog.showModal();
      } else {
        dialog.setAttribute('open', '');
        dialog.setAttribute('aria-modal', 'true');
      }
      // Open succeeded: only now commit state and lock the background.
      isOpen = true;
      setBackgroundInert(true);
      setGuard(!native || !('inert' in root));
      closeBtn.focus();
    } catch (err) {
      isOpen = false;
      setGuard(false);
      setBackgroundInert(false);
      resetDialogElement();
      lastTrigger = null;
      showFallback(detail, trigger);
    }
  }

  function closeSample() {
    if (!isOpen) { return; }
    isOpen = false;
    setGuard(false);
    resetDialogElement();
    setBackgroundInert(false);
    var trigger = lastTrigger;
    lastTrigger = null;
    focusElement(trigger);
  }

  var launchers = document.querySelectorAll('[data-sample-target]');
  Array.prototype.forEach.call(launchers, function (button) {
    button.addEventListener('click', function () {
      openSample(button.getAttribute('data-sample-target'), button);
    });
  });

  closeBtn.addEventListener('click', closeSample);

  dialog.addEventListener('cancel', function (event) {
    event.preventDefault();
    closeSample();
  });

  // Native close (not initiated here). Ignored once a newer open is active.
  dialog.addEventListener('close', function () {
    if (isOpen && !dialog.open) { closeSample(); }
  });

  dialog.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeSample();
    } else if (event.key === 'Tab') {
      trapTab(event);
    }
  });

  // Click on the backdrop (the dialog element itself) closes the sample.
  dialog.addEventListener('click', function (event) {
    if (event.target === dialog) { closeSample(); }
  });
})();

// Synthetic job intake / transition / results flow (offline demo).
// Everything here is SAMPLE DATA held in memory only: nothing is read, sent,
// stored or scheduled, and a reload resets it. The job state, the quality
// verdict, the comparison verdict, the human approval and the evidence are
// separate facts. A verdict can only be PASS / CHANGED when the job COMPLETED
// with synthetic evidence present; otherwise it fails closed to UNKNOWN. No
// operation here can record a human approval. Real files are never read or
// claimed. Nothing advances on its own: every transition is an explicit call.
(function () {
  'use strict';

  var MAX_JOBS = 8;
  var ACTIONS = ['start', 'complete', 'mark-unknown'];
  var TRANSITIONS = {
    'start': { from: 'pending', to: 'running' },
    'complete': { from: 'running', to: 'completed' },
    'mark-unknown': { from: 'running', to: 'unknown' }
  };

  var ACTION_LABEL = {
    'start': '「開始をシミュレート」',
    'complete': '「完了をシミュレート」',
    'mark-unknown': '「不明終了をシミュレート」'
  };

  var STATE_VIEW = {
    pending: { text: 'PENDING', css: 'st-pending', note: '受付済みで未開始の合成ジョブです。' },
    running: { text: 'RUNNING', css: 'st-running', note: 'シミュレーション上の実行中表示です。実際の処理は動いていません。' },
    completed: { text: 'COMPLETED', css: 'st-completed', note: 'ジョブが終了したことだけを示します。品質の良し悪しではありません。' },
    unknown: { text: 'UNKNOWN', css: 'st-unknown', note: '終了状態を確認できません。成功とはみなしません。' },
    NONE: { text: '—', css: 'st-none', note: 'ジョブが選択されていません。' }
  };

  var QUALITY_VIEW = {
    PASS: { text: 'PASS', css: 'st-pass', note: '独立した品質判定が「合格」という合成上の主張です。実測ではありません。' },
    UNKNOWN: { text: 'UNKNOWN', css: 'st-unknown', note: '品質を判定できません。成功とはみなしません。' },
    NONE: { text: '—', css: 'st-none', note: '未判定です（ジョブ未選択、または未終了）。' }
  };

  var COMPARISON_VIEW = {
    CHANGED: { text: 'CHANGED', css: 'st-changed', note: '差分があったことを示します。不具合とは限りません。' },
    UNKNOWN: { text: 'UNKNOWN', css: 'st-unknown', note: '比較できません。「変化なし」とは言えません。' },
    NONE: { text: '—', css: 'st-none', note: '未判定です（ジョブ未選択、または未終了）。' }
  };

  var APPROVAL_VIEW = {
    NOT_RECORDED: { text: 'NOT RECORDED', css: 'st-none', note: '人による承認は記録されていません。このデモに承認の操作はなく、APPROVED になることはありません。' },
    NONE: { text: '—', css: 'st-none', note: 'ジョブが選択されていません。' }
  };

  var EVIDENCE_VIEW = {
    present: { text: 'PRESENT', css: 'st-none', note: '合成シナリオ上「証跡あり」の設定です（SYNTHETIC）。実ファイルではありません。' },
    absent: { text: 'ABSENT', css: 'st-none', note: '合成シナリオ上「証跡なし」の設定です。実ファイルの有無とは無関係です。' },
    unknown: { text: 'UNKNOWN', css: 'st-unknown', note: '合成シナリオ上「証跡の有無が不明」の設定です。成功とはみなしません。' },
    NONE: { text: 'NOT EVALUATED', css: 'st-none', note: '未評価です（ジョブ未選択、または未終了）。' }
  };

  var REASON_TEXT = {
    JOB_ENDED_UNKNOWN: 'ジョブが UNKNOWN で終了したため、品質・比較は判定できません。',
    EVIDENCE_ABSENT: '合成証跡が ABSENT のため、PASS / CHANGED とは判定しません。',
    EVIDENCE_UNKNOWN: '合成証跡が UNKNOWN のため、PASS / CHANGED とは判定しません。',
    QUALITY_NOT_DETERMINED: 'シナリオ上、品質判定の根拠がありません。',
    COMPARISON_NOT_DETERMINED: 'シナリオ上、比較の基準がなく CHANGED かどうか判定できません。'
  };

  function deepFreeze(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      Object.freeze(value);
      Object.keys(value).forEach(function (key) { deepFreeze(value[key]); });
    }
    return value;
  }

  // claimedQuality / claimedComparison are what a naive pipeline would report;
  // evaluateResult() only honours them when the synthetic evidence is present.
  var SCENARIOS = deepFreeze([
    { key: 'present-pass-changed', label: '証跡あり ／ 品質 PASS ／ 差分 CHANGED',
      evidence: 'present', claimedQuality: 'PASS', claimedComparison: 'CHANGED' },
    { key: 'present-pass-compare-unknown', label: '証跡あり ／ 品質 PASS ／ 比較 UNKNOWN（基準なし）',
      evidence: 'present', claimedQuality: 'PASS', claimedComparison: 'UNKNOWN' },
    { key: 'present-quality-unknown-changed', label: '証跡あり ／ 品質 UNKNOWN ／ 差分 CHANGED',
      evidence: 'present', claimedQuality: 'UNKNOWN', claimedComparison: 'CHANGED' },
    { key: 'evidence-absent', label: '証跡なし（PASS / CHANGED を主張しても UNKNOWN になる）',
      evidence: 'absent', claimedQuality: 'PASS', claimedComparison: 'CHANGED' },
    { key: 'evidence-unknown', label: '証跡 不明（PASS / CHANGED を主張しても UNKNOWN になる）',
      evidence: 'unknown', claimedQuality: 'PASS', claimedComparison: 'CHANGED' }
  ]);

  function findScenario(key) {
    for (var i = 0; i < SCENARIOS.length; i++) {
      if (SCENARIOS[i].key === key) { return SCENARIOS[i]; }
    }
    return null;
  }

  function pad3(n) {
    return ('00' + n).slice(-3);
  }

  // Deterministic clock: the first event is 2000-01-01T00:00:00Z and each
  // further event is one minute later. These are not real event times.
  function createSyntheticClock() {
    var tick = 0;
    return function () {
      var stamp = new Date(Date.UTC(2000, 0, 1, 0, 0, 0) + tick * 60000).toISOString();
      tick += 1;
      return stamp.replace('.000Z', 'Z');
    };
  }

  function evaluateResult(scenario, terminalState) {
    var reasons = [];
    var quality = 'UNKNOWN';
    var comparison = 'UNKNOWN';
    if (terminalState !== 'completed') {
      reasons.push('JOB_ENDED_UNKNOWN');
    } else if (scenario.evidence !== 'present') {
      reasons.push(scenario.evidence === 'absent' ? 'EVIDENCE_ABSENT' : 'EVIDENCE_UNKNOWN');
    } else {
      if (scenario.claimedQuality === 'PASS') {
        quality = 'PASS';
      } else {
        reasons.push('QUALITY_NOT_DETERMINED');
      }
      if (scenario.claimedComparison === 'CHANGED') {
        comparison = 'CHANGED';
      } else {
        reasons.push('COMPARISON_NOT_DETERMINED');
      }
    }
    var summary = 'ジョブ ' + STATE_VIEW[terminalState].text +
      ' ／ 合成証跡 ' + EVIDENCE_VIEW[scenario.evidence].text +
      ' ／ 品質 ' + quality + ' ／ 比較 ' + comparison +
      ' ／ 人の承認 NOT RECORDED。いずれも合成であり実測ではありません。' +
      reasons.map(function (code) { return REASON_TEXT[code]; }).join('');
    return {
      quality: quality,
      comparison: comparison,
      approval: 'NOT_RECORDED',
      evidence: { synthetic: scenario.evidence, real: 'NOT_READ' },
      reasons: reasons,
      summary: summary
    };
  }

  function okResult(job) {
    return Object.freeze({ ok: true, job: job });
  }

  function failResult(code, message) {
    return Object.freeze({ ok: false, code: code, message: message });
  }

  function copyJob(job, changes) {
    var next = {};
    Object.keys(job).forEach(function (key) { next[key] = job[key]; });
    Object.keys(changes).forEach(function (key) { next[key] = changes[key]; });
    return deepFreeze(next);
  }

  // Pure in-memory model. Snapshots it returns are frozen; a transition
  // replaces the job with a new object, so earlier snapshots never change.
  // A rejected operation changes nothing and does not advance the clock.
  function createFlowModel(options) {
    var clock = options && typeof options.clock === 'function' ? options.clock : createSyntheticClock();
    var jobs = [];
    var selectedId = null;
    var counter = 0;

    function indexOfJob(id) {
      for (var i = 0; i < jobs.length; i++) {
        if (jobs[i].id === id) { return i; }
      }
      return -1;
    }

    function allowedActions(id) {
      var index = indexOfJob(id);
      if (index === -1) { return Object.freeze([]); }
      return Object.freeze(ACTIONS.filter(function (action) {
        return TRANSITIONS[action].from === jobs[index].state;
      }));
    }

    function addJob(scenarioKey) {
      var scenario = findScenario(scenarioKey);
      if (!scenario) {
        return failResult('UNKNOWN_SCENARIO', '未対応の合成シナリオです。ジョブは追加されません。');
      }
      if (jobs.length >= MAX_JOBS) {
        return failResult('LIMIT_REACHED', '合成ジョブは最大 ' + MAX_JOBS + ' 件です。ページを再読み込みするとリセットされます。');
      }
      counter += 1;
      var job = deepFreeze({
        id: 'SYN-' + pad3(counter),
        target: 'SAMPLE-TARGET-' + pad3(counter),
        synthetic: true,
        scenario: scenario.key,
        state: 'pending',
        createdAt: clock(),
        startedAt: null,
        finishedAt: null,
        result: null
      });
      jobs = jobs.concat([job]);
      return okResult(job);
    }

    function selectJob(id) {
      var index = indexOfJob(id);
      if (index === -1) {
        return failResult('UNKNOWN_JOB', '指定されたジョブは存在しません。選択は変わりません。');
      }
      selectedId = jobs[index].id;
      return okResult(jobs[index]);
    }

    function simulate(id, action) {
      if (id === null || id === undefined) {
        return failResult('NO_SELECTION', 'ジョブが選択されていません。先にジョブを追加して選択してください。');
      }
      var index = indexOfJob(id);
      if (index === -1) {
        return failResult('UNKNOWN_JOB', '指定されたジョブは存在しません。');
      }
      if (ACTIONS.indexOf(action) === -1) {
        return failResult('UNKNOWN_ACTION', '未対応の操作です。状態は変わりません。');
      }
      var job = jobs[index];
      var step = TRANSITIONS[action];
      if (job.state !== step.from) {
        var allowed = allowedActions(job.id).map(function (name) { return ACTION_LABEL[name]; });
        return failResult('INVALID_TRANSITION',
          job.id + ' は ' + STATE_VIEW[job.state].text + ' のため ' + ACTION_LABEL[action] + ' はできません。' +
          (allowed.length ? '可能な操作：' + allowed.join(' または ') + '。' : '終了状態のため、これ以上の操作はありません。'));
      }
      var next;
      if (action === 'start') {
        next = copyJob(job, { state: step.to, startedAt: clock() });
      } else {
        next = copyJob(job, {
          state: step.to,
          finishedAt: clock(),
          result: evaluateResult(findScenario(job.scenario), step.to)
        });
      }
      jobs = jobs.slice();
      jobs[index] = next;
      return okResult(next);
    }

    return Object.freeze({
      maxJobs: MAX_JOBS,
      scenarios: function () { return SCENARIOS; },
      addJob: addJob,
      selectJob: selectJob,
      simulate: simulate,
      allowedActions: allowedActions,
      getJobs: function () { return Object.freeze(jobs.slice()); },
      getSelectedId: function () { return selectedId; },
      getSelectedJob: function () {
        var index = indexOfJob(selectedId);
        return index === -1 ? null : jobs[index];
      }
    });
  }

  var FLOW_IDS = ['demo', 'nojs', 'app', 'scenario', 'add', 'empty', 'list', 'selected',
    'detail-empty', 'v-state', 'n-state', 'v-quality', 'n-quality', 'v-comparison',
    'n-comparison', 'v-approval', 'n-approval', 'v-evidence', 'n-evidence',
    't-created', 't-started', 't-finished', 'summary', 'hint',
    'start', 'complete', 'unknown', 'status', 'error'];

  function setHidden(el, hidden) {
    if (hidden) {
      el.setAttribute('hidden', '');
    } else {
      el.removeAttribute('hidden');
    }
  }

  // Wires the flow panel to a model. Returns null (and leaves the interactive
  // area hidden) if any expected element is missing.
  function initFlowUi(doc, model) {
    var els = {};
    for (var i = 0; i < FLOW_IDS.length; i++) {
      els[FLOW_IDS[i]] = doc.getElementById('flow-' + FLOW_IDS[i]);
      if (!els[FLOW_IDS[i]]) { return null; }
    }
    var actionButtons = { 'start': els.start, 'complete': els.complete, 'mark-unknown': els.unknown };
    var errorCount = 0;

    function hintFor(job) {
      if (!job) {
        return 'ジョブが選択されていません。「合成ジョブを追加」で作成するか、一覧から選択してください。';
      }
      var allowed = model.allowedActions(job.id).map(function (name) { return ACTION_LABEL[name]; });
      return '選択中 ' + job.id + ' は ' + STATE_VIEW[job.state].text + ' です。' + (allowed.length
        ? '可能な操作：' + allowed.join(' または ') + '。'
        : '終了状態のため、これ以上の操作はありません。');
    }

    // Clearing first makes a repeated identical message a fresh change.
    function announce(message) {
      els.status.textContent = '';
      els.status.textContent = message;
    }

    function clearError() {
      els.error.textContent = '';
    }

    function showError(result) {
      errorCount += 1;
      els.error.textContent = '';
      els.error.textContent = '[エラー ' + errorCount + '] ' + result.message;
    }

    function setBadge(valueEl, noteEl, view) {
      valueEl.textContent = view.text;
      valueEl.setAttribute('class', 'status-badge ' + view.css);
      noteEl.textContent = view.note;
    }

    function stamp(value) {
      return value === null ? '—（未発生）' : value + '（合成時刻）';
    }

    // Rebuilds the list; keyboard focus stays on the same job's button.
    function renderJobs() {
      var active = doc.activeElement;
      var focusId = active && els.list.contains(active) ? active.getAttribute('data-job-id') : null;
      var selectedId = model.getSelectedId();
      var jobs = model.getJobs();
      els.list.textContent = '';
      setHidden(els.empty, jobs.length > 0);
      jobs.forEach(function (job) {
        var item = doc.createElement('li');
        var button = doc.createElement('button');
        var parts = [
          ['flow-job-id', job.id],
          ['flow-job-target', job.target],
          ['status-badge ' + STATE_VIEW[job.state].css, STATE_VIEW[job.state].text],
          ['sample-tag', 'SAMPLE']
        ];
        if (job.id === selectedId) { parts.push(['flow-job-mark', '選択中']); }
        parts.forEach(function (part) {
          var span = doc.createElement('span');
          span.setAttribute('class', part[0]);
          span.textContent = part[1];
          button.appendChild(span);
        });
        button.setAttribute('type', 'button');
        button.setAttribute('class', 'flow-job');
        button.setAttribute('data-job-id', job.id);
        if (job.id === selectedId) { button.setAttribute('aria-current', 'true'); }
        button.addEventListener('click', function () { chooseJob(job.id); });
        item.appendChild(button);
        els.list.appendChild(item);
        if (job.id === focusId) { button.focus(); }
      });
    }

    function renderDetail(job) {
      var result = job ? job.result : null;
      setHidden(els['detail-empty'], !!job);
      els.selected.textContent = job ? '選択中: ' + job.id + ' ／ ' + job.target + '（SAMPLE）' : '選択中: なし';
      setBadge(els['v-state'], els['n-state'], STATE_VIEW[job ? job.state : 'NONE']);
      setBadge(els['v-quality'], els['n-quality'], QUALITY_VIEW[result ? result.quality : 'NONE']);
      setBadge(els['v-comparison'], els['n-comparison'], COMPARISON_VIEW[result ? result.comparison : 'NONE']);
      setBadge(els['v-approval'], els['n-approval'], APPROVAL_VIEW[job ? 'NOT_RECORDED' : 'NONE']);
      setBadge(els['v-evidence'], els['n-evidence'], EVIDENCE_VIEW[result ? result.evidence.synthetic : 'NONE']);
      els['t-created'].textContent = job ? stamp(job.createdAt) : '—';
      els['t-started'].textContent = job ? stamp(job.startedAt) : '—';
      els['t-finished'].textContent = job ? stamp(job.finishedAt) : '—';
      els.summary.textContent = result ? result.summary
        : (job ? 'まだ結果はありません（ジョブが終了していません）。' : '—');
    }

    function renderActions(job) {
      var allowed = job ? model.allowedActions(job.id) : [];
      Object.keys(actionButtons).forEach(function (action) {
        if (allowed.indexOf(action) === -1) {
          actionButtons[action].setAttribute('aria-disabled', 'true');
        } else {
          actionButtons[action].removeAttribute('aria-disabled');
        }
      });
      els.hint.textContent = hintFor(job);
    }

    function render() {
      var job = model.getSelectedJob();
      renderJobs();
      renderDetail(job);
      renderActions(job);
    }

    function chooseJob(id) {
      var result = model.selectJob(id);
      if (!result.ok) {
        showError(result);
        return;
      }
      clearError();
      render();
      announce(hintFor(result.job));
    }

    function simulateSelected(action) {
      var before = model.getSelectedJob();
      var result = model.simulate(model.getSelectedId(), action);
      if (!result.ok) {
        showError(result);
        return;
      }
      clearError();
      render();
      var job = result.job;
      var message = job.id + ': ' + STATE_VIEW[before.state].text + ' → ' + STATE_VIEW[job.state].text +
        '（シミュレーション）。';
      if (job.result) {
        message += '品質 ' + job.result.quality + ' ／ 比較 ' + job.result.comparison +
          ' ／ 人の承認 NOT RECORDED（いずれも合成）。';
      }
      announce(message + hintFor(job));
    }

    els.add.addEventListener('click', function () {
      var result = model.addJob(els.scenario.value);
      if (!result.ok) {
        showError(result);
        return;
      }
      model.selectJob(result.job.id);
      clearError();
      render();
      announce(result.job.id + ' を追加し、選択しました（PENDING・合成）。' + hintFor(result.job));
    });

    Object.keys(actionButtons).forEach(function (action) {
      actionButtons[action].addEventListener('click', function () { simulateSelected(action); });
    });

    render();
    setHidden(els.nojs, true);
    setHidden(els.app, false);
    return { model: model, render: render };
  }

  var instance = initFlowUi(document, createFlowModel());

  // Test hook for the Node harness; a browser has no `module`.
  if (typeof module !== 'undefined' && module && module.exports) {
    module.exports = {
      createFlowModel: createFlowModel,
      createSyntheticClock: createSyntheticClock,
      initFlowUi: initFlowUi,
      instance: instance,
      scenarios: SCENARIOS,
      maxJobs: MAX_JOBS
    };
  }
})();

// Offline result viewer. Parses ONE JSON file that the user explicitly selects,
// entirely in memory, and shows it as an untrusted report. It contacts nothing,
// opens no reference or path, stores nothing, and creates no file input or
// reader before the user presses the select button.
(function () {
  'use strict';

  var MAX_BYTES = 1048576;
  var MAX_DEPTH = 4;
  var MAX_STRING = 8192;
  var MAX_MEMBERS = 32;
  var MAX_ITEMS = 128;
  var MAX_REF = 4096;
  var NOTICE = 'オフライン結果です。撮影条件の真正性およびUIでの証拠検証は保証しません。';
  var TOP_KEYS = ['attempt_id', 'bridge', 'comparison', 'eligibility', 'evidence', 'human_approval',
    'job_id', 'notice', 'profile_trust', 'record_type', 'schema_version', 'source', 'unknown_reasons'];
  var BRIDGE_KEYS = ['reason', 'status'];
  var EVIDENCE_KEYS = ['manifest_ref', 'screenshot_ref', 'status'];
  var BRIDGE_STATUS = ['STRUCTURALLY_CHECKED', 'REJECTED', 'UNKNOWN'];
  var EVIDENCE_STATUS = ['STRUCTURALLY_CHECKED', 'NOT_VERIFIED'];
  var FIXED = {
    schema_version: 'siteproof.offline-result.v1',
    record_type: 'OFFLINE_RESULT',
    source: 'OFFLINE_PROJECTION',
    profile_trust: 'UNATTESTED',
    eligibility: 'UNKNOWN',
    comparison: 'NOT_RUN',
    human_approval: 'NOT_RECORDED'
  };
  var ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  var CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/;
  var own = Object.prototype.hasOwnProperty;

  // Fixed texts only: nothing from the file is ever echoed into an error.
  var MESSAGES = {
    TOO_LARGE: 'ファイルが大きすぎます（最大 1 MiB）。',
    EMPTY: 'ファイルが空です。',
    BOM: 'BOM 付きのファイルは受け付けません。',
    BAD_UTF8: 'UTF-8 として正しくありません。',
    NO_DECODER: 'このブラウザでは UTF-8 の厳密な検査ができません。',
    SYNTAX: 'JSON の形式が正しくありません。',
    DEPTH: '入れ子が深すぎます。',
    DUPLICATE_KEY: '同じ名前のキーが重複しています。',
    BAD_STRING: '文字列に使えない文字（制御文字・不正なサロゲート）が含まれています。',
    UNSUPPORTED_VALUE: '数値・真偽値など、この形式で使えない値が含まれています。',
    TOO_MANY: '項目数が多すぎます。',
    STRING_TOO_LONG: '文字列が長すぎます。',
    KEYS: 'キーの過不足があります。',
    TYPE: '値の型が正しくありません。',
    FIXED_VALUE: '固定値が一致しません。',
    ID: 'ジョブ ID または試行 ID の形式が正しくありません。',
    ENUM: '状態の値がこの形式で許可されていません。',
    REASON_CODE: '理由コードの形式が正しくありません。',
    UNKNOWN_REASONS: '不明の理由の一覧が正しくありません。',
    REF: '参照パスの形式が正しくありません。',
    CROSS_FIELD: '項目間の整合性が取れていません。',
    NOTICE: '注記が固定の文言と一致しません。',
    MULTI: 'ファイルは 1 つだけ選択してください。',
    NO_READER: 'このブラウザではファイルを読み取れません。',
    READ: 'ファイルの読み取りに失敗しました。',
    ABORTED: 'ファイルの読み取りが中断されました。',
    INTERNAL: '内部エラーのため表示できません。'
  };

  function fail(code) {
    var error = new Error(code);
    error.code = code;
    throw error;
  }

  function errorCode(error) {
    return error && typeof error.code === 'string' && own.call(MESSAGES, error.code) ? error.code : 'INTERNAL';
  }

  function hasLoneSurrogate(text) {
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) {
        var next = text.charCodeAt(i + 1);
        if (next >= 0xDC00 && next <= 0xDFFF) {
          i++;
        } else {
          return true;
        }
      } else if (c >= 0xDC00 && c <= 0xDFFF) {
        return true;
      }
    }
    return false;
  }

  function codePointLength(text) {
    var count = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) { i++; }
      count++;
    }
    return count;
  }

  // Strict, bounded JSON reader: duplicate keys (also escape-equivalent ones),
  // control characters, lone surrogates, numbers/booleans, trailing data and
  // deep nesting are all rejected. Objects have no prototype.
  var ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

  function parseStrictJson(text) {
    var pos = 0;
    var len = text.length;

    function skipSpace() {
      while (pos < len) {
        var c = text.charCodeAt(pos);
        if (c === 32 || c === 9 || c === 10 || c === 13) { pos++; } else { break; }
      }
    }

    function readString() {
      pos++;
      var out = '';
      var start = pos;
      for (;;) {
        if (pos >= len) { fail('SYNTAX'); }
        if (out.length + (pos - start) > MAX_STRING) { fail('STRING_TOO_LONG'); }
        var c = text.charCodeAt(pos);
        if (c === 34) {
          out += text.slice(start, pos);
          pos++;
          break;
        }
        if (c < 32) { fail('BAD_STRING'); }
        if (c === 92) {
          out += text.slice(start, pos);
          pos++;
          var e = text.charAt(pos);
          if (e === 'u') {
            var hex = text.substr(pos + 1, 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) { fail('SYNTAX'); }
            out += String.fromCharCode(parseInt(hex, 16));
            pos += 5;
          } else if (own.call(ESCAPES, e)) {
            out += ESCAPES[e];
            pos++;
          } else {
            fail('SYNTAX');
          }
          start = pos;
        } else {
          pos++;
        }
      }
      if (out.length > MAX_STRING) { fail('STRING_TOO_LONG'); }
      if (hasLoneSurrogate(out)) { fail('BAD_STRING'); }
      return out;
    }

    function readObject(depth) {
      if (depth > MAX_DEPTH) { fail('DEPTH'); }
      pos++;
      var obj = Object.create(null);
      var count = 0;
      skipSpace();
      if (text.charAt(pos) === '}') {
        pos++;
        return obj;
      }
      for (;;) {
        skipSpace();
        if (text.charAt(pos) !== '"') { fail('SYNTAX'); }
        var key = readString();
        if (own.call(obj, key)) { fail('DUPLICATE_KEY'); }
        if (++count > MAX_MEMBERS) { fail('TOO_MANY'); }
        skipSpace();
        if (text.charAt(pos) !== ':') { fail('SYNTAX'); }
        pos++;
        obj[key] = readValue(depth);
        skipSpace();
        var next = text.charAt(pos);
        pos++;
        if (next === '}') { return obj; }
        if (next !== ',') { fail('SYNTAX'); }
      }
    }

    function readArray(depth) {
      if (depth > MAX_DEPTH) { fail('DEPTH'); }
      pos++;
      var items = [];
      skipSpace();
      if (text.charAt(pos) === ']') {
        pos++;
        return items;
      }
      for (;;) {
        if (items.length >= MAX_ITEMS) { fail('TOO_MANY'); }
        items.push(readValue(depth));
        skipSpace();
        var next = text.charAt(pos);
        pos++;
        if (next === ']') { return items; }
        if (next !== ',') { fail('SYNTAX'); }
      }
    }

    function readValue(depth) {
      skipSpace();
      if (pos >= len) { fail('SYNTAX'); }
      var ch = text.charAt(pos);
      if (ch === '"') { return readString(); }
      if (ch === '{') { return readObject(depth + 1); }
      if (ch === '[') { return readArray(depth + 1); }
      if (ch === 'n') {
        if (text.substr(pos, 4) !== 'null') { fail('SYNTAX'); }
        pos += 4;
        return null;
      }
      if (/[-0-9tfNI]/.test(ch)) { fail('UNSUPPORTED_VALUE'); }
      return fail('SYNTAX');
    }

    var value = readValue(0);
    skipSpace();
    if (pos !== len) { fail('SYNTAX'); }
    return value;
  }

  function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function requireKeys(value, keys) {
    if (!isPlainObject(value)) { fail('TYPE'); }
    if (Object.keys(value).sort().join('|') !== keys.join('|')) { fail('KEYS'); }
  }

  function requireNullable(value, pattern, code) {
    if (value === null) { return; }
    if (typeof value !== 'string' || !pattern.test(value)) { fail(code); }
  }

  function badRef(ref, job, attempt, isManifest) {
    if (typeof ref !== 'string' || codePointLength(ref) > MAX_REF) { return true; }
    if (/[\\:\u0000-\u001f\u007f-\u009f]/.test(ref)) { return true; }
    var parts = ref.split('/');
    if (parts.length !== 3 || parts[0] !== job || parts[1] !== attempt) { return true; }
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === '' || parts[i] === '.' || parts[i] === '..' || /[. ]$/.test(parts[i])) { return true; }
    }
    return (parts[2] === 'manifest.json') !== isManifest;
  }

  function checkReport(raw) {
    requireKeys(raw, TOP_KEYS);
    Object.keys(FIXED).forEach(function (key) {
      if (raw[key] !== FIXED[key]) { fail('FIXED_VALUE'); }
    });
    if (raw.notice !== NOTICE) { fail('NOTICE'); }
    requireNullable(raw.job_id, ID_PATTERN, 'ID');
    requireNullable(raw.attempt_id, ID_PATTERN, 'ID');

    requireKeys(raw.bridge, BRIDGE_KEYS);
    requireKeys(raw.evidence, EVIDENCE_KEYS);
    var bridge = raw.bridge;
    var evidence = raw.evidence;
    if (BRIDGE_STATUS.indexOf(bridge.status) === -1) { fail('ENUM'); }
    if (EVIDENCE_STATUS.indexOf(evidence.status) === -1) { fail('ENUM'); }
    requireNullable(bridge.reason, CODE_PATTERN, 'REASON_CODE');

    var reasons = raw.unknown_reasons;
    if (!Array.isArray(reasons) || reasons.length < 1 || reasons.length > MAX_ITEMS) { fail('UNKNOWN_REASONS'); }
    reasons.forEach(function (code, index) {
      if (typeof code !== 'string' || !CODE_PATTERN.test(code) || reasons.indexOf(code) !== index) {
        fail('UNKNOWN_REASONS');
      }
    });
    if (reasons.indexOf('COMPARISON_NOT_RUN') === -1) { fail('UNKNOWN_REASONS'); }
    if (bridge.reason !== null && reasons.indexOf(bridge.reason) === -1) { fail('CROSS_FIELD'); }

    var bridgeChecked = bridge.status === 'STRUCTURALLY_CHECKED';
    var evidenceChecked = evidence.status === 'STRUCTURALLY_CHECKED';
    if (bridgeChecked !== evidenceChecked) { fail('CROSS_FIELD'); }
    if (bridge.status === 'REJECTED' && bridge.reason === null) { fail('CROSS_FIELD'); }
    if (bridge.status !== 'REJECTED' && bridge.reason !== null) { fail('CROSS_FIELD'); }
    if (evidenceChecked) {
      if (raw.job_id === null || raw.attempt_id === null) { fail('CROSS_FIELD'); }
      if (reasons.indexOf('PROFILE_UNATTESTED') === -1) { fail('CROSS_FIELD'); }
      if (badRef(evidence.manifest_ref, raw.job_id, raw.attempt_id, true) ||
          badRef(evidence.screenshot_ref, raw.job_id, raw.attempt_id, false)) { fail('REF'); }
    } else if (evidence.manifest_ref !== null || evidence.screenshot_ref !== null) {
      fail('CROSS_FIELD');
    }

    // Defensive copy: only known fields, frozen.
    return Object.freeze({
      schema_version: FIXED.schema_version,
      record_type: FIXED.record_type,
      source: FIXED.source,
      job_id: raw.job_id,
      attempt_id: raw.attempt_id,
      profile_trust: FIXED.profile_trust,
      eligibility: FIXED.eligibility,
      comparison: FIXED.comparison,
      human_approval: FIXED.human_approval,
      bridge: Object.freeze({ status: bridge.status, reason: bridge.reason }),
      evidence: Object.freeze({
        status: evidence.status,
        manifest_ref: evidence.manifest_ref,
        screenshot_ref: evidence.screenshot_ref
      }),
      unknown_reasons: Object.freeze(reasons.slice()),
      notice: NOTICE
    });
  }

  // Returns { ok: true, report } or { ok: false, code }; never throws.
  function validateReport(value) {
    try {
      return { ok: true, report: checkReport(value) };
    } catch (error) {
      return { ok: false, code: errorCode(error) };
    }
  }

  function decodeUtf8(buffer, Decoder) {
    if (!buffer || typeof buffer.byteLength !== 'number') { fail('READ'); }
    if (buffer.byteLength > MAX_BYTES) { fail('TOO_LARGE'); }
    if (buffer.byteLength === 0) { fail('EMPTY'); }
    var bytes = new Uint8Array(buffer);
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) { fail('BOM'); }
    if (typeof Decoder !== 'function') { fail('NO_DECODER'); }
    try {
      return new Decoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch (error) {
      return fail('BAD_UTF8');
    }
  }

  // Returns { ok: true, report } or { ok: false, code }; never throws.
  function parseReportBytes(buffer, Decoder) {
    try {
      return { ok: true, report: checkReport(parseStrictJson(decodeUtf8(buffer, Decoder))) };
    } catch (error) {
      return { ok: false, code: errorCode(error) };
    }
  }

  var BRIDGE_VIEW = {
    STRUCTURALLY_CHECKED: ['rv-b-claim', 'レポートが「構造チェック済み」と主張しているだけです。HOME は検証していません。'],
    REJECTED: ['rv-b-bad', 'レポートが「拒否」と報告しています。'],
    UNKNOWN: ['st-unknown', '不明です。成功とはみなしません。']
  };
  var EVIDENCE_VIEW = {
    STRUCTURALLY_CHECKED: ['rv-b-claim', 'レポート上の構造状態の主張です。ファイルの存在・真正性は確認していません。'],
    NOT_VERIFIED: ['st-none', '証跡は検証されていません（参照なし）。']
  };
  var FIELD_IDS = ['app', 'select', 'picker-slot', 'status', 'error', 'result', 'nojs',
    'v-source', 'v-job', 'v-attempt', 'v-bridge', 'n-bridge', 'v-reason', 'v-profile', 'v-eligibility',
    'v-comparison', 'v-approval', 'v-evidence', 'n-evidence', 'v-manifest', 'v-screenshot',
    'v-unknown', 'v-notice'];
  var CLEAR_IDS = ['v-source', 'v-job', 'v-attempt', 'v-bridge', 'n-bridge', 'v-reason', 'v-profile',
    'v-eligibility', 'v-comparison', 'v-approval', 'v-evidence', 'n-evidence', 'v-manifest',
    'v-screenshot', 'v-unknown', 'v-notice'];

  function setHidden(el, hidden) {
    if (hidden) { el.setAttribute('hidden', ''); } else { el.removeAttribute('hidden'); }
  }

  // `env` may supply FileReader / TextDecoder; otherwise the page globals are
  // looked up only when the user has chosen a file.
  function initViewer(doc, env) {
    env = env || {};
    var els = {};
    for (var i = 0; i < FIELD_IDS.length; i++) {
      els[FIELD_IDS[i]] = doc.getElementById('rv-' + FIELD_IDS[i]);
      if (!els[FIELD_IDS[i]]) { return null; }
    }

    var generation = 0;
    var reader = null;
    var input = null;

    function setStatus(message) { els.status.textContent = message; }

    function setError(message) {
      els.error.textContent = '';
      els.error.textContent = message;
    }

    function clearReport() {
      setHidden(els.result, true);
      CLEAR_IDS.forEach(function (id) { els[id].textContent = ''; });
      els['v-bridge'].setAttribute('class', 'status-badge');
      els['v-evidence'].setAttribute('class', 'status-badge');
    }

    function abortReader() {
      var pending = reader;
      reader = null;
      if (pending && typeof pending.abort === 'function') {
        try { pending.abort(); } catch (error) { /* a stale read is ignored anyway */ }
      }
    }

    // Every new action invalidates earlier reads and removes any shown report.
    function beginAttempt(message) {
      generation++;
      abortReader();
      clearReport();
      setError('');
      setStatus(message);
      return generation;
    }

    function showFailure(code) {
      clearReport();
      setStatus('レポートは表示されていません。');
      setError('読み込めません: ' + MESSAGES[own.call(MESSAGES, code) ? code : 'INTERNAL']);
    }

    function badge(id, value, view) {
      els[id].textContent = value;
      els[id].setAttribute('class', 'status-badge ' + view[0]);
    }

    function orNone(value) { return value === null ? '（なし）' : value; }

    function renderReport(report) {
      els['v-source'].textContent = report.source;
      els['v-job'].textContent = orNone(report.job_id);
      els['v-attempt'].textContent = orNone(report.attempt_id);
      badge('v-bridge', report.bridge.status, BRIDGE_VIEW[report.bridge.status]);
      els['n-bridge'].textContent = BRIDGE_VIEW[report.bridge.status][1];
      els['v-reason'].textContent = orNone(report.bridge.reason);
      els['v-profile'].textContent = report.profile_trust;
      els['v-eligibility'].textContent = report.eligibility;
      els['v-comparison'].textContent = report.comparison;
      els['v-approval'].textContent = report.human_approval;
      badge('v-evidence', report.evidence.status, EVIDENCE_VIEW[report.evidence.status]);
      els['n-evidence'].textContent = EVIDENCE_VIEW[report.evidence.status][1];
      els['v-manifest'].textContent = orNone(report.evidence.manifest_ref);
      els['v-screenshot'].textContent = orNone(report.evidence.screenshot_ref);
      els['v-unknown'].textContent = '';
      report.unknown_reasons.forEach(function (code) {
        var item = doc.createElement('li');
        item.textContent = code;
        els['v-unknown'].appendChild(item);
      });
      els['v-notice'].textContent = report.notice;
      setHidden(els.result, false);
      setError('');
      setStatus('未認証レポートを表示しました（HOME は検証していません）。ブリッジ ' + report.bridge.status +
        ' ／ 証跡 ' + report.evidence.status + '（レポートの主張）／ プロファイル ' + report.profile_trust +
        ' ／ 適格性 ' + report.eligibility + ' ／ 比較 ' + report.comparison +
        ' ／ 人の承認 ' + report.human_approval + '。');
    }

    function currentDecoder() {
      if (env.TextDecoder) { return env.TextDecoder; }
      return typeof TextDecoder === 'function' ? TextDecoder : undefined;
    }

    function currentReader() {
      if (env.FileReader) { return env.FileReader; }
      return typeof FileReader === 'function' ? FileReader : undefined;
    }

    function finishRead(result) {
      var parsed;
      try {
        parsed = parseReportBytes(result, currentDecoder());
        if (parsed.ok) {
          renderReport(parsed.report);
          return;
        }
      } catch (error) {
        parsed = { ok: false, code: 'INTERNAL' };
      }
      showFailure(parsed.code);
    }

    function onChange() {
      var files = input.files;
      var gen = beginAttempt('ファイルを確認しています。');
      if (!files || files.length === 0) {
        setStatus('ファイルが選択されませんでした。レポートは表示されていません。');
        return;
      }
      if (files.length !== 1) {
        showFailure('MULTI');
        return;
      }
      var file = files[0];
      try { input.value = ''; } catch (error) { /* the picked file object is already held */ }
      if (!file || typeof file.size !== 'number') {
        showFailure('READ');
        return;
      }
      if (file.size > MAX_BYTES) {
        showFailure('TOO_LARGE');
        return;
      }
      if (file.size === 0) {
        showFailure('EMPTY');
        return;
      }
      var Reader = currentReader();
      if (!Reader) {
        showFailure('NO_READER');
        return;
      }
      var current;
      try { current = new Reader(); } catch (error) {
        showFailure('READ');
        return;
      }
      function stale() { return gen !== generation || reader !== current; }
      current.onload = function () {
        if (stale()) { return; }
        reader = null;
        finishRead(current.result);
      };
      current.onerror = function () {
        if (stale()) { return; }
        reader = null;
        showFailure('READ');
      };
      current.onabort = function () {
        if (stale()) { return; }
        reader = null;
        showFailure('ABORTED');
      };
      reader = current;
      setStatus('ファイルを読み込み中です…');
      try {
        current.readAsArrayBuffer(file);
      } catch (error) {
        if (!stale()) {
          reader = null;
          showFailure('READ');
        }
      }
    }

    function onCancel() {
      beginAttempt('ファイル選択がキャンセルされました。レポートは表示されていません。');
    }

    // Activating the visible native control (click or keyboard) opens the chooser directly,
    // so the old report is dropped before it opens; a later change event still reads normally.
    function onNativeActivate() {
      beginAttempt('ファイル選択を開いています。選択しなかった場合、レポートは表示されません。');
    }

    function ensureInput() {
      if (input) { return input; }
      input = doc.createElement('input');
      input.setAttribute('type', 'file');
      input.setAttribute('accept', '.json,application/json');
      input.setAttribute('aria-label', '結果 JSON ファイルを選択（ローカル）');
      input.addEventListener('change', onChange);
      input.addEventListener('cancel', onCancel);
      input.addEventListener('click', onNativeActivate);
      return input;
    }

    function onSelect() {
      beginAttempt('ファイル選択を開いています。選択しなかった場合、レポートは表示されません。');
      var picker = ensureInput();
      try { picker.value = ''; } catch (error) { /* some engines refuse; harmless */ }
      var opened = false;
      try {
        if (typeof picker.showPicker === 'function') {
          picker.showPicker();
          opened = true;
        }
      } catch (error) {
        opened = false;
      }
      if (!opened) {
        // No programmatic picker: show the native control so the user can use it.
        els['picker-slot'].textContent = '';
        els['picker-slot'].appendChild(picker);
        setStatus('下のファイル選択欄から JSON ファイルを選んでください。選択しない場合、レポートは表示されません。');
      }
      els.select.focus();
    }

    els.select.addEventListener('click', onSelect);
    clearReport();
    setHidden(els.nojs, true);
    setHidden(els.app, false);
    return { render: renderReport, clear: clearReport, generation: function () { return generation; } };
  }

  var viewer = initViewer(document);

  // Test hook for the Node harness, added next to the existing flow exports.
  if (typeof module !== 'undefined' && module && module.exports) {
    module.exports.offlineResultViewer = {
      maxBytes: MAX_BYTES,
      notice: NOTICE,
      fixed: FIXED,
      messages: MESSAGES,
      parseStrictJson: parseStrictJson,
      validateReport: validateReport,
      decodeUtf8: decodeUtf8,
      parseReportBytes: parseReportBytes,
      initViewer: initViewer,
      instance: viewer
    };
  }
})();
