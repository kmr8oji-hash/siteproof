(function (root) {
  'use strict';

  function createController(env) {
    var doc = env.document;
    var ids = ['pair-form', 'pair-code', 'pair-button', 'connection-status', 'reload-list',
      'list-message', 'baseline-list', 'list-next', 'detail-message', 'baseline-detail',
      'history-message', 'baseline-history', 'history-next', 'approval-panel',
      'approval-confirm', 'approve-button', 'approval-message'];
    var els = {};
    ids.forEach(function (id) { els[id] = doc.getElementById(id); });
    var listToken = 0, selectionToken = 0, nextList = null, nextHistory = null, selected = null;
    var reviewed = null, csrf = null, approving = false;

    function empty(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
    function text(value) { return typeof value === 'string' ? value : '未記録'; }
    function version(value) { return Number.isInteger(value) && value > 0 ? String(value) : '未設定'; }
    function next(value) { return Number.isInteger(value) && value >= 0 && value <= 10000 ? value : null; }
    function approval(value) {
      return { PENDING: 'BASELINE_PENDING（承認待ち）', APPROVED: 'APPROVED（Baseline承認済み）',
        REJECTED: 'REJECTED（却下）' }[value] || 'UNKNOWN';
    }
    function clearSelection() {
      ++selectionToken; selected = null; nextHistory = null;
      reviewed = null; csrf = null;
      els['approval-panel'].hidden = true; els['approval-confirm'].checked = false;
      els['approve-button'].disabled = true; els['approval-message'].textContent = '';
      empty(els['baseline-detail']); empty(els['baseline-history']);
      els['detail-message'].textContent = '';
      els['history-message'].textContent = '';
      els['history-next'].disabled = true;
    }
    function clearAll() {
      ++listToken; clearSelection(); empty(els['baseline-list']); nextList = null;
      els['list-next'].disabled = true;
    }
    function failure(error, node) {
      if (error && error.status === 401) {
        clearAll();
        els['connection-status'].textContent = '認証が必要です';
        els['pair-form'].hidden = false;
        els['list-message'].textContent = '認証が必要です';
      } else {
        node.textContent = error && error.status === 404 ? 'Baselineが見つかりません' : 'Baselineを取得できません';
      }
    }
    async function request(url, options) {
      var controller = env.AbortController ? new env.AbortController() : null;
      var timer = controller && env.setTimeout ? env.setTimeout(function () { controller.abort(); }, 5000) : null;
      try {
        var response = await env.fetch(url, Object.assign({method: 'GET', credentials: 'same-origin',
          mode: 'same-origin', cache: 'no-store', redirect: 'error'}, options || {},
          controller ? {signal: controller.signal} : {}));
        if (response.status !== 200) { var err = new Error('request refused'); err.status = response.status; throw err; }
        return await response.json();
      } finally {
        if (timer !== null && env.clearTimeout) { env.clearTimeout(timer); }
      }
    }
    function ensureAssessment(body) {
      var a = body && body.assessment;
      if (!a || a.profile_trust !== 'UNATTESTED' || a.profile_reason !== 'PROFILE_UNATTESTED' ||
          a.quality !== 'UNKNOWN' || a.comparison !== 'NOT_RUN') { throw new Error('unsafe assessment'); }
    }
    function cell(row, value) {
      var td = doc.createElement('td'); td.textContent = value; row.appendChild(td); return td;
    }
    function field(label, value) {
      var dt = doc.createElement('dt'), dd = doc.createElement('dd');
      dt.textContent = label; dd.textContent = value;
      els['baseline-detail'].appendChild(dt); els['baseline-detail'].appendChild(dd);
    }
    function rows(items) {
      empty(els['baseline-list']);
      items.forEach(function (item) {
        if (!item || typeof item.candidate_id !== 'string') { throw new Error('invalid item'); }
        var row = doc.createElement('tr');
        cell(row, text(item.page_id));
        cell(row, text(item.profile_fingerprint));
        cell(row, item.candidate_id);
        cell(row, approval(item.approval_state));
        cell(row, version(item.current && item.current.version));
        var action = cell(row, ''), button = doc.createElement('button');
        button.type = 'button'; button.className = 'flow-btn'; button.textContent = '詳細・履歴';
        button.addEventListener('click', function () { select(item.candidate_id); });
        action.appendChild(button); els['baseline-list'].appendChild(row);
      });
    }
    async function refreshList(offset) {
      if (approving) { return false; }
      offset = next(offset) === null ? 0 : offset;
      clearAll(); var token = listToken;
      els['list-message'].textContent = '読み込み中…';
      try {
        var body = await request('/api/baselines?limit=25&offset=' + offset);
        if (token !== listToken) { return; }
        ensureAssessment(body);
        if (!Array.isArray(body.items)) { throw new Error('invalid list'); }
        rows(body.items); nextList = next(body.next_offset);
        els['list-next'].disabled = nextList === null;
        els['list-message'].textContent = body.items.length ? '保存済みBaselineの候補一覧です。Baseline標準レコードにはprofile名・Desktop/Mobile区分は保存されていません。M1の区分はfixture一覧で確認できます。' : 'Baselineが登録されていません';
        els['connection-status'].textContent = '接続中（ローカルBaseline）';
        els['pair-form'].hidden = true;
        return true;
      } catch (error) {
        if (token !== listToken) { return; }
        empty(els['baseline-list']); nextList = null; els['list-next'].disabled = true;
        failure(error, els['list-message']);
        return false;
      }
    }
    function detail(item) {
      empty(els['baseline-detail']);
      field('候補ID', text(item.candidate_id)); field('対象ページ', text(item.page_id));
      field('profile fingerprint', text(item.profile_fingerprint));
      field('承認状態', approval(item.approval_state));
      field('revision', Number.isInteger(item.revision) && item.revision >= 0 ? String(item.revision) : '未記録');
      field('digest', text(item.candidate_digest)); field('artifact SHA-256', text(item.artifact_sha256));
      field('artifact参照', item.artifact_ref_redacted ? '非表示（安全な相対参照ではありません）' : text(item.artifact_ref));
      field('候補のversion', version(item.candidate_version));
      field('現行version', version(item.current && item.current.version));
      field('現行候補ID', item.current ? text(item.current.candidate_id) : '未設定');
      field('承認者', item.approval ? text(item.approval.actor) : '未記録');
      field('承認日時', '未記録');
    }
    async function history(token, id, offset) {
      empty(els['baseline-history']); els['history-message'].textContent = '読み込み中…';
      els['history-next'].disabled = true;
      var body = await request('/api/baselines/' + encodeURIComponent(id) + '/history?limit=25&offset=' + offset);
      if (token !== selectionToken || id !== selected) { return; }
      ensureAssessment(body);
      if (!Array.isArray(body.versions)) { throw new Error('invalid history'); }
      body.versions.forEach(function (v) {
        var item = v.baseline || {}, li = doc.createElement('li');
        li.textContent = 'version ' + version(v.version) + (v.is_current ? '（現行版）' : '（過去版）') +
          ' / 候補 ' + text(item.candidate_id) + ' / ' + approval(item.approval_state) +
          ' / 承認者 ' + (item.approval ? text(item.approval.actor) : '未記録') + ' / 承認日時：未記録';
        els['baseline-history'].appendChild(li);
      });
      nextHistory = next(body.next_offset); els['history-next'].disabled = nextHistory === null;
      els['history-message'].textContent = body.versions.length ? '保存された版・承認情報です。品質の合否判定ではありません。' : '履歴はありません';
    }
    async function select(id) {
      if (approving) { return null; }
      clearSelection(); selected = id; var token = selectionToken;
      els['detail-message'].textContent = '読み込み中…';
      try {
        var body = await request('/api/baselines/' + encodeURIComponent(id));
        if (token !== selectionToken) { return; }
        ensureAssessment(body);
        if (!body.baseline || body.baseline.candidate_id !== id) { throw new Error('wrong candidate'); }
        detail(body.baseline); els['detail-message'].textContent = '';
        await history(token, id, 0);
        await prepareApproval(body.baseline, token);
        return token === selectionToken && selected === id ? body.baseline : null;
      } catch (error) {
        if (token !== selectionToken) { return; }
        empty(els['baseline-detail']); empty(els['baseline-history']); nextHistory = null;
        els['history-next'].disabled = true; els['history-message'].textContent = '';
        failure(error, els['detail-message']);
        return null;
      }
    }
    async function moreHistory() {
      if (approving || selected === null || nextHistory === null) { return; }
      var token = selectionToken, id = selected, offset = nextHistory;
      nextHistory = null;
      try { await history(token, id, offset); }
      catch (error) { if (token === selectionToken) { empty(els['baseline-history']); failure(error, els['history-message']); } }
    }
    async function prepareApproval(item, token) {
      if (item.approval_state !== 'PENDING') { return; }
      try {
        var state = await request('/api/baselines/_approval/session', {headers: {'X-SiteProof-UI': '1'}});
        if (token !== selectionToken) { return; }
        if (!state.approval_enabled) {
          els['approval-message'].textContent = '承認操作には起動プロセスによる操作主体の指定が必要です'; return;
        }
        var current = item.current ? item.current.version : 0;
        if (typeof state.csrf_token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(state.csrf_token) ||
            !Number.isSafeInteger(item.revision) || item.revision < 0 ||
            !Number.isSafeInteger(current) || current < 0 ||
            typeof item.candidate_digest !== 'string' || !/^[0-9a-f]{64}$/.test(item.candidate_digest)) {
          throw new Error('invalid approval context');
        }
        csrf = state.csrf_token;
        reviewed = {candidate_id: item.candidate_id, expected_revision: item.revision,
          reviewed_digest: item.candidate_digest, expected_current_version: current, confirmed: true};
        els['approval-panel'].hidden = false;
      } catch (error) {
        if (token === selectionToken) { failure(error, els['approval-message']); }
      }
    }
    async function approve() {
      if (approving || !reviewed || !csrf || !els['approval-confirm'].checked) { return; }
      var snapshot = reviewed, secret = csrf, message = '', accepted = false, expired = false;
      approving = true; reviewed = null; csrf = null;
      els['approval-confirm'].checked = false; els['approve-button'].disabled = true;
      els['approval-message'].textContent = '承認結果を確認中…';
      try {
        var result = await request('/api/baselines/_approval/approve', {method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-SiteProof-CSRF': secret}, body: JSON.stringify(snapshot)});
        accepted = result && result.approved === true;
      } catch (error) {
        if (error.status === 401) {
          expired = true; failure(error, els['approval-message']); message = '認証が必要です';
        } else if (error.status === 409) {
          message = '承認状態または現行版が変わりました。最新の内容を再確認してください';
        } else if (error.status === 422) {
          message = '確認digestが一致しないため承認を拒否しました。内容を再確認してください';
        } else if (error.status === 400 || error.status === 403 || error.status === 404) {
          message = '承認を拒否しました。認証と最新の内容を再確認してください';
        }
      } finally { secret = ''; approving = false; }
      if (!expired) {
        var listed = await refreshList(0);
        var actual = listed ? await select(snapshot.candidate_id) : null;
        if (accepted && listed && actual && actual.approval_state === 'APPROVED' &&
            actual.revision === snapshot.expected_revision + 1) {
          message = 'Baseline承認済み';
        }
      }
      els['approval-message'].textContent = message || '承認結果は未確認です。再取得した現行版と履歴を確認してください';
      if (env.onBaselineChange) { env.onBaselineChange(); }
    }
    async function pair() {
      var code = els['pair-code'].value; els['pair-code'].value = '';
      els['pair-button'].disabled = true;
      try {
        await request('/local/pair', {method: 'POST', headers: {'Content-Type': 'application/json',
          'X-SiteProof-Pair': '1'}, body: JSON.stringify({pairing_code: code})});
        code = ''; await refreshList(0);
        if (env.onBaselineChange) { env.onBaselineChange(); }
      } catch (error) {
        code = ''; clearAll(); els['connection-status'].textContent = '認証が必要です';
        els['pair-form'].hidden = false; els['list-message'].textContent = '認証が必要です';
      } finally { els['pair-button'].disabled = false; }
    }
    function start() {
      els['pair-form'].addEventListener('submit', function (event) { event.preventDefault(); pair(); });
      els['reload-list'].addEventListener('click', function () { refreshList(0); });
      els['list-next'].addEventListener('click', function () { if (nextList !== null) { refreshList(nextList); } });
      els['history-next'].addEventListener('click', moreHistory);
      els['approval-confirm'].addEventListener('change', function () {
        els['approve-button'].disabled = approving || !reviewed || !csrf || !els['approval-confirm'].checked;
      });
      els['approve-button'].addEventListener('click', approve);
      return refreshList(0);
    }
    return {start: start, refreshList: refreshList, select: select, pair: pair, moreHistory: moreHistory, approve: approve};
  }
  if (typeof module === 'object' && module.exports) { module.exports = {createController: createController}; }
  else if (root.document) {
    root.SiteProofBaseline = createController({document: root.document, fetch: root.fetch.bind(root), AbortController: root.AbortController,
      setTimeout: root.setTimeout.bind(root), clearTimeout: root.clearTimeout.bind(root),
      onBaselineChange: function () { root.document.dispatchEvent(new root.CustomEvent('siteproof:baseline-change')); }});
    root.SiteProofBaseline.start();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
