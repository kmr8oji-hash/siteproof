/* Local S1 comparison. Fixed authenticated routes; no URL fetch or browser-start. */
(function (root) {
  'use strict';
  function create(env) {
    var doc = env.document, e = {}, generation = 0, busy = false, nextOffset = null;
    ['m4-message','m4-jobs','m4-history','m4-result','m4-baseline','m4-current','m4-diff','m4-refresh','m4-next'].forEach(function (id) { e[id] = doc.getElementById(id); });
    if (!e['m4-jobs']) { return null; }
    var labels = {PROFILE_UNATTESTED:'撮影条件は未認証', PROFILE_ATTESTATION_MISMATCH:'撮影条件の証明が一致しません',
      PROFILE_MISMATCH:'撮影条件が不一致', PROFILE_VERIFIED:'撮影条件を検証済み',
      BASELINE_PENDING:'基準画像の承認待ち', BASELINE_UNSET:'基準画像が未設定',
      BASELINE_NOT_APPROVED:'基準画像が未承認', THRESHOLD_UNDEFINED:'差分閾値が未設定',
      EVIDENCE_MISSING:'画像証拠が欠損しています', EVIDENCE_MISMATCH:'証拠の整合性が一致しません',
      BASELINE_EVIDENCE_MISMATCH:'基準画像の証拠が一致しません', MANIFEST_MISSING:'manifestが欠損しています',
      IMAGE_SIZE_MISMATCH:'比較画像のサイズが不一致', CAPTURE_DIMENSIONS_MISMATCH:'画像と撮影設定のサイズが不一致',
      IMAGE_FORMAT_UNSUPPORTED:'PNG形式に対応していません', IMAGE_LIMIT:'画像が比較上限を超えています',
      IMAGE_INVALID:'画像を読み取れません', CAPTURE_NOT_SUCCEEDED:'撮影が成功していません',
      JOB_NOT_COMPLETED:'Jobが完了していません', CHECK_FAILED:'チェックで明確な失敗を検出',
      CHECK_NOT_PASSED:'必要なチェックが未完了または未実施', CAPTURE_UNSTABLE:'描画の安定性が未確認',
      RESOURCE_CLEANUP_UNCONFIRMED:'実行資源の終了が未確認', EVIDENCE_UNAVAILABLE:'元の証拠を確認できません'};
    function reason(code) { return (labels[code] || '確認できません') + ' (' + code + ')'; }
    function empty(node) { while (node.firstChild) { node.removeChild(node.firstChild); } node.textContent = ''; }
    function clearImages() { ['m4-baseline','m4-current','m4-diff'].forEach(function (id) { e[id].removeAttribute('src'); e[id].hidden = true; }); }
    function clear() { ++generation; nextOffset = null; e['m4-next'].disabled = true; empty(e['m4-jobs']); empty(e['m4-history']); e['m4-result'].textContent = ''; clearImages(); }
    function id(value) { if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value)) { throw Error('invalid reference'); } return value; }
    function button(text, callback) { var b = doc.createElement('button'); b.type = 'button'; b.className = 'flow-btn'; b.textContent = text; b.addEventListener('click', callback); return b; }
    async function request(path, body) {
      var headers = {}, options = {credentials:'same-origin', mode:'same-origin', cache:'no-store', redirect:'error'};
      if (body !== undefined) {
        var session = await request('/api/baselines/_approval/session');
        if (!session.workspace_enabled || typeof session.csrf_token !== 'string') { throw Error('session unavailable'); }
        headers = {'Content-Type':'application/json','X-SiteProof-CSRF':session.csrf_token};
        options.method = 'POST'; options.body = JSON.stringify(body);
      } else if (path === '/api/baselines/_approval/session') { headers['X-SiteProof-UI'] = '1'; }
      options.headers = headers;
      var abort = env.AbortController ? new env.AbortController() : null;
      var timer = abort && env.setTimeout ? env.setTimeout(function () { abort.abort(); },5000) : null;
      if (abort) { options.signal = abort.signal; }
      try {
        var response = await env.fetch(path, options), value = await response.json();
        if (response.status !== 200) { var error = Error('local request refused'); error.status = response.status; error.code = value.error && value.error.code; throw error; }
        return value;
      } finally { if (timer !== null && env.clearTimeout) { env.clearTimeout(timer); } }
    }
    function failure(error) { e['m4-message'].textContent = error.status === 401 ? '認証が必要です' :
      '比較データを取得できません。未接続・証拠欠損・エラーを確認してください' + (error.code ? ' / '+reason(error.code) : ''); }
    function image(name, path) { e[name].src = path; e[name].hidden = false; }
    function report(result) {
      if (['PASS','CHANGED','FAIL','UNKNOWN','SKIPPED'].indexOf(result.quality) < 0 || !Array.isArray(result.reasons)) { throw Error('invalid result'); }
      if ((result.quality === 'PASS' || result.quality === 'CHANGED') &&
          (['ATTESTED','TRUSTED_TEST'].indexOf(result.profile_trust) < 0 || result.reasons.length || !result.metrics || !result.policy)) { throw Error('invalid verdict'); }
      return '品質 '+result.quality+' / '+result.kind+' / 基準version '+(result.baseline ? result.baseline.version : '未設定')+
        ' / profile '+({MATCH:'一致',MISMATCH:'不一致',UNATTESTED:'未認証',NOT_EVALUATED:'未評価'}[result.profile_compatibility] || '未確認')+
        ' / '+reason(result.profile_reason)+' / '+result.reasons.map(reason).join(' / ')+
        (result.metrics ? ' / 差分 '+result.metrics.changed_pixels+' / '+result.metrics.total_pixels+' pixels' : '')+
        (result.preview_only ? ' / 未認証プレビューのみ・品質UNKNOWN / 差分観測: '+(result.preview_changed ? '変更あり' : '変更なし') : '')+
        (result.policy ? ' / 許容変更pixel数 '+result.policy.maximum_changed_pixels+'（'+result.policy.rationale+'）' : ' / 差分閾値未設定')+
        (result.trust_domain === 'OFFLINE_TEST' ? ' / オフライン合成検証（実撮影の認証ではありません）' : '')+
        ' / '+(result.source_availability === 'VERIFIED' ? '元の証拠を再確認済み' : result.source_availability === 'NOT_RECHECKED' ?
          '保存時点の結果です。画像表示時に元の証拠を再確認します' : '元の証拠を確認できません。保存時点の結果です');
    }
    function renderHistory(state) {
      state.results.forEach(function (result) { id(result.result_id); var row = doc.createElement('p'); row.textContent = report(result)+' / '+result.result_id+' ';
        row.appendChild(button('画像と保存結果を表示',function () { return show(result.result_id); })); e['m4-history'].appendChild(row); });
      nextOffset = state.next_offset;
      if (nextOffset !== null && (!Number.isSafeInteger(nextOffset) || nextOffset < 0 || nextOffset > 10000)) { throw Error('invalid pagination'); }
      e['m4-next'].disabled = nextOffset === null;
    }
    async function refresh() {
      var ticket = ++generation; clearImages(); e['m4-result'].textContent = '';
      try {
        var state = await request('/api/baselines/_m4/state');
        if (ticket !== generation) { return false; }
        if (!state.comparison_enabled || !Array.isArray(state.jobs) || !Array.isArray(state.results)) { throw Error('invalid state'); }
        empty(e['m4-jobs']); empty(e['m4-history']);
        state.jobs.forEach(function (job) {
          id(job.job_id); var row = doc.createElement('div'), p = doc.createElement('p');
          var pending = job.candidate && job.candidate.approval_state === 'PENDING';
          p.textContent = job.page_id+' / '+job.kind+' / 実行状態 '+job.execution+' / '+reason(job.profile_reason)+
            ' / '+(job.candidate ? (pending ? '基準画像の承認待ち (BASELINE_PENDING)' : '基準画像承認状態 '+job.candidate.approval_state)+
              ' / version '+(job.candidate.version || '未発行')+' / '+job.candidate.candidate_id : 'Baseline候補なし')+
            ' / Job開始時の基準version '+(job.baseline ? job.baseline.version : '未設定')+
            ' / 出力元 '+job.source+(job.profile_trust === 'TRUSTED_TEST' ? '（オフライン合成検証）' : '')+
            (job.evidence_reason ? ' / '+reason(job.evidence_reason) : '');
          row.appendChild(p);
          var details = doc.createElement('details'), summary = doc.createElement('summary'), pre = doc.createElement('pre');
          summary.textContent = '撮影条件・検証元を確認'; details.appendChild(summary);
          pre.textContent = JSON.stringify({profile:job.profile, conditions:job.conditions},null,2); details.appendChild(pre); row.appendChild(details);
          if (job.evidence_available) {
            row.appendChild(button('撮影画像を確認', function () { clearImages(); image('m4-current','/api/baselines/_m4/image/'+id(job.job_id)); }));
            if (job.candidate) { row.appendChild(button('Baseline詳細・明示承認', function () { return env.baseline.select(job.candidate.candidate_id); })); }
            else { row.appendChild(button('Baseline候補を作成', function () { return action('candidate',job.job_id); })); }
          }
          row.appendChild(button('固定基準版と比較・履歴保存', function () { return action('compare',job.job_id); }));
          e['m4-jobs'].appendChild(row);
        });
        renderHistory(state);
        e['m4-message'].textContent = state.jobs.length ? 'S1撮影証拠（最新10 Job）・比較履歴（25件ずつ）を再取得しました' : '比較対象の撮影Jobは登録されていません';
        return true;
      } catch (error) { if (ticket === generation) { clear(); failure(error); } return false; }
    }
    async function moreHistory() {
      if (nextOffset === null || busy) { return false; }
      var ticket = generation, offset = nextOffset; e['m4-next'].disabled = true;
      try {
        var state = await request('/api/baselines/_m4/history/'+offset);
        if (ticket !== generation) { return false; }
        renderHistory(state); return true;
      } catch (error) { if (ticket === generation) { failure(error); e['m4-next'].disabled = false; } return false; }
    }
    async function show(resultId) {
      var ticket = ++generation; clearImages(); e['m4-result'].textContent = '';
      try {
        var result = await request('/api/baselines/_m4/result/'+id(resultId));
        if (ticket !== generation) { return null; }
        e['m4-result'].textContent = report(result);
        if (result.source_availability === 'VERIFIED') {
          var path = '/api/baselines/_m4/result/'+id(resultId);
          if (result.current_sha256) { image('m4-current',path+'/current'); }
          if (result.baseline_job_id) { image('m4-baseline',path+'/baseline'); }
          if (result.diff_sha256) { image('m4-diff',path+'/diff'); }
        }
        return result;
      } catch (error) { if (ticket === generation) { clearImages(); failure(error); } return null; }
    }
    async function action(name, jobId) {
      if (busy) { return null; } busy = true; var saved, error;
      try { saved = await request('/api/baselines/_m4/'+name,{job_id:id(jobId)}); }
      catch (failed) { error = failed; }
      finally { busy = false; }
      var loaded = await refresh();
      if (error) { e['m4-message'].textContent = error.status === 401 ? '認証が必要です' :
        '保存結果は未確認です。一覧・履歴を確認し、自動再送しないでください' + (error.code ? ' / '+reason(error.code) : ''); return null; }
      if (!loaded) { return null; }
      if (name === 'candidate' && env.baseline) { await env.baseline.refreshList(0); await env.baseline.select(saved.candidate_id); }
      if (name === 'compare') { await show(saved.result_id); }
      return saved;
    }
    function start() {
      e['m4-refresh'].addEventListener('click',refresh);
      e['m4-next'].addEventListener('click',moreHistory);
      ['m4-baseline','m4-current','m4-diff'].forEach(function (name) { e[name].addEventListener('error',function () {
        e[name].removeAttribute('src'); e[name].hidden = true; e['m4-message'].textContent = '画像を表示できません。証拠欠損・認証・読戻しエラーを確認してください';
      }); });
      return refresh();
    }
    return {start:start, refresh:refresh, action:action, show:show, moreHistory:moreHistory, clear:clear};
  }
  if (typeof module === 'object' && module.exports) { module.exports = {create:create}; }
  else if (root.document) {
    var view = create({document:root.document,fetch:root.fetch.bind(root),baseline:root.SiteProofBaseline,
      AbortController:root.AbortController,setTimeout:root.setTimeout.bind(root),clearTimeout:root.clearTimeout.bind(root)});
    if (view) { view.start(); root.document.addEventListener('siteproof:baseline-change',view.refresh); }
  }
}(typeof globalThis === 'undefined' ? this : globalThis));
