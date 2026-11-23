/* Local-only read view. No browser launch, write route, paths or trusted verdict. */
(function (root) {
  'use strict';
  function create(doc, fetcher) {
    var panel = doc.getElementById('runtime-results'), generation = 0;
    if (!panel) { return null; }
    function clear() { while (panel.firstChild) { panel.removeChild(panel.firstChild); } }
    async function refresh() {
      var ticket = ++generation;
      clear(); panel.textContent = '撮影結果を取得中…';
      try {
        var response = await fetcher('/api/baselines/_m1/runtime', {
          credentials:'same-origin', mode:'same-origin', cache:'no-store', redirect:'error'
        });
        var body = await response.json();
        if (ticket !== generation) { return false; }
        clear(); panel.textContent = '';
        if (response.status !== 200) {
          panel.textContent = response.status === 401 ? '認証が必要です' : '撮影結果を取得できません（runtime未接続を含みます）';
          return false;
        }
        if (body.quality !== 'UNKNOWN' || !Array.isArray(body.jobs)) { throw Error('invalid runtime data'); }
        if (!body.jobs.length) { panel.textContent = '撮影Jobは登録されていません'; }
        body.jobs.forEach(function (job) {
          if (job.quality !== 'UNKNOWN' || job.profile_reason !== 'PROFILE_UNATTESTED') { throw Error('invalid assessment'); }
          var row = doc.createElement('p');
          row.textContent = [job.page_id, job.kind, job.job_id, '実行状態: '+job.execution,
            '品質UNKNOWN / PROFILE_UNATTESTED', job.reason || '',
            job.evidence ? '保存参照: '+job.evidence.artifact_ref+' / '+job.evidence.digest : '撮影証拠なし',
            '出力元: '+job.source].join(' / ');
          panel.appendChild(row);
        });
        return true;
      } catch (error) {
        if (ticket === generation) { clear(); panel.textContent = '撮影結果を取得できません'; }
        return false;
      }
    }
    return {refresh:refresh, clear:function () { ++generation; clear(); panel.textContent = ''; }};
  }
  root.SiteProofRuntime = {create:create};
  if (root.document && root.fetch) {
    var view = create(root.document, root.fetch.bind(root));
    if (view) {
      root.document.getElementById('runtime-refresh').addEventListener('click', view.refresh);
      root.document.addEventListener('siteproof:baseline-change', view.clear);
    }
  }
}(typeof window === 'undefined' ? globalThis : window));
