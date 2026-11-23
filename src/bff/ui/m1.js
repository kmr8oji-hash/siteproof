/* Local-only offline operations. No fetch of target URLs or trusted quality verdict. */
(function (root) {
  'use strict';
  function createController(env) {
    var doc = env.document, baseline = env.baseline, compareCore = env.compareCore;
    var ids = ['m1-message','m1-site-label','m1-site-origin','m1-site-save','m1-page-id',
      'm1-page-label','m1-page-path','m1-page-save','m1-pages','m1-profile-page','m1-profile-kind',
      'm1-profile-width','m1-profile-height','m1-profile-save','m1-fixture-name','m1-fixture-save',
      'm1-captures','m1-capture','m1-baseline','m1-compare','m1-result','m1-history','m1-reload',
      'm1-before','m1-after','m1-diff'];
    var e = {}, state = null, busy = false, loadToken = 0, resultToken = 0, pageEdit = null;
    ids.forEach(function (id) { e[id] = doc.getElementById(id); });
    function empty(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
    function tell(text) { e['m1-message'].textContent = text; }
    function id(value) { if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value)) { throw Error('invalid reference'); } return value; }
    function clearImages() {
      ['m1-before','m1-after','m1-diff'].forEach(function (name) { e[name].removeAttribute('src'); e[name].hidden = true; });
    }
    function clear() {
      state = null; pageEdit = null; ++resultToken;
      ['m1-pages','m1-captures','m1-history','m1-capture','m1-baseline','m1-profile-page'].forEach(function (name) { empty(e[name]); });
      e['m1-result'].textContent = ''; clearImages();
      ['m1-site-label','m1-site-origin','m1-page-id','m1-page-label','m1-page-path','m1-profile-width','m1-profile-height'].forEach(function (name) { e[name].value = ''; });
    }
    async function request(path, body) {
      var headers = {}, method = 'GET';
      if (body !== undefined) {
        var session = await request('/api/baselines/_approval/session');
        if (!session.workspace_enabled || typeof session.csrf_token !== 'string') { throw Error('workspace unavailable'); }
        headers = {'Content-Type':'application/json','X-SiteProof-CSRF':session.csrf_token}; method = 'POST';
      } else if (path === '/api/baselines/_approval/session') { headers['X-SiteProof-UI'] = '1'; }
      var abort = env.AbortController ? new env.AbortController() : null;
      var timer = abort && env.setTimeout ? env.setTimeout(function () { abort.abort(); },5000) : null;
      try {
        var options = {method:method,headers:headers,credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error'};
        if (body !== undefined) { options.body = JSON.stringify(body); }
        if (abort) { options.signal = abort.signal; }
        var response = await env.fetch(path,options), result = await response.json();
        if (response.status !== 200) {
          var error = Error('local request refused'); error.status = response.status;
          error.code = result.error && result.error.code; throw error;
        }
        return result;
      } finally { if (timer !== null && env.clearTimeout) { env.clearTimeout(timer); } }
    }
    function safeAssessment(value) {
      if (!value || value.quality !== 'UNKNOWN' || value.profile_reason !== 'PROFILE_UNATTESTED' ||
          value.profile_trust !== 'UNATTESTED' || value.comparison !== 'NOT_RUN') { throw Error('invalid assessment'); }
    }
    function options(node, items, key, label) {
      var prior = node.value; empty(node);
      items.forEach(function (item) { var o = doc.createElement('option'); o.value = item[key]; o.textContent = label(item); node.appendChild(o); });
      node.value = items.some(function (item) { return item[key] === prior; }) ? prior : (items[0] ? items[0][key] : '');
    }
    function button(label, callback) {
      var b = doc.createElement('button'); b.type = 'button'; b.className = 'flow-btn'; b.textContent = label;
      b.addEventListener('click',callback); return b;
    }
    function row(parent, values, action) {
      var tr = doc.createElement('tr'); values.forEach(function (v) { var td = doc.createElement('td'); td.textContent = String(v); tr.appendChild(td); });
      if (action) { var td = doc.createElement('td'); td.appendChild(action); tr.appendChild(td); }
      parent.appendChild(tr);
    }
    function fillProfile() {
      var p = state && state.profiles.find(function (p) { return p.page_id === e['m1-profile-page'].value && p.kind === e['m1-profile-kind'].value; });
      e['m1-profile-width'].value = p ? String(p.profile.attributes.viewport_width) : '';
      e['m1-profile-height'].value = p ? String(p.profile.attributes.viewport_height) : '';
    }
    function render() {
      var s = state.site;
      e['m1-site-label'].value = s ? s.label : ''; e['m1-site-origin'].value = s ? s.origin : '';
      empty(e['m1-pages']); empty(e['m1-captures']); empty(e['m1-history']);
      state.pages.forEach(function (p) {
        row(e['m1-pages'],[p.page_id,p.label,p.path,'revision '+p.revision],button('編集',function () {
          pageEdit = {page_id:p.page_id,revision:p.revision};
          e['m1-page-id'].value = p.page_id; e['m1-page-label'].value = p.label; e['m1-page-path'].value = p.path;
        }));
      });
      options(e['m1-profile-page'],state.pages,'page_id',function (p) { return p.label+' / '+p.page_id; }); fillProfile();
      state.captures.forEach(function (c) {
        row(e['m1-captures'],[c.page_id,c.kind,c.fixture,c.capture_id,'合成fixture保存済み','実Job: '+c.job_execution,'品質: '+c.quality],
          button('Baseline候補に登録',function () { registerCandidate(c.capture_id); }));
      });
      options(e['m1-capture'],state.captures,'capture_id',function (c) { return c.page_id+' / '+c.kind+' / '+c.fixture+' / '+c.capture_id; });
      options(e['m1-baseline'],state.baselines.filter(function (b) { return b.approval_state === 'APPROVED'; }),
        'candidate_id',function (b) { return b.page_id+' / '+(b.kind || 'profile区分未記録')+' / version '+b.candidate_version+' / '+b.candidate_id; });
      state.results.forEach(function (r) {
        row(e['m1-history'],[r.page_id,r.kind,'version '+r.baseline_version,r.preview_state,'品質UNKNOWN',r.result_id],
          button('保存結果を表示',function () { showResult(r.result_id); }));
      });
    }
    async function refresh() {
      var token = ++loadToken;
      try {
        var next = await request('/api/baselines/_m1/state');
        if (token !== loadToken) { return false; }
        safeAssessment(next.assessment); state = next; render();
        tell('M1オフライン / 最大5ページ / 合成fixtureのみ / 実Job NOT_RUN / 品質UNKNOWN（履歴は最新100件）'); return true;
      } catch (error) {
        if (token !== loadToken) { return false; }
        clear(); tell(error.status === 401 ? '認証が必要です' : 'M1データを取得できません。専用DBの接続と状態を確認してください'); return false;
      }
    }
    async function action(name, payload) {
      if (busy || !state) { return null; }
      busy = true; var result = null, error = null;
      try { result = await request('/api/baselines/_m1/'+name,payload); }
      catch (failure) { error = failure; }
      finally { busy = false; }
      var loaded = await refresh();
      if (error) {
        var reasons = {PAGE_LIMIT:'最大5ページです。6ページ目は登録できません',REVISION_CONFLICT:'変更が競合しました。最新の内容を再確認してください',
          CANDIDATE_EXISTS:'このfixtureの候補は登録済みです',EVIDENCE_MISSING:'画像証拠が欠損しています',PROFILE_SIZE_INVALID:'profileの寸法を確認してください'};
        tell(error.status === 401 ? '認証が必要です' : reasons[error.code] ||
          (error.status && error.status < 500 ? '操作を拒否しました。入力・認証・CSRFを確認してください' : '保存結果は未確認です。再取得した一覧・履歴を確認し、自動再送しないでください'));
        return null;
      }
      if (!loaded) { tell('保存結果は未確認です。最新の保存状態を取得できません'); return null; }
      tell('保存内容を再取得しました。合成fixtureの操作であり、実サイトの品質判定ではありません'); return result;
    }
    async function saveSite() { return action('site',{label:e['m1-site-label'].value,origin:e['m1-site-origin'].value,expected_revision:state && state.site ? state.site.revision : 0}); }
    async function savePage() {
      var p = state && state.pages.find(function (p) { return p.page_id === e['m1-page-id'].value; });
      var result = await action('page',{page_id:e['m1-page-id'].value,label:e['m1-page-label'].value,path:e['m1-page-path'].value,
        expected_revision:pageEdit && pageEdit.page_id === e['m1-page-id'].value ? pageEdit.revision : (p ? p.revision : 0)});
      if (result) { pageEdit = null; }
      return result;
    }
    async function saveProfile() {
      var p = state && state.profiles.find(function (p) { return p.page_id === e['m1-profile-page'].value && p.kind === e['m1-profile-kind'].value; });
      return action('profile',{page_id:e['m1-profile-page'].value,kind:e['m1-profile-kind'].value,
        width:Number(e['m1-profile-width'].value),height:Number(e['m1-profile-height'].value),expected_revision:p ? p.revision : 0});
    }
    async function saveFixture() { return action('fixture',{page_id:e['m1-profile-page'].value,kind:e['m1-profile-kind'].value,fixture:e['m1-fixture-name'].value}); }
    async function registerCandidate(capture) {
      var result = await action('candidate',{capture_id:capture});
      if (baseline) { await baseline.refreshList(0); }
      if (result && baseline) { await baseline.select(result.candidate_id); if (env.navigate) { env.navigate('detail-heading'); } }
      return result;
    }
    async function compare() {
      if (!e['m1-baseline'].value || !e['m1-capture'].value) { tell('承認済みBaselineと保存済みfixtureを選択してください'); return; }
      var result = await action('compare',{baseline_id:e['m1-baseline'].value,capture_id:e['m1-capture'].value});
      if (result) { await showResult(result.result_id); }
      return result;
    }
    async function showResult(key) {
      var token = ++resultToken;
      clearImages(); e['m1-result'].textContent = '読み込み中…';
      try {
        var r = await request('/api/baselines/_m1/result/'+id(key));
        if (token !== resultToken) { return null; }
        safeAssessment(r.assessment);
        if (r.preview_only !== true) { throw Error('invalid preview'); }
        var metric = r.metrics ? '差分 '+r.metrics.changed_pixels+' / '+r.metrics.total_pixels+' pixels ('+compareCore.formatRatio(r.metrics.changed_pixels,r.metrics.total_pixels)+')' : '差分を計算できません';
        e['m1-result'].textContent = 'PREVIEW_ONLY / 正式比較NOT_RUN / 品質UNKNOWN / Baseline version '+r.baseline_version+' / '+metric+' / 理由: '+r.reasons.join(', ');
        if (r.before_capture_id) { e['m1-before'].src = '/api/baselines/_m1/image/'+id(r.before_capture_id); e['m1-before'].hidden = false; }
        if (r.capture_id) { e['m1-after'].src = '/api/baselines/_m1/image/'+id(r.capture_id); e['m1-after'].hidden = false; }
        if (r.preview_state === 'CALCULATED') { e['m1-diff'].src = '/api/baselines/_m1/diff/'+id(r.result_id); e['m1-diff'].hidden = false; }
        if (env.navigate) { env.navigate('m1-compare-heading'); }
        return r;
      } catch (error) {
        if (token !== resultToken) { return null; }
        if (error.status === 401) { clear(); }
        e['m1-result'].textContent = error.status === 401 ? '認証が必要です' : '比較結果を取得できません';
        return null;
      }
    }
    function start() {
      [['m1-site-save',saveSite],['m1-page-save',savePage],['m1-profile-save',saveProfile],['m1-fixture-save',saveFixture],
       ['m1-compare',compare],['m1-reload',refresh]].forEach(function (pair) { e[pair[0]].addEventListener('click',pair[1]); });
      ['m1-profile-page','m1-profile-kind'].forEach(function (name) { e[name].addEventListener('change',fillProfile); });
      ['m1-before','m1-after','m1-diff'].forEach(function (name) { e[name].addEventListener('error',function () {
        e['m1-result'].textContent = '画像プレビューを取得できません。品質UNKNOWN / 正式比較NOT_RUN';
      }); });
      if (env.subscribe) { env.subscribe(refresh); }
      return refresh();
    }
    return {start:start,refresh:refresh,saveSite:saveSite,savePage:savePage,saveProfile:saveProfile,
      saveFixture:saveFixture,registerCandidate:registerCandidate,compare:compare,showResult:showResult};
  }
  if (typeof module === 'object' && module.exports) { module.exports = {createController:createController}; }
  else if (root.document) {
    root.SiteProofM1 = createController({document:root.document,fetch:root.fetch.bind(root),baseline:root.SiteProofBaseline,
      compareCore:root.SiteProofCompare,AbortController:root.AbortController,setTimeout:root.setTimeout.bind(root),clearTimeout:root.clearTimeout.bind(root),
      navigate:function (id) { root.location.hash = id; },subscribe:function (fn) { root.document.addEventListener('siteproof:baseline-change',fn); }});
    root.SiteProofM1.start();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
