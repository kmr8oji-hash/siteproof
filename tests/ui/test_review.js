'use strict';
// Existing node:test runner with a small DOM fixture; no browser or network.
const test = require('node:test');
const assert = require('node:assert/strict');
const {selection, boot} = require('../../src/noxiworks/review.js');
function data(id, change = 'CHANGED') {
  return {id, project:'Project ' + id, label:'Page ' + id, detail:'details.html#' + id,
    change, baseline:'approved', verified:'true', current:'evidence/' + id + '/current.png',
    baselineImage:'evidence/' + id + '/baseline.png', diff:'evidence/' + id + '/diff.png',
    observed:'11/13 12:00', caption:'合成デモ / 品質UNKNOWN', message:'保存済みの比較',
    history:JSON.stringify(['11/13 異常を検知', '11/12 復旧を確認']),
    visualKind:'changed', visualLabel:'画像の変化あり・要確認', visualDetail:'撮影環境の真正性未確認',
    auditLabel:'許可 3 ／ 遮断 0 ／ 失敗 0'};
}
test('page-bound paths only; unknown, missing and unapproved remain distinct', () => {
  const changed = selection(data('page-a'));
  assert.equal(changed.kind, 'changed');
  assert.equal(changed.images.diff, 'evidence/page-a/diff.png');
  const unknown = selection({...data('page-b'), change:'UNKNOWN', baseline:'missing'});
  assert.equal(unknown.stateLabel, '未確認');
  assert.equal(unknown.baselineLabel, '未取得');
  assert.equal(unknown.images.diff, null);
  assert.equal(selection({...data('page-b'), baseline:'pending'}).baselineLabel, '未承認');
  assert.equal(selection({...data('page-b'), verified:'false'}).kind, 'pending');
  assert.equal(selection({...data('page-a'), current:'evidence/page-b/current.png'}).images.current, null);
  assert.equal(selection({...data('page-a'), diff:'https://example.invalid/x.png'}).images.diff, null);
  assert.equal(selection({...data('page-a'), detail:'https://example.invalid/'}), null);
  assert.equal(selection({...data('page-a'), id:'../other'}), null);
  assert.equal(selection({...data('page-a'), baselineImage:''}).kind, 'pending');
  // The operational verdict is its own field: it never changes kind/stateLabel and unknown kinds fail closed.
  assert.equal(changed.visualKind, 'changed');
  assert.equal(selection({...data('page-a'), visualKind:'pass'}).visualKind, 'unknown');
  assert.equal(selection({...data('page-a'), visualKind:undefined, visualLabel:undefined, auditLabel:undefined}).auditLabel, '未取得');
});
function fixture() {
  class Element {
    constructor(dataset = {}) {this.dataset=dataset; this.attrs={}; this.hidden=false; this.textContent=''; this.listeners={};}
    setAttribute(k,v) {this.attrs[k]=v;}
    getAttribute(k) {return this.attrs[k] || null;}
    removeAttribute(k) {delete this.attrs[k];}
    addEventListener(k,fn) {this.listeners[k]=fn;}
    closest() {return this.folder;}
  }
  const ids = {};
  for (const id of ['review-app','review-project-title','review-page-title','review-change',
    'review-baseline','review-evidence','review-profile','review-observed','review-detail',
    'review-metadata','review-selected','review-visual','review-visual-detail','review-audit','review-message','review-history-empty','review-selected-message']) ids[id]=new Element();
  for (const role of ['baseline','current','diff']) for (const part of ['link','image','empty','caption']) ids['review-'+part+'-'+role]=new Element();
  for (let i=0;i<3;i++) ids['review-history-'+i]=new Element();
  const choices=[new Element(data('page-a')),new Element({...data('page-b'),label:'<img onerror=x>',
    change:'UNKNOWN',baseline:'pending',current:'',baselineImage:'',diff:'',history:'[]'})];
  choices.forEach(a => a.folder={open:false});
  ids['review-app'].querySelectorAll=()=>choices;
  const doc={getElementById:id=>ids[id]};
  return {ids,choices,doc};
}
test('switching pages clears all stale images, links and history; native folder expands', () => {
  const f=fixture(); const api=boot(f.doc);
  assert.equal(f.ids['review-selected'].attrs['data-selected-id'], 'page-a');
  assert.equal(f.ids['review-image-diff'].attrs.src, 'evidence/page-a/diff.png');
  let prevented=false;
  f.choices[1].listeners.click({button:0,preventDefault(){prevented=true;}});
  assert.equal(prevented,true);
  assert.equal(f.ids['review-selected'].attrs['data-selected-id'], 'page-b');
  assert.equal(f.ids['review-page-title'].textContent,'<img onerror=x>');
  assert.equal(f.ids['review-visual'].textContent,'画像の変化あり・要確認');
  assert.equal(f.ids['review-audit'].textContent,'許可 3 ／ 遮断 0 ／ 失敗 0');
  assert.equal(f.ids['review-detail'].attrs.href,'details.html#page-b');
  assert.equal(f.ids['review-metadata'].attrs.href,'evidence/page-b/details.json');
  for (const role of ['baseline','current','diff']) {
    assert.equal(f.ids['review-image-'+role].attrs.src,undefined);
    assert.equal(f.ids['review-link-'+role].attrs.href,undefined);
    assert.equal(f.ids['review-link-'+role].hidden,true);
    assert.equal(f.ids['review-empty-'+role].hidden,false);
  }
  assert.equal(f.ids['review-history-empty'].hidden,false);
  assert.equal(f.ids['review-history-0'].textContent,'');
  assert.equal(f.choices[1].folder.open,true);
  assert.equal(f.choices[0].attrs['aria-current'],undefined);
  assert.equal(f.choices[1].attrs['aria-current'],'page');
  assert.equal(api.select(f.choices[0]),true);
  assert.equal(f.ids['review-image-baseline'].attrs.src,'evidence/page-a/baseline.png');
  assert.equal(f.ids['review-history-empty'].hidden,true);
});
test('modified clicks retain DETAIL navigation; malformed history cannot inject markup', () => {
  const f=fixture();boot(f.doc);
  f.choices[1].listeners.click({button:0,ctrlKey:true,preventDefault(){throw Error('modified click intercepted');}});
  assert.equal(f.ids['review-selected'].attrs['data-selected-id'],'page-a');
  assert.deepEqual(selection({...data('page-a'),history:'{bad'}).history,[]);
  assert.deepEqual(selection({...data('page-a'),history:JSON.stringify(['<script>',{}])}).history,['<script>']);
  assert.equal(boot({getElementById:()=>null}),null);
});
