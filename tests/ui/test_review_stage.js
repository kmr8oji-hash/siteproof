'use strict';
// REVIEW 05: screenshot stage, Desktop/Mobile switch, enlarged view, five separate states. Node test runner + small DOM fixture; no browser or network.
const test = require('node:test');
const assert = require('node:assert/strict');
const {selection, boot} = require('../../src/noxiworks/review.js');

function captured(id, extra = {}) {
  const card = (key, size, file) => ({key, label:key, status:'SUCCEEDED', image:'evidence/' + id + '/' + file, size, viewport:size,
    captured:'11/18 11:46', range:'表示領域のみ（ページ全体ではありません）', frame:key});
  return {id, project:'Project ' + id, label:'Page ' + id, url:'https://example.invalid/' + id, detail:'details.html#' + id, change:'UNKNOWN',
    baseline:'pending', verified:'true', current:'evidence/' + id + '/current.png', baselineImage:'', diff:'', observed:'11/18 11:46',
    caption:'保存画像 / 品質UNKNOWN', message:'撮影は成功しました', history:'[]', compared:'false', captureLabel:'撮影成功', captureKind:'ok',
    changeKind:'none', baselineNote:'承認待ち（PENDING）', compareReason:'Baselineが未承認のため、比較はまだ行っていません（比較未実施）。',
    captures:JSON.stringify([card('desktop', '1440×900', 'current.png'), card('mobile', '390×844', 'mobile.png')]), ...extra};
}

// A synthetic page with an approved Baseline and a comparison for both profiles (Desktop changed, Mobile unchanged).
function compared(id) {
  const own = file => 'evidence/' + id + '/' + file;
  const card = (key, file, base, diff, change, label) => ({key, label:key, status:'SUCCEEDED', image:own(file), size:'1440×1538', viewport:'1440×900',
    captured:'11/18 11:46', range:'ページ全体', frame:key, health:'読み込み失敗 0件 ／ JavaScriptエラー 0件', baseline:own(base), diff:own(diff), change, change_label:label});
  return {...captured(id), baseline:'approved', change:'CHANGED', compared:'true', baselineImage:own('baseline.png'), diff:own('diff.png'),
    compareReason:'', plan:JSON.stringify({role:'PRIMARY', role_label:'主要監視対象', state_label:'実サイト撮影：未承認（未実施）', profiles:'Desktop', why:'',
      candidates:[{label:'防災（主要機能）', entry:'1回押す', state:'撮影できません'}]}),
    captures:JSON.stringify([card('desktop', 'current.png', 'baseline.png', 'diff.png', 'changed', '変更あり'),
      card('mobile', 'mobile.png', 'mobile_baseline.png', 'mobile_diff.png', 'unchanged', '変更なし')])};
}

test('a captured page: states stay separate and only the page\'s own images are accepted', () => {
  const s = selection(captured('page-c'));
  assert.equal(s.kind, 'pending');
  assert.deepEqual([s.captureLabel, s.baselineLabel, s.compareLabel, s.changeLabel], ['撮影成功', '未承認', '未実施', '判定なし']);
  assert.equal(s.baselineNote, '承認待ち（PENDING）');
  assert.deepEqual(s.cards.map(c => [c.key, c.image]), [['desktop', 'evidence/page-c/current.png'], ['mobile', 'evidence/page-c/mobile.png']]);
  assert.equal(s.images.baseline, null);
  assert.equal(selection(captured('page-c', {compared:'true'})).changeLabel, '判定不能（UNKNOWN）');
  // foreign, external and cross-role paths are dropped; unknown keys are ignored
  const bad = JSON.stringify([{key:'desktop', image:'evidence/other/current.png', status:'SUCCEEDED'},
    {key:'mobile', image:'evidence/page-c/current.png', status:'SUCCEEDED'}, {key:'tablet', image:'evidence/page-c/current.png'},
    {key:'desktop', image:'https://example.invalid/x.png', status:'SUCCEEDED'}]);
  assert.deepEqual(selection(captured('page-c', {captures:bad})).cards.map(c => c.image), [null, null]);
  assert.deepEqual(selection(captured('page-c', {captures:'{bad'})).cards, []);
  assert.equal(selection({...captured('page-c'), captureKind:'<x>'}).captureKind, 'ok');
  assert.equal(selection(captured('page-c', {baseline:'approved', change:'CHANGED', baselineImage:'evidence/page-c/baseline.png',
    diff:'evidence/page-c/diff.png'})).changeLabel, '変更あり');
  assert.equal(selection({...captured('page-c'), baseline:'missing'}).baselineNote, '');
  // data saved without capture records still gets its one plain picture
  const legacy = {...captured('page-c'), captures:undefined};
  assert.deepEqual(selection(legacy).cards.map(c => c.image), ['evidence/page-c/current.png']);
});

function stageFixture() {
  class Element {
    constructor(dataset = {}) {this.dataset = dataset; this.attrs = {}; this.hidden = false; this.textContent = ''; this.listeners = {}; this.kids = []; this.className = '';}
    setAttribute(k, v) {this.attrs[k] = v;}
    getAttribute(k) {return this.attrs[k] || null;}
    removeAttribute(k) {delete this.attrs[k];}
    addEventListener(k, fn) {this.listeners[k] = fn;}
    closest() {return this.folder;}
    focus() {}
    appendChild(c) {this.kids.push(c); return c;}
    removeChild(c) {this.kids.splice(this.kids.indexOf(c), 1);}
    get firstChild() {return this.kids[0] || null;}
    get children() {return this.kids;}
  }
  const ids = {};
  for (const id of ['review-app', 'review-project-title', 'review-page-title', 'review-page-url', 'review-change', 'review-change-note', 'review-baseline', 'review-baseline-note',
    'review-capture', 'review-compare-state', 'review-evidence', 'review-profile', 'review-observed', 'review-detail', 'review-detail-tech', 'review-evidence-page', 'review-metadata',
    'review-selected', 'review-visual', 'review-visual-detail', 'review-audit', 'review-message', 'review-history-empty', 'review-selected-message', 'review-stage-view',
    'review-compare', 'review-shot-title', 'review-shot-time', 'review-shot-size', 'review-shot-range', 'review-zoom', 'review-original', 'review-lightbox', 'review-lightbox-body',
    'review-lightbox-fit', 'review-lightbox-close', 'review-lightbox-title', 'review-shot-health', 'review-compare-kind', 'review-compare-result',
    'review-compare-empty', 'review-compare-body', 'review-slider-before', 'review-slider-after', 'review-slider-range',
    'review-plan', 'review-plan-role', 'review-plan-state', 'review-plan-profiles', 'review-plan-why', 'review-plan-candidates', 'review-plan-candidate-list']) ids[id] = new Element();
  for (const role of ['baseline', 'current', 'diff', 'after']) for (const part of ['link', 'image', 'empty', 'caption']) ids['review-' + part + '-' + role] = new Element();
  for (let i = 0; i < 3; i++) ids['review-history-' + i] = new Element();
  ids['review-slider-top'] = Object.assign(new Element(), {style:{}});
  ids['review-modes'] = new Element();
  ids['review-modes'].kids = ['side', 'slider', 'diff'].map(mode => new Element({mode}));
  ids['review-slider-range'].value = '50';
  const choices = [new Element(captured('page-c')),
    new Element({...captured('page-d'), captures:'[]', current:'', observed:'未取得', captureLabel:'未撮影', captureKind:'none'}),
    new Element(compared('page-e'))];
  choices.forEach(a => a.folder = {open:false});
  ids['review-app'].querySelectorAll = () => choices;
  ids['review-lightbox'].hidden = true;
  const keys = {};
  const doc = {getElementById:id => ids[id], createElement:() => new Element(), createTextNode:value => ({textContent:value}), addEventListener:(k, fn) => {keys[k] = fn;},
    body:{classList:{add() {}, remove() {}}}, activeElement:null};
  return {ids, choices, doc, keys};
}

test('Desktop / Mobile switch changes the picture; the Baseline comparison belongs to Desktop only', () => {
  const f = stageFixture(), api = boot(f.doc);
  assert.equal(f.ids['review-image-current'].attrs.src, 'evidence/page-c/current.png');
  assert.equal(f.ids['review-stage-view'].attrs['data-frame'], 'desktop');
  assert.equal(f.ids['review-capture'].textContent, '撮影成功');
  assert.equal(f.ids['review-capture'].className, 'review-status ok');
  assert.equal(f.ids['review-baseline'].className, 'review-status pending');
  assert.equal(f.ids['review-compare-state'].textContent, '未実施');
  assert.equal(f.ids['review-change'].textContent, '判定なし');
  assert.equal(f.ids['review-shot-size'].textContent, '画像 1440×900 px');
  assert.equal(f.ids['review-zoom'].hidden, false);
  api.showCard('mobile');
  assert.equal(f.ids['review-image-current'].attrs.src, 'evidence/page-c/mobile.png');
  assert.equal(f.ids['review-link-current'].attrs.href, 'evidence/page-c/mobile.png');
  assert.equal(f.ids['review-original'].attrs.href, 'evidence/page-c/mobile.png');
  assert.equal(f.ids['review-stage-view'].attrs['data-frame'], 'mobile');
  assert.equal(f.ids['review-shot-size'].textContent, '画像 390×844 px');
  // no approved Baseline: the comparison panel says why instead of disappearing
  assert.equal(f.ids['review-compare-body'].hidden, true);
  assert.equal(f.ids['review-compare-empty'].hidden, false);
  assert.match(f.ids['review-compare-empty'].textContent, /Baselineが未承認/);
  assert.equal(f.ids['review-compare-kind'].textContent, 'Mobile');
  assert.equal(f.ids['review-compare-result'].textContent, '比較なし');
  api.showCard('nonsense');  // an unknown tab falls back to a real picture, never to a stale one
  assert.equal(f.ids['review-image-current'].attrs.src, 'evidence/page-c/current.png');
  // a page that was never captured: no picture, no zoom, a plain empty state
  f.choices[1].listeners.click({button:0, preventDefault() {}});
  assert.equal(f.ids['review-image-current'].attrs.src, undefined);
  assert.equal(f.ids['review-link-current'].hidden, true);
  assert.equal(f.ids['review-zoom'].hidden, true);
  assert.equal(f.ids['review-empty-current'].hidden, false);
  assert.equal(f.ids['review-empty-current'].textContent, '未撮影：このページはまだ撮影されていません');
  assert.equal(f.ids['review-capture'].textContent, '未撮影');
});

test('an approved comparison follows the Desktop / Mobile tab, switches view mode, and drops foreign compare paths', () => {
  const f = stageFixture(), api = boot(f.doc);
  f.choices[2].listeners.click({button:0, preventDefault() {}});
  assert.equal(f.ids['review-compare-body'].hidden, false);
  assert.equal(f.ids['review-compare-empty'].hidden, true);
  assert.equal(f.ids['review-image-baseline'].attrs.src, 'evidence/page-e/baseline.png');
  assert.equal(f.ids['review-image-after'].attrs.src, 'evidence/page-e/current.png');
  assert.equal(f.ids['review-image-diff'].attrs.src, 'evidence/page-e/diff.png');
  assert.equal(f.ids['review-compare-result'].textContent, '変更あり');
  assert.equal(f.ids['review-shot-health'].textContent, '読み込み失敗 0件 ／ JavaScriptエラー 0件');
  assert.equal(f.ids['review-plan-role'].textContent, '主要監視対象');
  assert.equal(f.ids['review-plan-candidate-list'].kids.length, 1);
  api.showCard('mobile');
  assert.equal(f.ids['review-image-baseline'].attrs.src, 'evidence/page-e/mobile_baseline.png');
  assert.equal(f.ids['review-slider-after'].attrs.src, 'evidence/page-e/mobile.png');
  assert.equal(f.ids['review-image-diff'].attrs.src, 'evidence/page-e/mobile_diff.png');
  assert.equal(f.ids['review-compare-result'].textContent, '変更なし');
  api.setMode('slider');
  assert.equal(f.ids['review-compare-body'].attrs['data-mode'], 'slider');
  assert.deepEqual(f.ids['review-modes'].kids.map(b => b.attrs['aria-pressed']), ['false', 'true', 'false']);
  assert.equal(api.slide(30), 30);
  assert.equal(f.ids['review-slider-top'].style.clipPath, 'inset(0 70% 0 0)');
  api.setMode('nonsense');
  assert.equal(f.ids['review-compare-body'].attrs['data-mode'], 'side');
  // a Mobile Baseline path that points at the Desktop file (or another page) is dropped, and with it the whole comparison
  const bad = compared('page-e'), parsed = JSON.parse(bad.captures);
  parsed[1].baseline = 'evidence/page-e/baseline.png'; parsed[0].diff = 'evidence/other/diff.png';
  const s = selection({...bad, captures:JSON.stringify(parsed)});
  assert.deepEqual(s.cards.map(c => [c.baseline, c.diff, c.change]), [[null, null, 'none'], [null, null, 'none']]);
  // without page-level approval no profile shows a comparison, whatever the cards claim
  assert.deepEqual(selection({...compared('page-e'), baseline:'pending'}).cards.map(c => c.baseline), [null, null]);
});

test('enlarged view opens on the shown picture, closes with Esc, and never opens without one', () => {
  const f = stageFixture(), api = boot(f.doc);
  api.showCard('mobile');
  assert.equal(api.openLightbox(), true);
  assert.equal(f.ids['review-lightbox'].hidden, false);
  assert.equal(f.ids['review-lightbox-body'].firstChild.attrs.src, 'evidence/page-c/mobile.png');
  assert.match(f.ids['review-lightbox-title'].textContent, /390×844 px/);
  f.keys.keydown({key:'Escape', preventDefault() {}});
  assert.equal(f.ids['review-lightbox'].hidden, true);
  let prevented = false;
  f.ids['review-link-current'].listeners.click({button:0, preventDefault() {prevented = true;}});
  assert.equal(prevented, true);  // a plain click enlarges
  api.closeLightbox();
  prevented = false;
  f.ids['review-link-current'].listeners.click({button:0, ctrlKey:true, preventDefault() {prevented = true;}});
  assert.equal(prevented, false);  // a modified click keeps the browser's own "open image"
  f.choices[1].listeners.click({button:0, preventDefault() {}});
  assert.equal(api.openLightbox(), false);
  assert.equal(f.ids['review-lightbox'].hidden, true);
});
