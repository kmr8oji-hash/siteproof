'use strict';
// Node DOM simulation only: no browser/rendering, network or dependencies.
const test = require('node:test');
const assert = require('node:assert/strict');
const {normalize, matches, start, STORAGE_KEY} = require('../../src/noxiworks/folders.js');

function fixture(storage = null) {
  const queued = new Set();
  class Element {
    constructor(dataset = {}) { this.dataset = dataset; this.hidden = false; this.value = ''; this.textContent = ''; this.attrs = {}; this.listeners = {}; this._open = false; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    fire(type) { (this.listeners[type] || []).forEach(fn => fn({currentTarget: this})); }
    setAttribute(name, value) { this.attrs[name] = value; }
    get open() { return this._open; }
    set open(value) { if (this._open !== value) { this._open = value; queued.add(this); } }
  }
  const group = (id, rows, open) => {
    const g = new Element({project: id});
    g.rows = rows.map(([search, changed, attention]) => new Element({search, changed, attention, pageId: search}));
    g.label = new Element(); g._open = open;
    g.querySelectorAll = () => g.rows;
    g.querySelector = () => g.label;
    return g;
  };
  const groups = [
    group('noxiworks', [['NoxiWorks トップページ https://noxiworks-sample.test/', 'false', 'false'], ['NoxiWorks Taxi Anomaly Loop https://noxiworks-sample.test/works/taxi-anomaly-loop/', 'true', 'false']], true),
    group('hms', [['Hello, My Saitama トップページ /', 'false', 'true'], ['Hello, My Saitama コンシェルジュ /concierge', 'true', 'true']], false),
    group('ttn', [['Tokyo Trouble Navi トップページ /', 'false', 'false']], false)
  ];
  const ids = Object.fromEntries(['project-folders', 'folder-search', 'folder-tools', 'visible-count', 'folder-empty'].map(id => [id, new Element()]));
  ids['folder-tools'].hidden = true;
  ids['project-folders'].querySelectorAll = () => groups;
  const buttons = ['all', 'attention', 'changed'].map(filter => new Element({filter}));
  ids['folder-tools'].querySelectorAll = () => buttons;
  const doc = {getElementById: id => ids[id]};
  const api = start(doc, storage);
  const flush = () => { while (queued.size) { const nodes = [...queued]; queued.clear(); nodes.forEach(n => n.fire('toggle')); } };
  flush();
  return {groups, ids, buttons, api, flush,
    search(query) { ids['folder-search'].value = query; ids['folder-search'].fire('input'); flush(); },
    filter(mode) { buttons.find(b => b.dataset.filter === mode).fire('click'); flush(); }};
}

test('search normalizes text; attention is independent of change state', () => {
  assert.equal(normalize(' Ｔａｘｉ '), 'taxi');
  assert.equal(matches({search:'NoxiWorks Taxi Anomaly Loop', changed:'true', attention:'false'}, 'ＴＡＸＩ', 'attention'), true);
  assert.equal(matches({search:'Page', changed:'false', attention:'true'}, '', 'attention'), true);
  assert.equal(matches({search:'Page', changed:'false', attention:'false'}, '', 'attention'), false);
  assert.equal(matches({search:'Page', changed:'false', attention:'true'}, '', 'changed'), false);
  assert.equal(matches({search:'Page', changed:'true', attention:'false'}, '', 'changed'), true);
});

test('search/project/URL, no match, filter counts and automatic expansion', () => {
  const f = fixture();
  assert.equal(f.ids['folder-tools'].hidden, false);
  assert.equal(f.ids['visible-count'].textContent, '表示 5 / 5 ページ');
  f.search('Hello, My Saitama');
  assert.equal(f.ids['visible-count'].textContent, '表示 2 / 5 ページ');
  assert.equal(f.groups[1].open, true);
  assert.equal(f.groups[0].hidden, true);
  f.search('taxi-anomaly-loop/');
  assert.equal(f.ids['visible-count'].textContent, '表示 1 / 5 ページ');
  assert.equal(f.groups[0].label.textContent, '1/2ページ');
  f.search('一致しない検索語');
  assert.equal(f.ids['folder-empty'].hidden, false);
  assert.equal(f.ids['visible-count'].textContent, '表示 0 / 5 ページ');
  f.search('');
  assert.equal(f.groups[1].open, false);
  f.filter('changed');
  assert.equal(f.ids['visible-count'].textContent, '表示 2 / 5 ページ');
  assert.equal(f.groups[0].label.textContent, '1/2ページ');
  f.filter('attention');
  assert.equal(f.ids['visible-count'].textContent, '表示 3 / 5 ページ');
  assert.equal(f.groups[2].hidden, true);
  assert.equal(f.groups[1].open, true);
  assert.equal(f.buttons[1].attrs['aria-pressed'], 'true');
  f.filter('all');
  assert.equal(f.groups[1].open, false);
  assert.equal(f.groups.every(g => !g.hidden), true);
});

test('native toggle preference persists; queued automatic toggles do not overwrite it', () => {
  const writes = [];
  const storage = {getItem: () => JSON.stringify({noxiworks:false, hms:false, ttn:false}), setItem: (key,value) => writes.push([key,JSON.parse(value)])};
  const f = fixture(storage);
  assert.equal(f.groups[0].open, false);
  assert.equal(writes.length, 0);
  f.search('NoxiWorks'); f.search('');
  assert.equal(f.groups[0].open, false);
  assert.equal(writes.length, 0);
  f.groups[1].open = true; f.flush();
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], STORAGE_KEY);
  assert.equal(writes[0][1].hms, true);
  f.filter('attention'); f.filter('all');
  assert.equal(f.groups[1].open, true);
  assert.equal(writes.length, 1);
  const restored = fixture({getItem: () => JSON.stringify(writes[0][1]), setItem: () => {}});
  assert.equal(restored.groups[1].open, true);
  restored.groups[0].open = true; restored.flush();
  assert.equal(restored.groups[0].open && restored.groups[1].open, true);
});

test('unavailable or malformed storage never disables folders/search', () => {
  for (const storage of [null, {getItem:()=>'{bad',setItem:()=>{throw Error('denied');}}, {getItem:()=>{throw Error('denied');}}, {getItem:()=>JSON.stringify({hms:'false', ttn:4}),setItem:()=>{throw Error('denied');}}]) {
    const f = fixture(storage);
    f.groups[0].open = false; f.flush();
    f.search('concierge');
    assert.equal(f.ids['visible-count'].textContent, '表示 1 / 5 ページ');
    assert.equal(f.groups[1].open, true);
  }
  assert.equal(start({getElementById:()=>null}, null), null);
});