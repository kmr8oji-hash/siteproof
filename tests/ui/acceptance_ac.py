"""Acceptance A1-A4, B1, C1 of docs/RELEASE_CANDIDATE.md against the REAL app (SiteProof.cmd, no stand-ins) on a NEW data folder, in headless Firefox
(tests/ui/firefox_gui.py: every request but 127.0.0.1 goes to a dead proxy). Registers only *.example.com placeholder hosts: the app contacts nothing before
ownership is verified and a permit is signed (and the HTTP / mail / DNS switches are off). B2 (restore) is done with tools/restore_backup.py afterwards.
    SiteProof.cmd --data <NEW folder> --no-browser --port 8797
    py -3.15 -B tests/ui/acceptance_ac.py --url http://127.0.0.1:8797/ --data <that folder> --out <NEW folder for screenshots + report.json>
"""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--url', required=True)
parser.add_argument('--data', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
url, data, out = args.url.rstrip('/') + '/', args.data, args.out
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.ui.firefox_gui import FIREFOX, PREFS, Marionette  # noqa: E402

out.mkdir(parents=True, exist_ok=False)
profile = Path(tempfile.mkdtemp(prefix='siteproof-ff-acc-'))
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
(profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(k)}, {json.dumps(v)});\n' for k, v in {**PREFS, 'marionette.port': port}.items()), encoding='utf-8')
ff = subprocess.Popen([str(FIREFOX), '-headless', '-marionette', '-no-remote', '-profile', str(profile)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
steps = []


def step(key, name, ok, detail=''):
    steps.append({'id': key, 'step': name, 'result': 'PASS' if ok else 'FAIL', 'detail': str(detail)[:500]})
    print(('PASS ' if ok else 'FAIL ') + key + ' ' + name + (' : ' + str(detail)[:220] if detail else ''), flush=True)


def shot(m, name, full=False):
    (out / name).write_bytes(base64.b64decode(m.call('WebDriver:TakeScreenshot', {'full': full})['value']))


def register(m, name, site_url):
    m.click('#site-add-open')
    m.type('#site-name', name)
    m.type('#site-url', site_url)
    m.click('#site-owner')
    m.click('#site-add-submit')


_click = Marionette.click


def centred_click(self, css):  # the sticky navigation can cover an element at the very top of the viewport
    self.js(f"document.querySelector({json.dumps(css)}).scrollIntoView({{block: 'center'}})")
    _click(self, css)


Marionette.click = centred_click

try:
    m = Marionette(port)
    m.call('WebDriver:SetWindowRect', {'width': 1280, 'height': 1000})
    # A1
    m.call('WebDriver:Navigate', {'url': url})
    m.wait("return document.getElementById('first-steps')", 60, 'はじめの手順')
    step('A1', '起動：HOMEが開き「はじめの手順」が出る', True, m.js("return document.querySelector('#first-steps h2').textContent + ' / ' + document.querySelector('#first-steps .app-run-tag').textContent"))
    shot(m, 'A1-home.png')
    # A2
    m.js("var d = document.getElementById('environment-panel'); d.open = true; d.dispatchEvent(new Event('toggle'));")
    m.wait("return document.getElementById('environment-table')", 90, '導入環境の確認の結果')
    rows = m.js("return Array.prototype.map.call(document.querySelectorAll('#environment-table tr'), function (r) { return r.innerText.replace(/\\s+/g, ' ').slice(0, 120); })")
    need = ('Python', 'OpenSSH', 'Docker Desktop', '撮影イメージ')
    okrows = [r for r in rows if any(n in r for n in need)]
    step('A2', '導入環境：Python・OpenSSH・Docker・固定イメージがOK', len(okrows) >= 4 and all('OK' in r for r in okrows), okrows)
    m.js("document.getElementById('environment-panel').scrollIntoView()")
    shot(m, 'A2-environment.png')
    # A3
    register(m, 'RC1受入サイト', 'https://rc1-acceptance.example.com/')
    m.wait("return document.getElementById('site-readiness')", 60, '登録後のHOME')
    summary = m.js("return document.querySelector('#site-readiness summary').textContent")
    missing = m.js("return Array.prototype.filter.call(document.querySelectorAll('#site-readiness li'), function (x) { return /未|ありません|必要/.test(x.innerText); }).length")
    step('A3a', '登録：準備の不足が一覧で出る', '完了' in summary and missing > 0, f'{summary}（不足の行 {missing}）')
    shot(m, 'A3-registered.png')
    # The first scheduled pass comes right after the registration and reloads HOME: wait for it (it must refuse, never capture), then act on a settled page.
    deadline = time.monotonic() + 60
    site_dirs, logs = [], []
    while time.monotonic() < deadline and not logs:
        time.sleep(1)
        site_dirs = [p for p in (data / 'sites').iterdir() if p.is_dir()]
        logs = [json.loads(x) for p in site_dirs if (p / 'monitor-log.jsonl').is_file() for x in (p / 'monitor-log.jsonl').read_text('utf-8').splitlines() if x.strip()]
    pngs = [str(p) for p in (data / 'sites').rglob('*.png')]
    step('A3c', '実サイトへのアクセスなし（撮影なし・監視は「準備待ち」で止まる）', logs and not pngs and all(e.get('outcome') == 'REAL_NOT_READY' for e in logs),
         {'outcomes': [e.get('outcome') for e in logs], 'png': len(pngs)})
    time.sleep(3)
    m.call('WebDriver:Navigate', {'url': url})
    m.wait("return document.getElementById('page-add-more') || document.getElementById('page-add-form')", 60, 'ページの追加')
    m.js("var d = document.getElementById('page-add-more'); if (d) d.open = true;")
    m.type('#page-path', '/about')
    m.type('#page-label', '会社概要')
    m.click('#page-add-submit')
    m.wait("return document.getElementById('page-switcher') && document.getElementById('page-switcher').innerText.indexOf('会社概要') >= 0", 60, 'ページの切り替え')
    step('A3b', '「ページを追加」で2ページ目', True, m.js("return document.getElementById('page-switcher').innerText.replace(/\\s+/g, ' ')"))
    # A4
    m.js("var d = document.getElementById('site-add-more'); if (d) d.open = true;")
    register(m, 'RC1受入サイト2', 'https://rc1-acceptance-2.example.com/')
    time.sleep(2)
    m.call('WebDriver:Navigate', {'url': url})
    m.wait("return document.getElementById('sites-panel') && document.querySelectorAll('#site-cards > *').length === 2", 60, '全サイトの状態（2サイト）')
    links = m.js("return Array.prototype.map.call(document.querySelectorAll('#site-cards a'), function (a) { return [a.getAttribute('href'), a.closest('#site-cards > *').innerText.slice(0, 60)]; })")
    first = next(h for h, t in links if 'RC1受入サイト\n' in t or t.startswith('RC1受入サイト\n'))
    step('A4a', '2つ目のサイト：HOMEが「全サイトの状態」（2サイト）', True, [t.split('\n')[0] for _, t in links])
    shot(m, 'A4-all-sites.png')
    m.call('WebDriver:Navigate', {'url': url.rstrip('/') + first})
    m.wait("return document.getElementById('site-panel')", 60, '1つ目のサイトの画面')
    body = m.js('return document.body.innerText')
    step('A4b', 'サイトの画面に別のサイトの設定が混ざらない', 'rc1-acceptance-2.example.com' not in body and 'rc1-acceptance.example.com' in body)
    # B1
    m.js("var d = document.getElementById('storage-panel'); if (d) { d.open = true; d.scrollIntoView(); }")
    m.click('#backup-all-button')
    status = m.wait("var t = document.getElementById('backup-status').textContent; return /作りました|失敗|できません/.test(t) ? t : null", 120, 'バックアップの結果')
    step('B1', '画面からバックアップ：照合に合格', 'バックアップを作りました' in status and '確認済み' in status, status)
    shot(m, 'B1-backup.png')
    # C1
    m.call('WebDriver:Navigate', {'url': url + 'demo/'})
    m.wait("return document.getElementById('app-run-form')", 60, '合成デモ')
    results = {}
    for value in m.js("return Array.prototype.map.call(document.querySelectorAll('#app-run-fixture option'), function (o) { return o.value; })"):
        m.call('WebDriver:Navigate', {'url': url + 'demo/'})
        m.wait("return document.getElementById('app-run-form')", 60)
        m.js(f"document.getElementById('app-run-fixture').value = '{value}';")
        m.click('#app-run-button')
        results[value] = m.wait("var t = document.getElementById('app-run-status').textContent; return /実行中/.test(t) || !t ? null : t", 180, 'デモ検査 ' + value)
        time.sleep(3)
    shot(m, 'C1-demo.png')
    expect = {'unchanged': '変更なし', 'changed': '変更', 'unstable': '判定不能'}
    step('C1', '合成デモ：変更なし・変更あり・判定不能', set(results) == set(expect) and all(expect[k] in results[k] for k in expect), results)
except Exception as exc:
    step('X', '操作の途中で停止', False, f'{type(exc).__name__}: {exc}')
finally:
    (out / 'report.json').write_text(json.dumps(steps, ensure_ascii=False, indent=1), encoding='utf-8')
    ff.kill()
print('ALL PASS' if steps and all(s['result'] == 'PASS' for s in steps) else 'NOT ALL PASS')
