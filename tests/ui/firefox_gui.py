"""Drive the GUI rehearsal (tests/ui/gui_rehearsal.py) in a REAL headless Firefox via Marionette (plain TCP, stdlib only).
Every non-127.0.0.1 request of the browser goes to a dead proxy (127.0.0.1:9), and Firefox's own background services are switched off.
Usage: py -3.15 -B tests/ui/firefox_gui.py --url http://127.0.0.1:8799/ --data <rehearsal data folder> --out <NEW folder for screenshots + report>
Steps: register a site -> refuse a setup without the user's own check -> 初回セットアップ -> watch "セットアップ中" turn into "完了" without
reloading by hand -> first real-mode capture (stand-in harness) and automatic Baseline -> 今すぐ再検査 -> REVIEW / ACTIVITY -> background button."""
import argparse
import base64
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time

FIREFOX = Path(r'C:\Program Files\Mozilla Firefox\firefox.exe')
ELEMENT = 'element-6066-11e4-a52e-4f735466cecf'
PREFS = {
    'marionette.port': 0, 'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': 9,
    'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': 9, 'network.proxy.no_proxies_on': '127.0.0.1',
    'network.proxy.allow_hijacking_localhost': False, 'app.update.enabled': False, 'app.update.auto': False,
    'toolkit.telemetry.enabled': False, 'datareporting.healthreport.uploadEnabled': False, 'datareporting.policy.dataSubmissionEnabled': False,
    'browser.safebrowsing.malware.enabled': False, 'browser.safebrowsing.phishing.enabled': False, 'network.captive-portal-service.enabled': False,
    'network.connectivity-service.enabled': False, 'extensions.update.enabled': False, 'browser.newtabpage.enabled': False,
    'browser.startup.homepage': 'about:blank', 'startup.homepage_welcome_url': '', 'browser.aboutwelcome.enabled': False,
    'network.dns.disablePrefetch': True, 'network.prefetch-next': False, 'browser.search.update': False, 'remote.prefs.recommended': True,
    'intl.accept_languages': 'ja-JP', 'browser.shell.checkDefaultBrowser': False,
    'network.trr.mode': 5, 'app.normandy.enabled': False, 'messaging-system.rsexperimentloader.enabled': False}  # no DNS-over-HTTPS, no remote experiments


class Marionette:
    def __init__(self, port):
        deadline = time.monotonic() + 60
        while True:
            try:
                self.sock = socket.create_connection(('127.0.0.1', port), timeout=5)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        self.sock.settimeout(120)
        self.buf, self.n = b'', 0
        self.read()  # the server's hello
        self.call('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {'acceptInsecureCerts': False}}})

    def read(self):
        while b':' not in self.buf:
            self.buf += self.sock.recv(65536)
        size, rest = self.buf.split(b':', 1)
        while len(rest) < int(size):
            rest += self.sock.recv(1 << 20)
        msg, self.buf = rest[:int(size)], rest[int(size):]
        return json.loads(msg)

    def call(self, command, params=None):
        self.n += 1
        raw = json.dumps([0, self.n, command, params or {}]).encode()
        self.sock.sendall(str(len(raw)).encode() + b':' + raw)
        while True:
            kind, mid, error, result = self.read()
            if mid == self.n:
                if error:
                    raise RuntimeError(f"{command}: {error.get('error')}: {error.get('message', '')[:300]}")
                return result

    def js(self, script, *args):
        return self.call('WebDriver:ExecuteScript', {'script': script, 'args': list(args)}).get('value')

    def find(self, css):
        return self.call('WebDriver:FindElement', {'using': 'css selector', 'value': css})['value'][ELEMENT]

    def click(self, css):
        self.call('WebDriver:ElementClick', {'id': self.find(css)})

    def type(self, css, text):
        self.call('WebDriver:ElementSendKeys', {'id': self.find(css), 'text': text})

    def wait(self, script, seconds=60, what=''):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                value = self.js(script)
                if value:
                    return value
            except RuntimeError:
                pass  # the page is reloading
            time.sleep(0.5)
        raise TimeoutError('waited for: ' + (what or script))

    def shot(self, path):
        path.write_bytes(base64.b64decode(self.call('WebDriver:TakeScreenshot', {'full': True})['value']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', required=True)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=False)
    profile = Path(tempfile.mkdtemp(prefix='siteproof-ff-'))
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    prefs = {**PREFS, 'marionette.port': port}
    (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(k)}, {json.dumps(v)});\n' for k, v in prefs.items()), encoding='utf-8')
    ff = subprocess.Popen([str(FIREFOX), '-headless', '-marionette', '-no-remote', '-profile', str(profile)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    steps = []

    def step(name, ok, detail=''):
        steps.append({'step': name, 'ok': bool(ok), 'detail': str(detail)[:400]})
        print(('OK  ' if ok else 'NG  ') + name + (' : ' + str(detail)[:200] if detail else ''), flush=True)

    try:
        m = Marionette(port)
        m.call('WebDriver:SetWindowRect', {'width': 1280, 'height': 1100})
        m.call('WebDriver:Navigate', {'url': args.url})
        # 1. register a site (the real form)
        m.wait("return document.getElementById('site-add-open')", what='サイトを追加')
        m.click('#site-add-open')
        m.type('#site-name', 'GUIリハーサル')
        m.type('#site-url', 'https://my-worker.my-sub.workers.dev/')
        m.click('#site-owner')
        m.shot(args.out / '01-register-form.png')
        m.click('#site-add-submit')
        m.wait("return document.getElementById('site-readiness')", what='登録後のHOME')
        summary = m.js("return document.querySelector('#site-readiness summary').textContent")
        step('サイト登録 → HOMEに「実サイト監視の準備」', re.search(r'（[0-4] / 6 完了）', summary), summary)
        m.shot(args.out / '02-registered.png')
        # 2. the two methods that cannot be verified are listed but not selectable (nothing is launched)
        step('確認用ファイル・DNSのTXTレコードは選べない（未対応と表示）',
             m.js("var o = document.querySelectorAll('#site-setup-ownership option'); var bad = 0; for (var i = 0; i < o.length; i++) { if (/well-known|dns-txt/.test(o[i].value) && o[i].disabled && o[i].textContent.indexOf('対応していません') >= 0) bad++; } return bad") == 2)
        # 3. 初回セットアップ (workers.dev: Cloudflare, chosen automatically)
        step('workers.devでは確認方法の既定がCloudflare', m.js("return document.getElementById('site-setup-ownership').options[0].value") == 'cloudflare')
        m.click('#site-setup-start')
        running = m.wait("var e = document.getElementById('site-setup-state'); return e && /LAUNCHED|RUNNING/.test(e.dataset.state) && e.textContent", 30, 'セットアップ中')
        step('セットアップ中の表示', 'セットアップ中' in running, running)
        m.shot(args.out / '03-setup-running.png')
        done = m.wait("var e = document.getElementById('site-setup-state'); return e && e.dataset.state === 'DONE' && document.querySelector('#site-readiness summary').textContent", 90, 'セットアップ完了（自動更新）')
        step('セットアップ完了 → HOMEが自動で更新され準備 6/6', '6 / 6' in done, done)
        m.shot(args.out / '04-setup-done.png')
        # 4. the scheduler captures by itself (stand-in harness) and makes the Baseline
        def outcomes():
            f = next((args.data / 'sites').glob('site-*/monitor-log.jsonl'), None)
            return [json.loads(l) for l in f.read_text('utf-8').splitlines() if l.strip()] if f else []
        deadline = time.monotonic() + 120
        while not any(e['outcome'] == 'BASELINE_CREATED' for e in outcomes()) and time.monotonic() < deadline:
            time.sleep(1)
        step('初回の自動撮影とBaseline自動作成（代役のハーネス・操作なし）', any(e['outcome'] == 'BASELINE_CREATED' for e in outcomes()),
             [(e['trigger'], e['outcome']) for e in outcomes()])
        time.sleep(4)  # HOME reloads itself after the inspection; act on the settled page
        m.wait("return document.readyState === 'complete' && /正常に監視中|実サイト監視中/.test((document.getElementById('site-display') || {}).textContent || '')", 120, 'HOME 正常に監視中')
        step('HOMEの画像監視が「正常に監視中」', True)
        permit = m.js("var e = document.getElementById('site-permit'); return e && e.textContent")
        step('監視許可の期限・残り回数の表示', bool(permit) and '残り' in permit, permit)
        step('「監視設定を更新」ボタン', m.js("return document.getElementById('site-setup-start').textContent") == '監視設定を更新')
        m.shot(args.out / '05-monitoring.png')
        # 5. 今すぐ再検査 -> automatic comparison with the same Baseline
        m.js("var f = document.getElementById('site-inspect-form'); f.requestSubmit(); return true;")
        deadline = time.monotonic() + 120
        while not any(e['trigger'] == 'MANUAL' for e in outcomes()) and time.monotonic() < deadline:
            time.sleep(1)
        manual = [e for e in outcomes() if e['trigger'] == 'MANUAL']
        step('今すぐ再検査 → 同じBaselineと自動比較', bool(manual) and manual[-1]['outcome'] == 'UNCHANGED',
             manual and {k: (p['image_label'], p['quality_label']) for k, p in manual[-1].get('profiles', {}).items()})
        time.sleep(4)
        shown = m.wait("return document.readyState === 'complete' && document.body.innerText", 30, '再検査後のHOME')
        step('HOMEに再検査の結果（画像比較・検査品質）', '画像比較：変更なし' in shown and '検査品質：問題なし' in shown,
             [l for l in shown.splitlines() if '画像比較' in l][:2])
        m.shot(args.out / '06-recheck.png')
        # 6. background button (stand-in: recorded, no Windows task)
        m.js("document.getElementById('site-background-form').requestSubmit(); return true;")
        bg = m.wait("var t = document.getElementById('site-background-status'); return t && /タスク/.test(t.textContent) && t.textContent", 30, 'バックグラウンド登録')
        step('「アプリを閉じても監視する」（代役：記録のみ）', 'タスク' in bg, bg)
        # 7. REVIEW / ACTIVITY show the same result
        for page, name in (('review.html', 'REVIEW'), ('activity.html', 'ACTIVITY')):
            m.call('WebDriver:Navigate', {'url': args.url.rstrip('/') + '/' + page})
            text = m.wait("return document.readyState === 'complete' && document.body.innerText", 30, name)
            step(f'{name}に画像比較・検査品質の表示', '画像比較：' in text and '検査品質：' in text,
                 [l for l in text.splitlines() if '画像比較' in l or '検査品質' in l][:3])
            m.shot(args.out / f'07-{name.lower()}.png')
        m.call('WebDriver:DeleteSession')
    except Exception as exc:  # recorded as a failed step; the screenshots so far stay
        step('操作の途中で停止', False, f'{type(exc).__name__}: {exc}')
    finally:
        ff.terminate()
        try:
            ff.wait(20)
        except subprocess.TimeoutExpired:
            ff.kill()
        shutil.rmtree(profile, ignore_errors=True)
    calls = [json.loads(l) for l in (args.data / 'rehearsal-calls.jsonl').read_text('utf-8').splitlines()] if (args.data / 'rehearsal-calls.jsonl').is_file() else []
    report = {'steps': steps, 'stand_in_calls': calls, 'all_ok': all(s['ok'] for s in steps)}
    (args.out / 'REPORT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('ALL OK' if report['all_ok'] else 'SOME STEPS FAILED')
    return 0 if report['all_ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
