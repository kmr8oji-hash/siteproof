"""Local-only, read-only integration of the USER-approved AWS OPERATIONS UI-01.

The HTML, palette and historical records are preserved assets, not an AWS provider.
No network, credentials, login, client construction or resource operation occurs.
"""
import json
import os
import re
from html import escape
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .nav import global_nav

ASSETS = Path(__file__).with_name('operations_assets')
SERVICES = ('EC2', 'Lambda', 'EventBridge Scheduler', 'DynamoDB', 'S3', 'CloudWatch', 'SNS', 'IAM')


def console_links():
    data = json.loads((ASSETS / 'operations-data.json').read_text('utf-8'))
    links = data['console_links']
    if set(links) != set(SERVICES) | {'Billing'}:
        raise ValueError('unexpected console link registry')
    for url in links.values():
        u = urlsplit(url)
        if (u.scheme != 'https' or u.hostname not in {'console.aws.amazon.com',
                'us-east-1.console.aws.amazon.com', 's3.console.aws.amazon.com'}
                or u.username is not None or u.password is not None or u.port is not None
                or u.fragment or parse_qs(u.query) not in ({}, {'region': ['us-east-1']})
                or any(c.isspace() or c in '<>"\\' for c in url)):
            raise ValueError('unsafe console link registry')
    return links


def user_site():
    """True when the pages are generated for the user's own site (SITEPROOF_TARGETS, set by the local app and by --targets).

    The preserved records below are the author's AWS-B trial of 2026-11 (their own five pages). They are shown only with the author's
    own targets / the synthetic demo; a user's dashboard never presents them as its monitoring state.
    """
    return bool(os.environ.get('SITEPROOF_TARGETS'))


def user_home_section():
    links = console_links()
    shortcuts = ''.join(f'<a href="{escape(links[name], quote=True)}" target="_blank" rel="noopener noreferrer" aria-label="{escape(name, quote=True)} AWS公式コンソール（外部サイト・別タブで開きます）">{escape(name)} ↗</a>' for name in SERVICES)
    return f'''<section class="panel aws-overview mini mini-purple" id="aws-operations" aria-labelledby="aws-title"><div class="panel-head"><h2 id="aws-title"><a class="aws-title-link" href="aws-operations.html">AWS運用の状況 <span aria-hidden="true">›</span></a></h2><span class="aws-tag">未取得</span></div><dl class="aws-facts"><div><dt>AWS-Bの監視結果</dt><dd>未取得（取り込むと、上の「保存時点のHTTP結果」に反映されます）</dd></div><div class="is-current"><dt>現在のAWS稼働状態：</dt><dd>確認していません（この画面はAWSに接続しません）</dd></div><div><dt>実際の請求額</dt><dd>未確認</dd></div></dl><details class="aws-console"><summary>AWS公式コンソールを開く <span class="ext-badge">外部サイト</span></summary><nav class="aws-shortcuts" aria-label="AWS公式コンソール（外部サイト・別タブで開きます）">{shortcuts}</nav></details></section>'''


def user_page(page):
    """The AWS OPERATIONS page for a user's own site: the shared header and footer, and a plain 未取得 body instead of the author's records."""
    body = ('<main id="main" class="operations-main"><section class="home-main summary-section" aria-label="AWS運用状態サマリー">'
            '<h1>AWS運用</h1><p>この画面にはAWSの記録がありません（未取得）。この画面はAWSに接続せず、他の人の過去の実証記録も表示しません。</p>'
            '<p>AWS-Bの監視結果は、自分のAWS-Bから保存したデータを取り込むと、HOME・DETAIL・履歴・通知に反映されます。'
            '取り込み手順は docs/aws_portfolio/RUNBOOK_AWS_B_LITE.md の「§9.1 結果をSiteProofに取り込む」を参照してください。</p>'
            '<p>実際の請求額：未確認。</p></section></main>')
    out, n = re.subn(r'<main[ >].*?</main>', lambda m: body, page, count=1, flags=re.S)
    if n != 1:
        raise ValueError('unexpected AWS operations page')
    return out


def home_section():
    if user_site():
        return user_home_section()
    links = console_links()
    shortcuts = ''.join(f'<a href="{escape(links[name], quote=True)}" target="_blank" rel="noopener noreferrer" aria-label="{escape(name, quote=True)} AWS公式コンソール（外部サイト・別タブで開きます）">{escape(name)} ↗</a>' for name in SERVICES)
    return f'''<section class="panel aws-overview mini mini-purple" id="aws-operations" aria-labelledby="aws-title"><div class="panel-head"><h2 id="aws-title"><a class="aws-title-link" href="aws-operations.html">AWS運用の状況 <span aria-hidden="true">›</span></a></h2><span class="aws-tag">保存済みの記録</span></div><dl class="aws-facts"><div><dt>5サイトの監視</dt><dd>2026-11-15 19:28 JSTに開始（15分間隔）</dd></div><div><dt>障害・復旧の動作確認</dt><dd>成功（2026-11-15）</dd></div><div class="is-current"><dt>現在のAWS稼働状態：</dt><dd>確認していません（この画面はAWSに接続しません）</dd></div><div><dt>実際の請求額</dt><dd>未確認（予算通知は月10 USD・USER報告）</dd></div><div><dt>画像比較用の実行基盤（AWS-C）</dt><dd>利用できません（LIVE NO-GO）</dd></div></dl><details class="aws-console"><summary>AWS公式コンソールを開く <span class="ext-badge">外部サイト</span></summary><nav class="aws-shortcuts" aria-label="AWS公式コンソール（外部サイト・別タブで開きます）">{shortcuts}</nav></details></section>'''


def write(output):
    """Called only inside build()'s newly created export directory."""
    console_links()  # Invalid asset registries fail closed before links are exported.
    output = Path(output)
    resource_dir = output / 'operations'
    resource_dir.mkdir(exist_ok=False)
    for name in ('prototype.css', 'recovery04.css', 'operations.css', 'operations-data.json'):
        with (resource_dir / name).open('xb') as stream:
            stream.write((ASSETS / name).read_bytes())
    page = (ASSETS / 'aws-operations.html').read_text('utf-8').replace('<!--GLOBAL_NAV-->', global_nav('operations'))
    if user_site():
        page = user_page(page)
    with (output / 'aws-operations.html').open('xb') as stream:
        stream.write(page.encode('utf-8'))
