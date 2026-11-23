"""Read-only dashboard composed from the existing, approved web/home components."""
from html import escape
from datetime import timedelta, timezone
import json
from pathlib import Path
import hashlib
import re
import ipaddress
from urllib.parse import urlsplit

from .nav import global_nav
from .product import dashboard, deployment_plan, settings, snapshot_config
from src.aws_b.model import parse_utc

ROOT = Path(__file__).resolve().parents[2]
LABELS = {'UP': '正常', 'DOWN': '異常', 'UNKNOWN': '未確認', 'STALE': '観測が古い', 'NOT_FETCHED': '未取得',
          'STOPPED': '停止中', 'CHANGED': '変更あり', 'UNCHANGED': '変更なし',
          'OK': '期限内', 'WARNING': '期限間近', 'EXPIRED': '期限切れ', 'PROVIDER_MANAGED': '提供元管理'}
SOURCE_LABELS = {'EMPTY': '未取得', 'FIXTURE': 'デモ', 'AWS_EXPORT': '保存済みの監視結果', 'LOCAL_CAPTURE': 'ローカルに保存した撮影結果'}


def e(value):
    return escape(str(value) if value is not None else '未取得', quote=True)


def every(seconds):
    """Whole hours when the interval is a multiple of an hour, otherwise whole minutes (900 s -> 15分)."""
    return f'{seconds // 3600}時間' if seconds % 3600 == 0 else f'{seconds // 60}分'


def jst(value, date_only=False):
    moment = parse_utc(value)
    return moment.astimezone(timezone(timedelta(hours=9))).strftime('%Y/%m/%d' if date_only else '%m/%d %H:%M') if moment else '未取得'


def safe_site_url(value):
    """Validate a navigational URL only. Never resolve, request or follow it."""
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in '<>"\\' for c in value)):
        return None
    try:
        u = urlsplit(value)
        if (u.scheme not in ('http', 'https') or not u.hostname
                or u.username is not None or u.password is not None
                or u.port is not None and not 1 <= u.port <= 65535):
            return None
        try:
            ipaddress.ip_address(u.hostname)
        except ValueError:
            host = u.hostname.encode('idna').decode('ascii').rstrip('.')
            if len(host) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in host.split('.')):
                return None
    except (ValueError, UnicodeError):
        return None
    return value


def tag(state):
    if state == 'PROVIDER_MANAGED':
        return '<span class="status-badge st-none">提供元管理</span>'
    style = 'st-alert' if state in ('DOWN', 'EXPIRED') else 'st-stopped' if state == 'STOPPED' else 'st-pass' if state in ('UP', 'OK', 'UNCHANGED') else 'st-changed' if state == 'CHANGED' else 'st-unknown'
    return f'<span class="status-badge {style}" data-state="{e(state)}">{e(LABELS.get(state, "未確認"))}</span>'


def assets():
    original = (ROOT / 'web/home/index.html').read_text('utf-8')
    return (re.search(r'<svg class="brand-mark".*?</svg>', original, re.S)[0],
            re.findall(r'<svg class="status-icon".*?</svg>', original, re.S),
            re.findall(r'<svg class="launcher-icon".*?</svg>', original, re.S))


def shell(view, body, title='ダッシュボード'):
    logo, _, _ = assets()
    observed = [p['http'].get('last_checked_at') for p in view['pages']]
    observed += [p['change'].get('observed_at') for p in view['pages']]
    observed += [x.get('observed_at') for x in view['expiry']]
    dates = [v for v in observed if parse_utc(v) and parse_utc(v) <= parse_utc(view['generated_at'])]
    updated = jst(max(dates)) if dates else '未取得'
    demo = '<span class="badge badge-sample">デモ</span>' if view['source'] == 'FIXTURE' else ''
    imported = '<span class="badge badge-sample">保存済み</span>' if view['source'] == 'AWS_EXPORT' else ''
    mode = {'AWS_EXPORT': '保存済みの監視結果', 'FIXTURE': 'サンプルデータ（デモ）', 'EMPTY': '監視結果は未取得です',
            'LOCAL_CAPTURE': 'ローカルに保存した撮影結果（HTTP監視は未取得）'}[view['source']]
    refresh = view.get('http_refresh', {})
    if view.get('source_mode') == 'REFRESH_SNAPSHOT':
        mode = '保存済みの監視結果'
    fetched = ('<p>データ取得：<time>' + jst(refresh.get('fetched_at')) + ' JST</time>' + (' · 取得に失敗したページ ' + str(len(refresh['read_errors'])) if refresh.get('read_errors') else '') + '（AWSの監視記録をこのPCに保存した時点）</p>') if refresh else ''
    viewed = '<p>この画面を開いた時刻（JST）：<time id="viewed-at">未取得</time></p>' if title == 'ダッシュボード' else ''
    generated = parse_utc(view['generated_at']).astimezone(timezone(timedelta(hours=9))).strftime('%Y/%m/%d %H:%M:%S JST')
    when = fetched or f'<p>データ作成：<time datetime="{e(view["generated_at"])}">{generated}</time></p>'
    snapshot_notice = f'<aside class="panel snapshot-note" role="note" aria-label="データの時点"><strong>{mode}</strong>{when}<p>リアルタイムの情報ではありません。「正常」はHTTP応答が成功だったことを示すもので、現在のサイトの状態や表示内容の品質を保証するものではありません。</p>{viewed}</aside>'
    state_line = f'<div class="data-strip"><span class="badge{' badge-sample' if view['source'] != 'EMPTY' else ''}">{mode}</span>{when}<p>リアルタイムの情報ではありません</p>{viewed}</div>'
    if title == 'ダッシュボード':
        snapshot_notice = ''
    scripts = {'ダッシュボード': ('folders.js', 'scrollcard.js', 'nav.js'), '差分レビュー': ('review.js', 'nav.js'), '監視の詳細': ('projectfilter.js', 'nav.js'),
               '履歴・通知': ('nav.js',), '証拠一覧': ('projectfilter.js', 'nav.js')}.get(title, ())
    script = ''.join(f'<script src="{name}" defer></script>' for name in scripts)
    current = {'ダッシュボード': 'home', '差分レビュー': 'review', '監視の詳細': 'details', '履歴・通知': 'activity', '証拠一覧': 'evidence'}.get(title, '')
    review_style = '<link rel="stylesheet" href="review.css">' if title == '差分レビュー' else ''
    script_policy = "script-src 'self'; " if script else "script-src 'none'; "
    return f'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; {script_policy}img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>{e(title)} | SiteProof</title><link rel="stylesheet" href="home.css"><link rel="stylesheet" href="dashboard.css">{review_style}<link rel="stylesheet" href="site-background.css"><link rel="stylesheet" href="global-nav.css"></head>
<body class="monitor-home{' dashboard-home' if title == 'ダッシュボード' else ' review-screen' if title == '差分レビュー' else ' support-screen' if title in ('監視の詳細', '履歴・通知', '証拠一覧') else ''}"><a class="skip-link" href="#main">メインコンテンツへスキップ</a>
<header class="site-header"><div class="header-inner"><div class="header-left"><p class="brand">{logo}<span class="brand-text">SITEPROOF</span></p><h1 class="page-title">{e(title)}</h1></div>
<div class="header-bar">{demo}{'' if title == 'ダッシュボード' else imported}<p class="updated">最後の監視 <time>{updated}</time><span class="sr-only"> 日本時間</span></p></div></div>{state_line if title == 'ダッシュボード' else ''}</header>{global_nav(current)}
<main id="main" class="main" tabindex="-1">{snapshot_notice}{body}</main><footer class="site-footer"><p>SITEPROOF</p>{'<p>総合品質：未評価</p>' if title == 'ダッシュボード' else ''}</footer>{script}</body></html>'''


def visual_view(change):
    """Operational image-check wording. Not a quality verdict, not HTTP state, not renderer authenticity."""
    v = change.get('visual')
    if not change.get('observed_at') or not v:
        return {'kind': 'none', 'label': '未取得', 'detail': '', 'audit': '未取得', 'image': '', 'quality': ''}
    kind = {'VISUAL_CHANGED': 'changed', 'NO_VISUAL_CHANGE_DETECTED': 'unchanged', 'UNKNOWN': 'unknown'}.get(v['verdict'], 'legacy')
    a = v['audit']
    audit = {'MISSING': '記録なし（旧データ）', 'UNAVAILABLE': '取得不可（遮断0件の意味ではありません）',
             'INVALID': '記録が不正です'}.get(a['state']) or (
        f'許可 {a["allowed"]} ／ 遮断 {a["blocked"]} ／ 失敗 {a["failed"]}' + ('' if a['complete'] else ' ／ 記録が不完全'))
    b = v.get('browser') or {}
    if b.get('state') == 'RECORDED':
        audit += f'｜ブラウザ報告：読み込み失敗 {b["failed"] + b["http_errors"]}件（TLS {b["tls"]}）' + ('' if b['complete'] else '・記録が不完全')
        audit += '・JavaScriptエラー ' + ('未記録（この撮影の時点では記録していません）' if b.get('script_errors') is None else f'{b["script_errors"]}件')
    elif b:
        audit += '｜ブラウザ報告：取得できていません'
    p = a.get('prelude')
    if a['state'] == 'RECORDED' and p and (p['blocked'] or p['failed'] or p['idle']):
        audit += f'｜撮影前（ブラウザ起動時）の拒否・空接続 {p["blocked"] + p["failed"] + p["idle"]}件（記録済み・撮影の対象外）'
    if a['state'] == 'RECORDED' and a['refused']:
        audit += '（' + '、'.join(f'{x["host"] or "不明"}:{x["port"] or "-"} {x["reason"]}' for x in a['refused'][:3]) + '）'
    parts = list(v['reason_labels'][:3]) if kind == 'unknown' else []
    if v['recorded'] and v['unattested']:
        parts.append('撮影環境の真正性未確認')
    # The pixel comparison and the inspection quality, side by side: "no pixel changed" stays visible when the verdict is UNKNOWN.
    image = (v.get('image') or {}).get('label', '') if (v.get('image') or {}).get('state') != 'NOT_COMPARED' else ''
    return {'kind': kind, 'label': v['label'], 'detail': '／'.join(parts), 'audit': audit, 'image': image,
            'quality': (v.get('quality') or {}).get('label', '') if image else ''}


def visual_note(change):
    v = visual_view(change)
    if v['kind'] == 'none':
        return ''
    detail = f'<small>{e(v["detail"])}</small>' if v['detail'] else ''
    split = (f'<span class="visual-split"><span data-image-comparison>{e(v["image"])}</span> ／ <span data-inspection-quality>{e(v["quality"])}</span></span>'
             if v['image'] else '')
    return f'<p class="visual-note {v["kind"]}" data-visual="{v["kind"]}">{e(v["label"])}{split}{detail}</p>'


def baseline_wording(change):
    """'承認済み' for a Baseline a person approved (or one with no registry record); an automatic one says what it is."""
    from .baseline_registry import STANDING_LABELS, baseline_standing
    standing = baseline_standing(change)
    return STANDING_LABELS[standing][0] if standing else '承認済み'


def plan_note(page):
    """The page's place in image monitoring (primary / candidate / supplemental) and whether it was captured. Empty without a plan."""
    from .captures import plan_summary
    plan = plan_summary(page)
    if not plan['role']:
        return ''
    change = page['change']
    if change.get('captures') and change.get('comparison_after_approval') == 'NOT_RUN':  # Approved, nothing captured or compared since.
        kinds = '・'.join(b['kind'] for b in change['baseline_registry']['baselines'])
        text = (f'撮影済み（{jst(change.get("observed_at"))}）／ Baseline {baseline_wording(change)}（{kinds}・{jst(change["baseline_registry"]["approved_at"], True)}）'
                ' ／ 承認後の実サイト撮影・比較 未実施')
    elif change.get('captures'):  # Three separate facts, never merged into one "OK": captured / Baseline / comparison.
        baseline = baseline_wording(change) if change.get('baseline_approved') is True else '未承認'
        compared = '実施済み' if change.get('metrics') is not None else '未実施'
        text = f'撮影済み ／ Baseline {baseline} ／ 比較 {compared}'
    else:
        text = '画像：未撮影 ／ ' + plan['state_label']
    return f'<p class="plan-note" data-plan-role="{e(plan["role"])}"><strong>{e(plan["role_label"])}</strong><span>{e(text)}</span></p>'


def page_attention(page):
    """UI review flag only; never rewrites HTTP, comparison or quality states."""
    change = page['change']
    return (page['http']['state'] != 'UP' or change['state'] != 'UNCHANGED'
            or change.get('baseline_approved') is not True
            or change.get('source_availability') != 'VERIFIED')


def pending_baseline(page):
    """An explicit pending approval, not a missing observation."""
    change = page['change']
    return (parse_utc(change.get('observed_at')) is not None
            and change.get('baseline_approved') is False)


def folder_status(pages):
    """UI summary only: HTTP, approval, comparison and evidence stay separate."""
    counts = {
        'http_down': sum(p['http']['state'] == 'DOWN' for p in pages),
        'action': sum(pending_baseline(p) for p in pages),
        'changed': sum(p['change']['state'] == 'CHANGED' for p in pages),
        'attention': sum(page_attention(p) for p in pages)}
    level = ('danger' if counts['http_down'] else 'action' if counts['action']
             else 'changed' if counts['changed'] else 'unknown'
             if counts['attention'] else 'normal')
    return level, counts


def scroll_card(inner, label):
    """Body that scrolls inside its card. The buttons stay hidden until scrollcard.js finds an overflow."""
    return (f'<div class="scroll-card" data-scroll-card><div class="scroll-body" tabindex="0" role="region" aria-label="{e(label)}">{inner}</div>'
            f'<div class="scroll-ctl" hidden><button type="button" data-scroll="up" aria-label="{e(label)}を上へスクロール">▲</button>'
            f'<button type="button" data-scroll="down" aria-label="{e(label)}を下へスクロール">▼</button></div></div>')


SCOPE_HTML = ('<details class="panel" id="scope"><summary>監視できること・できないこと</summary><ul>'
    '<li>見ているのは<strong>HTTPの応答状態</strong>（死活監視）です。ページの内容・表示崩れは見ません。HTTP 200でも内容の異常は検知できません。</li>'
    '<li><strong>15分ごと</strong>に確認します。短時間で直る障害は見逃すことがあります。</li>'
    '<li>障害通知は、直近3回の確認のうち<strong>2回以上</strong>失敗した時に出ます（約30分後）。復旧通知も、正常が続いた後です。</li>'
    '<li>名前解決の失敗やリダイレクト（3xx）は障害ではなく「判定不能」として扱い、<strong>監視ヘルスの通知</strong>になります。</li>'
    '<li>通知はメール（SNS）です。この画面は保存した履歴の閲覧用で、<strong>現在の稼働状態は表示しません</strong>。</li></ul></details>')
KIND_LABELS = {'failure': 'HTTP障害', 'unpersisted': '監視ヘルス', 'function-error': '関数エラー'}
OUTCOME_STATE = {'PASS': 'UP', 'FAIL': 'DOWN'}


def archive_events(view, labels, limit):
    """Newest stored observations of the real monitored sites (archive only)."""
    rows = [{'at': r['finished_at'] or r['scheduled_slot'], 'label': labels[tid], 'state': OUTCOME_STATE.get(r['outcome'], 'UNKNOWN'),
             'event': (f"HTTP {r['http_status']} · {r['elapsed_ms']} ms" if r['http_status'] is not None else (r['reason'] or '結果なし'))}
            for tid, s in view['archive']['sites'].items() if tid in labels for r in s['recent']]
    rows.sort(key=lambda x: x['at'], reverse=True)
    return rows[:limit]


def render_archive_activity(view):
    """Stored monitoring history. Real sites and the Gate B fixture trial are kept in separate sections."""
    a = view.get('archive')
    if not a:
        return ''
    labels = {p['target_id']: p.get('site_name', p['domain']) + ' / ' + p['label'] for p in view['pages']}
    def group_table(group):
        rows = ''.join(f'<tr><th scope="row">{e(p["label"])}</th><td data-label="記録">{s["runs"]}</td><td data-label="正常">{s["pass"]}</td><td data-label="異常">{s["fail"]}</td><td data-label="判定不能">{s["unknown"]}</td>'
                       f'<td data-label="正常率">{e(s["availability_percent"])}%</td><td data-label="平均応答">{e(s["avg_elapsed_ms"])} ms</td><td data-label="期間（JST）">{jst(s["first_slot"])} 〜 {jst(s["last_slot"])}</td></tr>'
                       for p in group for s in [a['sites'].get(p['target_id'])] if s)
        return ('<div class="support-table"><table class="runs-table"><thead><tr><th scope="col">対象ページ</th><th scope="col">記録</th><th scope="col">正常</th><th scope="col">異常</th><th scope="col">判定不能</th>'
                f'<th scope="col">正常率</th><th scope="col">平均応答</th><th scope="col">期間（JST）</th></tr></thead><tbody>{rows}</tbody></table></div>')
    summary = project_groups(view, group_table)
    recent = ''.join(f'<tr><td><time>{jst(x["at"])}</time></td><td>{e(x["label"])}</td><td>{tag(x["state"])}</td><td>{e(x["event"])}</td></tr>' for x in archive_events(view, labels, 30))
    real = [i for s in a['sites'].values() for i in s['incidents']]
    real_text = f'実サイトの障害記録：{len(real)}件' + ('（保存期間内に連続失敗はありません）' if not real else '')
    html = (f'<section class="panel" id="stored-runs"><div class="panel-head"><h2>保存済みの監視記録（実サイト）</h2><p class="panel-note">データ取得：{jst(a["fetched_at"])} JST</p></div>'
            f'<p>AWSから取得してローカルに保存した記録です。<strong>現在の稼働状態を示すものではありません</strong>。{e(real_text)}。間隔の空いた時間帯は監視を停止していた期間です。</p>'
            f'{summary}'
            f'<details><summary>直近の監視記録（最新30件）</summary><div class="support-table"><table><thead><tr><th scope="col">確認日時（JST）</th><th scope="col">対象</th><th scope="col">判定</th><th scope="col">HTTP・応答時間</th></tr></thead><tbody>{recent}</tbody></table></div></details></section>')
    trial = a['trial']
    if trial['targets']:
        incident_rows = ''.join(f'<tr><td>{jst(i["started_at"])}</td><td>{jst(i["last_failure_at"])}</td><td>{jst(i["recovered_at"]) if i["recovered_at"] else "継続中"}</td><td>{i["failed_runs"]}回</td><td>{e(",".join(map(str, i["http_statuses"])))}</td></tr>'
                                for t in trial['targets'].values() for i in t['incidents'])
        event_rows = ''.join(f'<tr><td><time>{jst(x["at"])}</time></td><td>{KIND_LABELS.get(x["alarm_kind"], "")}</td><td>{e(x["old_state"])} → {e(x["new_state"])}</td></tr>'
                             for x in trial['alarm_events'] if x['alarm_kind'] == 'failure' and x['old_state'] != 'INSUFFICIENT_DATA')
        html += (f'<section class="panel" id="trial"><div class="panel-head"><h2>障害・復旧の動作確認（試験）</h2><p class="panel-note">試験用Fixture · 実サイトの障害ではありません</p></div>'
                 f'<p>2026-11-15、試験用の応答先（Fixture）を意図的にHTTP 503にして、障害の検知から復旧までの通知を確認した記録です。障害メール・復旧メールの受信はUSER報告です。</p>'
                 f'<div class="support-table"><table><thead><tr><th scope="col">障害開始（JST）</th><th scope="col">最終失敗</th><th scope="col">復旧確認</th><th scope="col">失敗回数</th><th scope="col">HTTP</th></tr></thead><tbody>{incident_rows}</tbody></table></div>'
                 f'<div class="support-table"><table><thead><tr><th scope="col">アラーム状態の変化（JST）</th><th scope="col">種類</th><th scope="col">変化</th></tr></thead><tbody>{event_rows}</tbody></table></div></section>')
    return html


# ---- monitoring status / history / events (monitoring.build). Real and demo data never share a section.
MON_BADGES = {'UNCHANGED': ('pass', '変更なし'), 'CHANGED': ('changed', '変更あり'), 'UNKNOWN': ('unknown', '判定不能'), 'FAILED': ('alert', '撮影失敗'),
              'NOT_COMPARED': ('none', '比較なし'), 'STALE': ('unknown', '長期間未監視'), 'RECOVERED': ('pass', '復旧'),
              'NOT_RUNNING': ('none', '予定・未稼働'), 'SCHEDULED': ('pass', '自動実行中'), 'STOPPED': ('alert', '停止'),
              'OVERDUE': ('unknown', '予定超過'), 'RECENT': ('pass', '記録あり'), 'NONE': ('unknown', '記録なし'),
              'PROVIDER_UNKNOWN': ('unknown', 'Provider管理・未確認'), 'UNVERIFIED': ('unknown', '有効の記録あり・未確認'), 'UNKNOWN': ('unknown', '未確認')}


def mon_badge(state, label=None):
    tone, text = MON_BADGES.get(state, ('unknown', '未確認'))
    return f'<span class="mon-badge mon-{tone}" data-mon="{e(state)}">{e(label or text)}</span>'


def http_result(http):
    """The last saved HTTP result in words; whether it is old is shown separately (freshness badge)."""
    outcome, status = http.get('last_outcome'), http.get('http_status')
    if outcome == 'PASS':
        return mon_badge('RECENT', f'前回 正常（HTTP {status}）')
    if outcome == 'FAIL':
        return mon_badge('STOPPED', f'前回 異常（HTTP {status if status is not None else "応答なし"}）')
    return mon_badge('NONE', '結果なし')


def interval_text(seconds):
    return f'{seconds // 3600}時間ごと' if seconds % 3600 == 0 else f'{seconds // 60}分ごと'


def _mon_labels(view):
    return {p['target_id']: p.get('site_name', p['domain']) + ' / ' + p['label'] for p in view['pages']}


def render_schedule(view):
    """HOME: the monitoring state first (is anything running, when was the last good result, what is next), one row per page x channel."""
    m = view.get('monitoring')
    if not m:
        return ''
    labels = _mon_labels(view)
    demo = '（合成デモ）' if m['synthetic'] else ''
    last = m['last_success']
    states = {c['channel']: c['schedule_state'] for r in m['rows'] for c in r['channels'] if c['schedule_state'] != 'NO_SETTING'}
    next_text = ' ／ '.join(x for x in (
        '画像：自動実行なし（予定・未稼働）' if states.get('capture') == 'NOT_RUNNING' else '',
        'HTTP：Provider（AWS-B）管理・現在の予定は未確認' if states.get('http') in ('PROVIDER_UNKNOWN', 'UNVERIFIED') else '') if x) or '各行を参照'

    def last_of(channel):
        found = max(((c['last_success_at'], r['target_id'], c['freshness']) for r in m['rows'] for c in r['channels']
                     if c['channel'] == channel and c['last_success_at']), default=None)
        if not found:
            return None
        return f'{"画像" if channel == "capture" else "HTTP"} {jst(found[0])}（{labels.get(found[1], found[1])}{"・観測が古い" if found[2] == "STALE" else ""}）'
    last_text = ' ／ '.join(x for x in (last_of('capture'), last_of('http')) if x) or '記録なし'
    rows = []
    for r in m['rows']:
        for c in r['channels']:
            if c['schedule_state'] == 'NO_SETTING':
                continue
            result = ''.join(mon_badge(x['class']) + f'<small>{e(x["kind"])}</small>' for x in c.get('latest', [])) if c['channel'] == 'capture' else (
                http_result(next(p for p in view['pages'] if p['target_id'] == r['target_id'])['http']))
            fresh = mon_badge('STALE') if c['freshness'] == 'STALE' else mon_badge('NONE') if c['freshness'] == 'NONE' else ''
            nxt = (jst(c['next_due_at']) if c['next_due_at'] else 'Providerの状態を未取得' if c['schedule_state'] == 'PROVIDER_UNKNOWN'
                   else f'不明（有効の記録 {jst(c["observed_at"])}）' if c['schedule_state'] == 'UNVERIFIED' else '自動実行なし')
            rows.append(f'<tr data-target-id="{e(r["target_id"])}" data-channel="{c["channel"]}"><th scope="row"><a href="details.html#{e(r["target_id"])}">{e(labels[r["target_id"]])}</a></th>'
                        f'<td data-label="種類">{e(c["channel_label"])}</td><td data-label="間隔">{interval_text(c["interval_seconds"])}</td>'
                        f'<td data-label="前回の監視"><time>{jst(c["last_at"]) if c["last_at"] else "未実施"}</time></td>'
                        f'<td data-label="結果">{result or "—"} {fresh}</td><td data-label="次回予定">{e(nxt)}</td><td data-label="状態">{mon_badge(c["schedule_state"])}</td></tr>')
    table = ('<div class="support-table"><table class="runs-table schedule-table"><thead><tr><th scope="col">監視ページ</th><th scope="col">種類</th><th scope="col">間隔</th>'
             '<th scope="col">前回の監視</th><th scope="col">結果</th><th scope="col">次回予定</th><th scope="col">状態</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')
    return (f'<section class="panel schedule-panel" id="schedule" aria-labelledby="schedule-heading"><div class="panel-head"><h2 id="schedule-heading">監視の状態{demo} <span class="h-en">SCHEDULE</span></h2>'
            f'<a class="panel-link" href="{"activity.html#monitoring-history" if m["history"] else "activity.html"}">監視履歴を見る ›</a></div>'
            f'<dl class="schedule-summary"><div><dt>現在の監視状態</dt><dd>{mon_badge(m["overall"] if m["overall"] != "ATTENTION" else "OVERDUE", m["overall_label"])}</dd></div>'
            f'<div><dt>最後に正常に監視できた日時</dt><dd>{e(last_text)}</dd></div>'
            f'<div><dt>次回の監視予定</dt><dd>{next_text}</dd></div></dl>'
            f'<p class="panel-note">保存済みの結果です。過去の正常結果は、現在も監視が動いている証拠ではありません。品質は未評価（UNKNOWN）です。</p>'
            + table + '</section>')


def monitoring_notices(view):
    """HOME notices from the latest state per page and profile (one notice per state, never one per repeated observation)."""
    m = view.get('monitoring')
    if not m:
        return []
    labels, out = _mon_labels(view), []
    icons = {'CHANGED': ('change', '↗'), 'UNKNOWN': ('pending', '⚠'), 'FAILED': ('danger', '!'), 'STALE': ('pending', '⚠')}
    for n in m['notices']:
        tone, icon = icons[n['type']]
        who = labels.get(n['target_id'], n['target_id']) + (f'（{n["kind"]}）' if n['kind'] else '')
        detail = f'<span>{e(who)}{"・" + e(n["detail"]) if n["detail"] else ""}{" ・合成デモ" if n["synthetic"] else ""}</span>'
        href = f'review.html#{e(n["target_id"])}' if n['type'] in ('CHANGED', 'UNKNOWN') else 'activity.html#monitoring-history' if m['history'] else '#schedule'
        out.append(f'<li class="notice {tone}" data-mon-notice="{n["type"]}"><span class="notice-icon" aria-hidden="true">{icon}</span><div><strong>{e(n["label"])}</strong>{detail}</div><a href="{href}">確認する ›</a></li>')
    for state, title, note in (('STOPPED', '監視が停止中', '監視の設定が停止になっています。'),
                               ('OVERDUE', '予定時刻を過ぎても未実行', '予定どおりに実行されていません。正常稼働とはみなしません。')):
        hit = [labels.get(r['target_id'], r['target_id']) + '（' + c['channel_label'] + '）' for r in m['rows'] for c in r['channels'] if c['schedule_state'] == state]
        if hit:
            out.append(f'<li class="notice {"danger" if state == "STOPPED" else "pending"}" data-mon-notice="{state}"><span class="notice-icon" aria-hidden="true">!</span>'
                       f'<div><strong>{title} {len(hit)}件</strong><span>{e(hit[0])}{" ほか" if len(hit) > 1 else ""}。{note}</span></div><a href="#schedule">監視の状態を見る ›</a></li>')
    http = [c for r in m['rows'] for c in r['channels'] if c['channel'] == 'http' and c['schedule_state'] != 'NO_SETTING']
    none, stale = [c for c in http if c['freshness'] == 'NONE'], [c for c in http if c['freshness'] == 'STALE']
    if none or stale:  # no / old HTTP observation is missing information, never "up"
        parts = ([f'結果なし {len(none)}ページ'] if none else []) + ([f'観測が古い {len(stale)}ページ'] if stale else [])
        latest = max((c['last_at'] for c in stale), default=None)
        note = (f'最後の観測は {jst(latest)}（JST）で、それ以降の記録がありません。' if latest else 'HTTPの監視結果がありません。')
        out.append(f'<li class="notice pending" data-mon-notice="HTTP_MISSING"><span class="notice-icon" aria-hidden="true">⚠</span><div><strong>HTTP監視：{e("・".join(parts))}</strong>'
                   f'<span>{e(note)}現在稼働しているかは不明です（障害の確定ではありません）。</span></div><a href="#schedule">監視の状態を見る ›</a></li>')
    if m.get('provider_unknown'):
        seen = max((c['observed_at'] for c in m['provider_unknown'] if c.get('observed_at')), default=None)
        detail = (f'最後に確認できた記録（{jst(seen)} JST）では定期実行は有効でしたが、それ以降は確認していません。' if seen
                  else 'Providerの稼働状態を取得していません。')
        out.append(f'<li class="notice pending" data-mon-notice="PROVIDER_UNKNOWN"><span class="notice-icon" aria-hidden="true">⚠</span><div><strong>HTTP監視（AWS-B）が今も動いているかは未確認</strong>'
                   f'<span>{e(detail)}現在動いているか・止まっているかは、この画面では分かりません。</span></div><a href="#schedule">監視の状態を見る ›</a></li>')
    if m['not_running']:
        out.append('<li class="notice neutral" data-mon-notice="NOT_RUNNING"><span class="notice-icon" aria-hidden="true">ℹ</span><div><strong>画像の自動監視は未稼働です</strong>'
                   '<span>画像の撮影・比較は自動実行していません。表示は保存済みの結果です。</span></div><a href="#schedule">監視の状態を見る ›</a></li>')
    return out


def monitoring_log_events(view):
    """Image-monitoring events for HOME's latest log (state changes only)."""
    m = view.get('monitoring')
    if not m:
        return []
    labels = _mon_labels(view)
    state = {'UNCHANGED': 'UNCHANGED', 'CHANGED': 'CHANGED', 'RECOVERED': 'UP', 'FAILED': 'DOWN'}
    return [{'at': x['at'], 'label': labels.get(x['target_id'], x['target_id']) + f'（{x["kind"]}）', 'state': state.get(x['type'], 'UNKNOWN'),
             'event': '画像：' + x['label']} for x in m['events'] if x['type'] != 'NOT_COMPARED']


def render_monitoring_history(view):
    """ACTIVITY: saved image-monitoring history (one row per capture job) and its events, newest first."""
    m = view.get('monitoring')
    if not m or not m['history']:
        return ''
    labels = _mon_labels(view)
    demo = m['synthetic']
    def baseline(h):
        return f'{h["baseline"]["candidate_id"][:16]}… v{h["baseline"]["version"]}' if h['baseline'] else '未承認（候補のみ）'
    def pixels(h):
        return f'{h["changed_pixels"]:,} / {h["total_pixels"]:,} px' if h['total_pixels'] else '—'
    def links(h):  # REVIEW shows each page's latest run only; older jobs link to DETAIL
        tid = e(h['target_id'])
        return (f'<a href="review.html#{tid}">REVIEW</a> ・ ' if h['in_review'] else '') + f'<a href="details.html#{tid}">DETAIL</a>'
    rows = ''.join(
        f'<tr data-target-id="{e(h["target_id"])}" data-job-id="{e(h["job_id"])}"><th scope="row">{e(labels.get(h["target_id"], h["target_id"]))}</th>'
        f'<td data-label="撮影日時（JST）"><time>{jst(h["observed_at"])}</time></td><td data-label="表示サイズ">{e(h["kind"])}</td>'
        f'<td data-label="実行結果">{"撮影成功" if h["execution"] == "COMPLETED" and h["class"] != "FAILED" else "失敗"}</td>'
        f'<td data-label="Baseline比較">{e(baseline(h))}</td><td data-label="変更の有無">{mon_badge(h["class"])} <small>{e(pixels(h))}</small></td>'
        f'<td data-label="画像比較／検査品質">{e(h.get("image_label") or "—")}<br><small>{e(h.get("quality_label") or "")}</small></td>'
        f'<td data-label="確認">{links(h)}</td></tr>'
        for h in m['history'])
    events = ''.join(f'<tr data-target-id="{e(x["target_id"])}"><td data-label="日時（JST）"><time>{jst(x["at"])}</time></td><td data-label="対象">{e(labels.get(x["target_id"], x["target_id"]))}（{e(x["kind"])}）</td>'
                     f'<td data-label="出来事">{mon_badge(x["type"])} {e(x["label"])}</td></tr>' for x in m['events'])
    title = '画像監視の履歴（合成デモ・実サイトの結果ではありません）' if demo else '画像監視の履歴（実測・保存済み）'
    return (f'<section class="panel" id="monitoring-history"><div class="panel-head"><h2>{title}</h2><p class="panel-note">{len(m["history"])}件の撮影 ・ 出来事 {len(m["events"])}件</p></div>'
            f'<p>保存済みの撮影・比較の記録です（同じ撮影Jobは1件として表示）。<strong>現在の稼働状態を示すものではありません。</strong>REVIEWでは各ページの最新の撮影を表示します。</p>'
            f'<div class="support-table"><table class="runs-table history-table"><thead><tr><th scope="col">監視ページ</th><th scope="col">撮影日時（JST）</th><th scope="col">表示サイズ</th>'
            f'<th scope="col">実行結果</th><th scope="col">Baseline比較</th><th scope="col">変更の有無</th><th scope="col">画像比較／検査品質</th><th scope="col">確認</th></tr></thead><tbody>{rows}</tbody></table></div>'
            f'<h3>監視の出来事（状態が変わった時だけ）</h3><div class="support-table"><table class="runs-table"><thead><tr><th scope="col">日時（JST）</th><th scope="col">対象</th>'
            f'<th scope="col">出来事</th></tr></thead><tbody>{events or "<tr><td colspan=3>記録なし</td></tr>"}</tbody></table></div></section>')


def render(view):
    _, status_icons, launcher_icons = assets()
    pages = view['pages']
    from .operations import home_section
    up = sum(p['http']['state'] == 'UP' for p in pages)
    down = sum(p['http']['state'] == 'DOWN' for p in pages)
    stopped = sum(p['http']['state'] == 'STOPPED' for p in pages)
    unknown = len(pages) - up - down - stopped
    changes = sum(p['change']['state'] == 'CHANGED' for p in pages)
    change_unknown = sum(p['change']['state'] == 'UNKNOWN' for p in pages)
    attention = sum(page_attention(p) for p in pages)
    expiry_attention = sum(x['state'] in ('WARNING', 'EXPIRED') for x in view['expiry'])
    expiry_unknown = sum(x['state'] == 'UNKNOWN' for x in view['expiry'])
    sites = {p.get('site_id', p['domain']): p.get('site_name', p['domain']) for p in pages}
    unverified = sum(page_attention(p) and p['http']['state'] != 'DOWN' for p in pages)
    from .captures import plan_summary
    image_pages = sum(bool(plan_summary(p)['role']) for p in pages)  # image monitoring: pages with a capture plan
    http_pages = sum(p['http']['state'] != 'NOT_FETCHED' for p in pages)  # HTTP monitoring: pages with an HTTP result (a page can be in both)
    summary = [
        ('監視対象', f'{len(pages)}ページ', f'HTTP監視 {http_pages}ページ・画像監視 {image_pages}ページ（{len(sites)}プロジェクト）', '', 'index.html?filter=all#pages', 'すべての監視ページを見る'),
        ('保存時点のHTTP結果', f'異常 {down}' if down else f'正常 {up}' if up else '未確認', f'正常 {up} ・ 未確認 {unknown} ・ 停止 {stopped}', 'card-danger' if down else 'card-amber' if unknown else 'card-neutral' if stopped else '', 'index.html?filter=up#pages', '正常のページを見る'),
        ('変更検知', f'変更 {changes}' if changes else '未確認' if change_unknown else '変更なし', f'未確認 {change_unknown}ページ', 'card-changed' if changes else 'card-neutral' if change_unknown else '', 'review.html', '差分レビューを開く'),
        ('要確認', f'{attention}ページ', f'障害 {down} ・ 未検証 {unverified} ・ 期限未取得 {expiry_unknown}', 'card-danger' if down else 'card-amber' if any(pending_baseline(p) for p in pages) or expiry_attention or unknown or expiry_unknown else 'card-neutral' if attention else '', 'index.html?filter=attention#pages', '要確認のページを見る')]
    cards = ''.join(f'<a class="status-card {color}" href="{href}" aria-label="{label}：{value}。{hint}">{status_icons[i]}<h3>{label}</h3><p class="card-value">{value}</p><p class="card-meta"><span class="summary-badge">{meta}</span></p><span class="card-go" aria-hidden="true">{hint} ›</span></a>' for i, (label,value,meta,color,href,hint) in enumerate(summary))
    project_options = ''.join(f'<option value="{e(sid)}">{e(name)}</option>' for sid, name in sites.items())
    labels = {p['target_id']: p.get('site_name', p['domain']) + ' / ' + p['label'] for p in pages}
    events = [{'at': h['at'], 'label': labels[h['target_id']], 'state': 'DOWN' if h['event'] == '異常を検知' else 'UP', 'event': '異常を検知' if h['event'] == '異常を検知' else '復旧を確認'} for h in view['history']]
    image_events = monitoring_log_events(view)
    events += image_events or [{'at': p['change']['observed_at'], 'label': labels[p['target_id']], 'state': 'CHANGED', 'event': '変更を検知'} for p in pages if p['change']['state'] == 'CHANGED']
    events.sort(key=lambda x: x['at'], reverse=True)
    if not events and view.get('archive'):
        events = archive_events(view, labels, 5)
    logs = ''.join(f'<li class="log-row"><p class="log-head">{tag(x["state"])}</p><p class="log-body"><span class="log-event">{e(x["event"])}</span><span class="log-target">{e(x["label"])}</span></p><p class="log-time"><time>{jst(x["at"])}</time></p></li>' for x in events[:5])
    if not logs:
        logs = '<li class="log-row"><p class="log-event">履歴未取得</p></li>'
    folders = []
    for index, (site_id, site) in enumerate(sites.items()):
        group = [p for p in pages if p.get('site_id', p['domain']) == site_id]
        level, counts = folder_status(group)
        changed_count, attention_count = counts['changed'], counts['attention']
        symbol, priority_label = {
            'danger': ('!', 'HTTP異常あり'), 'action': ('!', 'Baseline承認待ち'),
            'changed': ('↗', '画像変更あり'), 'unknown': ('', '未確認'),
            'normal': ('●', '稼働・比較確認済み')}[level]
        priority_symbol = f'<span class="priority-symbol" aria-label="{priority_label}">{symbol}</span>' if symbol else ''
        badges = (
            (f'<span class="folder-badge danger">HTTP異常 {counts["http_down"]}</span>' if counts['http_down'] else '')
            + (f'<span class="folder-badge action">未承認 {counts["action"]}</span>' if counts['action'] else '')
            + (f'<span class="folder-badge changed">変更あり {changed_count}</span>' if changed_count else '')
            + f'<span class="folder-badge neutral">要確認 {attention_count}</span>')
        rows = []
        for p in group:
            change = p['change']
            observed = [v for v in (p['http'].get('last_checked_at'), change.get('observed_at')) if parse_utc(v) and parse_utc(v) <= parse_utc(view['generated_at'])]
            last = max(observed, key=parse_utc) if observed else None
            search = ' '.join((site, p['label'], p['url']))
            path = p['url'].split(p['domain'], 1)[-1] or '/'
            site_url = None if p.get('trial_fixture') else safe_site_url(p.get('url'))
            site_link = f'<a class="external-site" href="{e(site_url)}" target="_blank" rel="noopener noreferrer">↗ サイトを開く</a>' if site_url else ''
            http = p['http']
            historical = '過去の観測 · ' if http.get('last_checked_at') and (view['source'] == 'AWS_EXPORT' or http['state'] in ('UNKNOWN', 'STALE', 'STOPPED')) else ''
            http_metrics = (f'<p class="http-metrics">{historical}HTTP {e(http["http_status"])} · {e(http["elapsed_ms"])} ms</p>'
                            if http.get('http_status') is not None else '')
            rows.append(f'''<article class="monitor-row" data-page-id="{e(p['target_id'])}" data-http-state="{e(http['state'])}" data-search="{e(search)}" data-changed="{'true' if change['state']=='CHANGED' else 'false'}" data-attention="{'true' if page_attention(p) else 'false'}">
<div class="page-cell"><h3><a href="details.html#{e(p['target_id'])}">{e(p['label'])}</a></h3><p class="page-url" title="{e(p['url'])}">{e(path)}</p>{site_link}{plan_note(p)}{visual_note(change)}</div>
<div><span class="mobile-label">稼働</span>{tag(p['http']['state'])}{http_metrics}</div><div><span class="mobile-label">変更</span>{tag(change['state'])}</div>
<div><span class="mobile-label">最終確認</span><time>{jst(last)}</time></div><a href="details.html#{e(p['target_id'])}" aria-label="{e(site+' / '+p['label']+'の詳細')}">詳細 <span aria-hidden="true">›</span></a></article>''')
        folders.append(f'''<details class="project-folder" data-project="{e(site_id)}" data-level="{level}" data-http-down="{counts['http_down']}" data-action="{counts['action']}" data-changed="{changed_count}" data-review="{attention_count}" {'open' if index == 0 else ''}>
<summary class="folder-summary">{priority_symbol}<span class="folder-name">{e(site)}</span><span data-page-count class="project-count">{len(group)}ページ</span><span class="folder-counts">{badges}</span></summary>
<div class="folder-content"><div class="monitor-labels" aria-hidden="true"><span>監視ページ</span><span>稼働</span><span>変更</span><span>最終確認</span><span></span></div>{''.join(rows)}</div></details>''')
    expiry = []
    for x in view['expiry']:
        days = x['remaining_days']
        when = '提供元管理' if x['state'] == 'PROVIDER_MANAGED' else '未取得' if x['state'] == 'UNKNOWN' else jst(x.get('expires_at'), True)
        remaining = '' if days is None or x['state'] == 'UNKNOWN' else f'残り{days}日' if days >= 0 else '期限切れ'
        expiry.append(f'<li class="expiry-row"><div><strong>{e(x["kind"])}</strong><span>{e(x["scope"])}</span></div><div>{tag(x["state"])}<p>{when} {remaining}</p></div></li>')
    latest = sorted((p for p in pages if p['change']['state'] == 'CHANGED'), key=lambda p: p['change'].get('observed_at') or '', reverse=True)
    changed_rows = ''.join(f'<a class="change-row" href="details.html#{e(p["target_id"])}"><span><strong>{e(p["label"])}</strong><small>{e(p.get("site_name",p["domain"]))}</small></span>{tag(p["change"]["state"])}<time>{jst(p["change"].get("observed_at"))}</time></a>' for p in latest[:3])
    if not changed_rows:
        changed_rows = f'<p class="card-meta">変更あり 0 ・ 未確認 {change_unknown}ページ</p>'
    notices = []
    for state, label, icon, selected in (
            ('danger', 'HTTP異常', '!', [p for p in pages if p['http']['state'] == 'DOWN']),
            ('pending', 'Baseline承認待ち', '!', [p for p in pages if pending_baseline(p)]),
            ('change', '画像変更', '↗', latest)):
        if selected:
            first = selected[0]
            href = '#changes' if state == 'change' else 'details.html#' + e(first['target_id'])
            target = e(first.get('site_name', first['domain']) + ' / ' + first['label'])
            notices.append(f'<li class="notice {state}"><span class="notice-icon" aria-hidden="true">{icon}</span><div><strong>{label} {len(selected)}件</strong><span>{target}</span></div><a href="{href}" aria-label="{label}の詳細">対象を確認する ›</a></li>')
    if expiry_attention:
        notices.append(f'<li class="notice pending"><span class="notice-icon" aria-hidden="true">!</span><div><strong>期限の確認 {expiry_attention}件</strong></div><a href="details.html#expiry">期限の一覧を見る ›</a></li>')
    if not notices:
        reminders = []   # (headline, explanation, link, link text, tone, icon)
        if view['source'] == 'AWS_EXPORT' and up and not down:
            reminders.append(('HTTP障害は記録されていません', '保存した監視結果に、失敗の記録はありません（保存時点）。', 'activity.html#stored-runs' if view.get('archive') else 'activity.html', '監視記録を見る', 'neutral ok', '✓'))
        if unknown or view['source'] == 'AWS_EXPORT':
            reminders.append(('現在の稼働状態は確認できません',
                              '保存済みのデータで、リアルタイムではありません。' if view['source'] == 'AWS_EXPORT' else '監視結果が未取得・不明、または観測が古い状態です。',
                              'details.html#scope', '監視の範囲と限界を見る', 'neutral', 'ℹ'))
        elif stopped:
            reminders.append(('保存記録上、監視は停止中です', 'サイト障害を意味するものではありません。', 'details.html#summary', '監視設定を見る', 'neutral', 'ℹ'))
        if change_unknown or any(p['change'].get('source_availability') != 'VERIFIED' for p in pages):
            reminders.append(('画像の比較と証拠は未検証です', '障害ではなく、撮影・Baseline承認・証拠の確認が済んでいない項目です。', 'review.html', '差分レビューを開く', 'pending', '⚠'))
        if expiry_unknown:
            kinds = '・'.join(sorted({x['kind'] for x in view['expiry'] if x['state'] == 'UNKNOWN'}))
            reminders.append((f'{kinds}の期限が未取得です', '期限を取得できていない項目です。障害ではありません。', 'details.html#expiry', '期限の一覧を見る', 'pending', '⚠'))
        if not reminders:
            reminders.append(('対応が必要な項目はありません', '', 'details.html#evidence', '証拠一覧を見る', 'neutral ok', '✓'))
        for text, note, href, link_text, tone, icon in reminders:
            supplement = f'<span>{e(note)}</span>' if note else ''
            notices.append(f'<li class="notice {tone}"><span class="notice-icon" aria-hidden="true">{icon}</span><div><strong>{e(text)}</strong>{supplement}</div><a href="{href}">{e(link_text)} ›</a></li>')
    # Monitoring notices after the existing ones: undecided / failed / stale / stopped / overdue / not running. The image change is
    # already one notice above, and "HTTP unknown" already has its reminder when that one is shown.
    said = ''.join(notices)
    notices += [n for n in monitoring_notices(view)
                if not (latest and 'data-mon-notice="CHANGED"' in n) and not ('現在の稼働状態は確認できません' in said and 'data-mon-notice="HTTP_MISSING"' in n)]
    body = f'''<section class="panel status-panel" aria-labelledby="status-heading"><div class="panel-head"><h2 id="status-heading">保存済みの監視結果の概要 <span class="h-en">STATUS</span></h2></div><div class="status-cards">{cards}</div></section>
{render_schedule(view)}
<div class="overview-row" aria-label="期限と最新ログ"><details class="expiry-panel mini mini-cyan" open><summary>証明書・ドメイン期限 <span class="panel-note">注意 {expiry_attention} ・ 未取得 {expiry_unknown}</span></summary>{scroll_card('<ul class="expiry-list">' + ''.join(expiry) + '</ul>', '証明書・ドメイン期限の一覧')}<a class="support-detail" href="details.html#expiry">期限の詳細 ›</a></details>
<details id="activity" class="log-section activity-panel mini mini-blue" open><summary>最新ログ <span class="panel-note">{len(events)}件</span>{'<span class="log-demo">デモ</span>' if view['source']=='FIXTURE' else ''}</summary>{scroll_card('<ol class="log-list">' + logs + '</ol>', '最新ログの一覧')}</details></div>
{home_section()}
<div class="monitor-layout"><section class="panel projects-panel" id="pages" aria-labelledby="pages-heading"><div class="panel-head"><h2 id="pages-heading">プロジェクト・監視ページ</h2><p id="visible-count" role="status" aria-live="polite">表示 {len(pages)} / {len(pages)} ページ</p></div>
<div class="folder-toolbar" id="folder-tools" hidden><label for="project-select" class="tool-select">プロジェクト<select id="project-select"><option value="">すべてのプロジェクト</option>{project_options}</select></label><label for="folder-search">検索<input id="folder-search" type="search" maxlength="200" placeholder="プロジェクト・ページ・URL" aria-controls="project-folders" autocomplete="off"></label><div class="folder-filters" role="group" aria-label="監視ページの絞り込み"><button type="button" data-filter="all" aria-pressed="true">すべて</button><button type="button" data-filter="up" aria-pressed="false">正常</button><button type="button" data-filter="changed" aria-pressed="false">変更あり</button><button type="button" data-filter="attention" aria-pressed="false">要確認</button></div></div>
<noscript><p class="card-meta">プロジェクト名を選ぶとページ一覧を開閉できます。</p></noscript><div class="project-list" id="project-folders">{''.join(folders)}</div><p id="folder-empty" role="status" hidden>一致する監視ページはありません。</p></section>
<aside class="monitor-support" aria-label="確認事項"><section class="panel notices-panel"><div class="panel-head"><h2>確認すること</h2></div><ul class="notice-list">{''.join(notices)}</ul></section><details id="changes" class="panel changes-panel"><summary>最新の変更検知 <span class="panel-note">{changes}ページ</span></summary>{changed_rows}<a class="support-detail" href="details.html#evidence">画像・証拠の詳細 ›</a></details></aside></div>
'''
    return shell(view, body)


def support_navigation(current):
    """Kept for callers; the shared top menu now lives in shell()."""
    return ''


def inspection_summary(page, record):
    """Saved execution/check facts are not an aggregate quality verdict."""
    result = page['change'].get('result') or {}
    checks = result.get('checks', [])
    if not isinstance(checks, list):
        checks = []
    outcomes = {'PASS', 'FAIL', 'SKIPPED', 'UNKNOWN', 'NOT_RUN'}
    check_text = ' ／ '.join(
        str(c.get('type', 'UNKNOWN')) + ': ' + str(c.get('outcome') if c.get('outcome') in outcomes else 'UNKNOWN')
        for c in checks if isinstance(c, dict)) or '未取得'
    vv = {'label': record['visual_label'], 'detail': record['visual_detail'], 'audit': record['audit_label']}  # = page_view's projection
    return f'<dl class="inspection-summary"><dt>Job実行（保存値）</dt><dd>{e(result.get("execution", "UNKNOWN"))}</dd><dt>Check（保存値）</dt><dd>{e(check_text)}</dd><dt>Baseline</dt><dd>{e(record["baseline_label"])}</dd><dt>証拠の整合記録</dt><dd>{e(record["evidence_label"])}</dd><dt>Renderer認証</dt><dd>{e(record["profile_label"])}</dd><dt>画像検査（運用判定）</dt><dd>{e(vv["label"])}{(" ／ " + e(vv["detail"])) if vv["detail"] else ""}。品質保証ではありません</dd><dt>通信記録</dt><dd>{e(vv["audit"])}</dd><dt>総合品質</dt><dd>UNKNOWN</dd></dl>'


def project_tools(view):
    """Project select + search shared by DETAIL and EVIDENCE (script: projectfilter.js)."""
    sites = {}
    for p in view['pages']:
        sites.setdefault(p.get('site_id', p['domain']), p.get('site_name', p['domain']))
    n = len(view['pages'])
    return ('<section class="panel detail-tools" id="detail-tools" hidden><label for="detail-project">プロジェクト<select id="detail-project"><option value="">すべてのプロジェクト</option>'
            + ''.join(f'<option value="{e(sid)}">{e(name)}</option>' for sid, name in sites.items())
            + '</select></label><label for="detail-search">ページ名・プロジェクト名で検索<input id="detail-search" type="search" maxlength="200" autocomplete="off" placeholder="例：トップページ"></label>'
            + f'<p id="detail-count" role="status" aria-live="polite">表示 {n} / {n} ページ</p></section><p id="detail-empty" role="status" hidden>一致するページはありません。</p>')


def project_groups(view, render_group, extra=None):
    """One collapsible block per project. Only the first project starts open."""
    groups = {}
    for p in view['pages']:
        groups.setdefault(p.get('site_id', p['domain']), []).append(p)
    blocks = []
    for index, (sid, group) in enumerate(groups.items()):
        suffix = f' · {extra(group)}' if extra else ''
        blocks.append(f'<details class="project-group" data-project-group="{e(sid)}"{" open" if index == 0 else ""}><summary><strong>{e(group[0].get("site_name", group[0]["domain"]))}</strong>'
                      f'<span class="group-count" data-group-count data-extra="{e(extra(group) if extra else "")}">{len(group)}ページ{e(suffix)}</span></summary>{render_group(group)}</details>')
    return ''.join(blocks)


IMAGE_LINKS = (('current', '最新画像'), ('mobile', 'Mobile画像'), ('baseline', 'Baseline画像'), ('diff', '差分画像'),
               ('mobile_baseline', 'Mobile Baseline画像'), ('mobile_diff', 'Mobile差分画像'))


def render_details(view):
    from .review import page_view
    from .captures import baseline_html, facts_html, plan_html
    sections = []
    for p in view['pages']:
        tid = p['target_id']
        record = page_view(p, view['source'])
        images = '　'.join(f'<a href="{e(record["images"][role])}">{label}</a>' for role, label in IMAGE_LINKS if record['images'][role])
        facts = plan_html(p) + baseline_html(p) + inspection_summary(p, record) + facts_html(p)
        history = ''.join(f'<li>{jst(h["at"])}　{e(h["event"])}</li>' for h in p['http']['history']) or ('<li>異常・復旧の記録はありません</li>' if view.get('archive') else '<li>履歴未取得</li>')
        sections.append((p, f'<section class="panel" id="{e(tid)}" data-detail-section data-site="{e(p.get("site_id", p["domain"]))}" data-search="{e(p.get("site_name", p["domain"]) + " " + p["label"] + " " + p["url"])}"><div class="panel-head"><h2>{e(p.get("site_name",p["domain"]))} / {e(p["label"])}</h2></div><p>稼働 {tag(p["http"]["state"])} ／ HTTP {e(p["http"]["http_status"])} ／ 応答時間 {e(p["http"]["elapsed_ms"])} ms ／ 最後の監視 {jst(p["http"]["last_checked_at"])} ／ 鮮度判定期限 {jst(p["http"].get("fresh_until"))}（生成時点）</p><p>画像変更 {tag(p["change"]["state"])}</p>{facts}<h3>異常・復旧履歴</h3><ol>{history}</ol><p>{images}</p><p><a href="evidence/{e(tid)}/details.json">監視・比較・manifestの詳細JSON</a></p><details><summary>検査条件・判定理由</summary><pre>{e(json.dumps(p,ensure_ascii=False,indent=2))}</pre></details></section>'))
    by_id = {id(p): html for p, html in sections}
    detail_tools = project_tools(view)
    expiry = ''.join(f'<article><h3>{e(x["kind"])} / {e(x["scope"])}</h3><p>{tag(x["state"])}　期限：{e(x.get("expires_at"))}　観測：{e(x.get("observed_at"))}</p><p>取得元：{e(x.get("source"))} ／ {e(x["reason"])}</p></article>' for x in view['expiry'])
    body = f'''{support_navigation('details')}<details class="panel" id="summary"><summary>監視設定・データ</summary><p>データ：{e(SOURCE_LABELS[view['source']])}</p><p>HTTP：{every(view['http_interval_seconds'])}ごと ／ 撮影：{every(view['capture_interval_seconds'])}ごと</p><p>画面生成：{jst(view['generated_at'])}（日本時間）。静的表示のため、最新化には再生成が必要です。</p><p>保存済みデータの取得元は検証していません。デモは合成データです。</p><p>差分は不具合の確定ではありません。Baseline・撮影条件の検証状態は各ページの詳細を確認してください。</p></details>{SCOPE_HTML}
{detail_tools}<div id="evidence">{project_groups(view, lambda group: ''.join(by_id[id(p)] for p in group))}</div><section class="panel" id="expiry"><h2>期限の詳細</h2>{expiry}<p>登録期限の自動取得は未実装です。自動更新予定は更新完了として扱いません。</p></section>'''
    return shell(view, body, '監視の詳細')


def render_activity(view):
    events = []
    labels = {p['target_id']: p.get('site_name', p['domain']) + ' / ' + p['label'] for p in view['pages']}
    for page in view['pages']:
        tid = page['target_id']
        for h in page['http']['history']:
            if h.get('target_id') != tid:
                raise ValueError('cross-page activity refused')
            at = parse_utc(h.get('at'))
            if at and at <= parse_utc(view['generated_at']):
                state = {'異常を検知': 'DOWN', '復旧を確認': 'UP'}.get(h['event'], 'UNKNOWN')
                events.append((h['at'], tid, 'HTTP履歴', h['event'], state))
        at = page['change'].get('observed_at')
        in_history = any(h['target_id'] == tid for h in (view.get('monitoring') or {}).get('history', []))
        if parse_utc(at) and parse_utc(at) <= parse_utc(view['generated_at']) and not in_history:
            events.append((at, tid, '比較記録', '保存された比較の観測', page['change']['state']))
    events.sort(key=lambda row: parse_utc(row[0]), reverse=True)
    rows = ''.join(f'<tr data-target-id="{e(tid)}"><td><time>{jst(at)}</time></td><td>{e(kind)}</td><td><a href="details.html#{e(tid)}">{e(labels[tid])}</a></td><td>{e(event)} {tag(state)}</td></tr>' for at, tid, kind, event, state in events)
    history = (view.get('monitoring') or {}).get('history', [])
    if not rows:
        rows = '<tr><td colspan="4">%s</td></tr>' % ('状態の変化（異常・復旧）の記録はありません' if view.get('archive') else '履歴未取得')
    # With an image history and nothing else, the empty generic table would only contradict it.
    table = '' if history and not events and not view.get('archive') else f'<div class="support-table"><table><thead><tr><th scope="col">観測日時（JST）</th><th scope="col">種別</th><th scope="col">対象ページ</th><th scope="col">保存された状態</th></tr></thead><tbody>{rows}</tbody></table></div>'
    count = len(events) + len(history)
    body = f'''{support_navigation('activity')}<section class="panel"><div class="panel-head"><h2>履歴・通知</h2><p class="panel-note">{'状態変化の記録' if view.get('archive') else '保存履歴'} {count}件</p></div><p>データ：{e(SOURCE_LABELS[view['source']])} ／ 総合品質：未評価</p><p>通知配信・受信履歴：未取得（外部通知は送信していません。注意事項は画面内の表示のみ）</p>{render_monitoring_history(view)}{render_archive_activity(view)}{table}<p class="panel-note">過去の観測記録です。現在の稼働状態や通知成功の証明ではありません。</p></section>'''
    return shell(view, body, '履歴・通知')


def render_evidence(view):
    from .review import page_view
    from .captures import facts_html
    rows = {}
    for page in view['pages']:
        record = page_view(page, view['source'])
        tid = record['id']
        images = ' ／ '.join(f'<a href="{e(path)}">{label}</a>' for role, label in IMAGE_LINKS if (path := record['images'][role])) or '閲覧可能な画像未取得'
        manifests = '記録あり' if page['change'].get('manifests') else '未取得'
        facts = inspection_summary(page, record) + facts_html(page)
        search = e(record['project'] + ' ' + record['label'] + ' ' + page['url'])
        rows[id(page)] = (f'<tr id="{e(tid)}" data-target-id="{e(tid)}" data-detail-section data-site="{e(page.get("site_id", page["domain"]))}" data-search="{search}"><th scope="row"><span>{e(record["project"])}</span><a href="{e(record["detail"])}">{e(record["label"])}</a></th><td>保存画像 {len(page.get("available_assets", []))}件<p>{images}</p></td><td>{e(record["baseline_label"])}</td><td>{e(record["evidence_label"])}<p>manifest：{manifests}</p></td><td>UNKNOWN<details><summary>検証記録</summary>{facts}<a href="{e(record["metadata"])}">ページ別JSON・manifest記録</a></details></td></tr>')
    head = '<div class="support-table"><table><thead><tr><th scope="col">監視ページ</th><th scope="col">画像の保存・閲覧</th><th scope="col">Baseline</th><th scope="col">整合確認の記録</th><th scope="col">品質・検証詳細</th></tr></thead><tbody>'
    groups = project_groups(view, lambda group: head + ''.join(rows[id(p)] for p in group) + '</tbody></table></div>',
                            extra=lambda group: f'保存画像 {sum(len(p.get("available_assets", [])) for p in group)}件')
    body = f'''{support_navigation('evidence')}<section class="panel"><div class="panel-head"><h2>証拠一覧</h2><p class="panel-note">{len(view['pages'])}ページ</p></div><p>データ：{e(SOURCE_LABELS[view['source']])} ／ 総合品質：未評価</p><p class="panel-note">画像の存在・整合確認の記録・Renderer真正性は別の状態です。保存済みデータの取得元は検証していません。</p></section>{project_tools(view)}<div id="evidence-groups">{groups}</div>'''
    return shell(view, body, '証拠一覧')


# Keep the public Penpot-aligned base assets unchanged; product-only additions.
EXTRA_CSS = (Path(__file__).with_name('dashboard.css')).read_text('utf-8')


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def build(output, snapshot, *, now, assets=None, archive=None):
    """New output only. Imported links never become HTML hrefs. `archive` is the public-only summary from archive.home_extra."""
    output = Path(output)
    if output.exists():
        raise ValueError('output exists; refusing to overwrite')
    config = snapshot_config(snapshot)
    view = dashboard(snapshot, now=now, config=config)
    if archive is not None:
        view['archive'] = archive
    output.mkdir(parents=True, exist_ok=False)
    for page in view['pages']:
        tid = page['target_id']
        directory = output / 'evidence' / tid
        directory.mkdir(parents=True)
        page['available_assets'] = []
        result = page['change'].get('result') or {}
        # Synthetic offline-demo images are checked against the demo's own digests, never the page's comparison result.
        from .baseline_registry import DEMO_ROLES
        demo = (page['change'].get('offline_demo') or {}).get('assets') or {}
        for role in ('current', 'baseline', 'diff', 'mobile', 'mobile_baseline', 'mobile_diff') + DEMO_ROLES:
            if assets is None:
                continue
            path = Path(assets) / tid / (role + '.png')
            if not path.exists():
                continue
            if path.is_symlink() or path.resolve().parent != (Path(assets) / tid).resolve() or path.stat().st_size > 32*1024*1024:
                raise ValueError('unsafe asset')
            raw = path.read_bytes()
            expected = demo.get(role) if role in DEMO_ROLES else result.get(role + '_sha256')
            if expected is None or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError('evidence digest mismatch')
            from src.comparison.preview import dimensions
            dimensions(raw, max_pixels=16*1024*1024, max_bytes=32*1024*1024)
            (directory / (role + '.png')).write_bytes(raw)
            page['available_assets'].append(role)
        write_json(directory / 'details.json', {'source': view['source'], 'page': page})
    (output / 'home.css').write_bytes((ROOT / 'web/home/styles.css').read_bytes())
    (output / 'dashboard.css').write_text(EXTRA_CSS, encoding='utf-8')
    for name in ('folders.js', 'nav.js', 'projectfilter.js', 'scrollcard.js', 'global-nav.css'):
        (output / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    (output / 'index.html').write_text(render(view), encoding='utf-8')
    (output / 'details.html').write_text(render_details(view), encoding='utf-8')
    (output / 'activity.html').write_text(render_activity(view), encoding='utf-8')
    (output / 'evidence.html').write_text(render_evidence(view), encoding='utf-8')
    from .review import render as render_review
    (output / 'review.html').write_text(render_review(view), encoding='utf-8')
    from .operations import write as write_operations
    write_operations(output)
    for name in ('review.css', 'review.js', 'site-background.css'):
        (output / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    write_json(output / 'diagnostics.json', {'gates': 'AWS-B/C LIVE NO-GO; C-02 DEFERRED/OPEN', 'source': view['source']})
    write_json(output / 'snapshot.json', snapshot)
    write_json(output / 'view.json', view)
    template = json.loads((ROOT / 'infra/aws_b/template.json').read_text('utf-8'))
    # A locally captured page is not a monitoring target: it gets no AWS-B stack plan.
    monitored = [p for p in config['pages'] if not p.get('local_capture')]
    for plan in deployment_plan(template, {**config, 'pages': monitored, 'http_interval_seconds': view['http_interval_seconds']}):
        directory = output / 'plans' / plan['target_id']
        directory.mkdir(parents=True)
        write_json(directory / 'aws-b.template.json', plan.pop('template'))
        write_json(directory / 'plan.json', plan)
    return view
