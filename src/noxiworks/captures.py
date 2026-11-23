"""Saved captures as the screens show them.

`cards()` is the plain-language side used by REVIEW (what was captured, when, how big). `facts_html()` is the technical side
(SHA-256, fingerprint, CaptureProfile, response record, CONNECT / Browser audit) used by DETAIL and EVIDENCE only.
Pure functions: no I/O. A capture succeeding says the picture was taken; it is never shown as a quality verdict.
"""
import json
import re

from src.comparison.operational import present
from .baseline_registry import STANDING_LABELS, baseline_standing
from .home import e, jst, visual_view

ROLE_FILE = {'current': 'current.png', 'mobile': 'mobile.png'}
KEY_ROLE = {'desktop': 'current', 'mobile': 'mobile', 'current': 'current'}
# Per profile: (current, Baseline, diff) image roles. Desktop keeps the original role names every screen already knows.
COMPARE_ROLES = {'desktop': ('current', 'baseline', 'diff'), 'current': ('current', 'baseline', 'diff'),
                 'mobile': ('mobile', 'mobile_baseline', 'mobile_diff')}
STATUS_LABELS = {'SUCCEEDED': '撮影成功', 'FAILED': '撮影失敗', 'PLANNED': '未撮影'}
CHANGE_LABELS = {'changed': '変更あり', 'unchanged': '変更なし', 'unknown': '判定不能', 'none': '比較なし'}


def _image(page, role, record):
    sha = (page['change'].get('result') or {}).get(role + '_sha256')
    ok = role in page.get('available_assets', []) and re.fullmatch(r'[a-f0-9]{64}', str(sha)) is not None and sha == record.get('sha256', sha)
    return f'evidence/{page["target_id"]}/{ROLE_FILE[role]}' if ok else None


def _range(full_page, planned=False):
    if planned:
        return ('ページ全体' if full_page else '表示領域のみ') + '（予定）'
    # A full-page screenshot draws fixed elements (a bottom menu bar) once, where they sat in the first screen, not at the page end.
    return 'ページ全体（画面に固定されたメニューは撮影時の位置に写ります）' if full_page else '表示領域のみ（ページ全体ではありません）'


def _compare(key, images, ready, verdict):
    """Baseline / diff / change of one profile. Without a confirmed comparison there is nothing to compare, and it says so."""
    _, base, diff = COMPARE_ROLES[key]
    if not (ready and images.get(base) and images.get(diff)):
        return {'baseline': None, 'diff': None, 'change': 'none', 'change_label': CHANGE_LABELS['none']}
    kind = {'VISUAL_CHANGED': 'changed', 'NO_VISUAL_CHANGE_DETECTED': 'unchanged'}.get(verdict, 'unknown')
    return {'baseline': images[base], 'diff': images[diff], 'change': kind, 'change_label': CHANGE_LABELS[kind]}


def stability_line(result, repeat_identical=None):
    """Plain wording of the trusted stability check. No record (captures before the check existed) is never shown as confirmed."""
    s = (result or {}).get('capture_stability')
    if isinstance(s, dict) and s.get('value') == 'STABLE':
        return f'描画の安定：確認済み（{s.get("attempts")}回撮影・{round((s.get("elapsed_ms") or 0) / 1000, 1)}秒）'
    if isinstance(s, dict):
        return f'描画の安定：不安定（{s.get("attempts") or "-"}回撮影）。比較は判定不能になります'
    if repeat_identical is False:
        return '描画の安定：未確認（旧方式の2枚が一致しません。このままでは比較が判定不能になります）'
    return '描画の安定：未確認（旧方式の撮影）'


def _health(result, repeat_identical=None):
    """Plain-language page-load line of one capture (browser self-report; it can only ever add a warning)."""
    b = present(result, None).get('browser') or {}
    unstable = ' ／ ' + stability_line(result, repeat_identical)
    if b.get('state') != 'RECORDED':
        return '読み込みの記録：なし' + unstable
    scripts = '未記録' if b.get('script_errors') is None else f'{b["script_errors"]}件'
    return f'読み込み失敗 {b["failed"] + b["http_errors"]}件 ／ JavaScriptエラー {scripts}' + ('' if b['complete'] else ' ／ 記録が不完全') + unstable


def cards(page, images, ready=False):
    """One card per screenshot tab, in tab order. `images` = review.page_view()'s page-bound image paths.

    Pages saved without capture records (older data, the demo) get one plain "latest image" card. A page that was never
    captured but has a capture plan gets one PLANNED card per planned profile, so Desktop / Mobile stay visible (no image).
    """
    saved = page['change'].get('captures')
    if not isinstance(saved, list) or not saved:
        if images.get('current'):
            state = {'CHANGED': 'VISUAL_CHANGED', 'UNCHANGED': 'NO_VISUAL_CHANGE_DETECTED'}.get(page['change'].get('state'))
            return [{'key': 'current', 'label': '最新の撮影画像', 'status': 'SUCCEEDED', 'status_label': '保存画像', 'image': images['current'],
                     'size': '', 'viewport': '', 'captured': jst(page['change'].get('observed_at')), 'range': '', 'frame': 'desktop',
                     'health': '', **_compare('current', images, ready, state)}]
        plan = page.get('plan') or {}
        return [{'key': p['kind'].lower(), 'label': p['kind'], 'status': 'PLANNED', 'status_label': STATUS_LABELS['PLANNED'], 'image': None,
                 'size': '', 'viewport': f'{p["width"]}×{p["height"]}', 'captured': '未撮影', 'range': _range(p['full_page'], True),
                 'frame': p['kind'].lower(), 'health': '', **_compare('desktop', {}, False, None)} for p in plan.get('profiles', [])]
    out = []
    for c in saved:
        kind = c.get('kind')
        key = {'Desktop': 'desktop', 'Mobile': 'mobile'}.get(kind)
        if key is None:
            continue
        image = _image(page, KEY_ROLE[key], c) if c.get('status') == 'SUCCEEDED' else None
        w, h = c.get('image_size') or (None, None)
        vw, vh = c.get('viewport') or (None, None)
        verdict = (present(c.get('result'), None) or {}).get('verdict')
        out.append({'key': key, 'label': kind, 'status': 'SUCCEEDED' if image else 'FAILED', 'status_label': STATUS_LABELS['SUCCEEDED' if image else 'FAILED'],
                    'image': image, 'size': f'{w}×{h}' if w else '', 'viewport': f'{vw}×{vh}' if vw else '', 'captured': jst(c.get('captured_at')),
                    'range': '' if not image else _range(c.get('full_page')), 'frame': key,
                    'health': _health(c.get('result'), c.get('repeat_identical')) if image else '',
                    **_compare(key, images, ready and bool(image), verdict)})
    return out


def capture_label(cs):
    """(label, css kind) of the capture chip. Succeeded / failed / not taken are three different things."""
    cs = [c for c in cs if c['status'] != 'PLANNED']
    ok, bad = sum(c['status'] == 'SUCCEEDED' for c in cs), sum(c['status'] == 'FAILED' for c in cs)
    if not cs:
        return '未撮影', 'none'
    if not bad:
        return '撮影成功', 'ok'
    return ('撮影失敗', 'unknown') if not ok else ('一部の撮影が失敗', 'unknown')


ROLE_LABELS = {'PRIMARY': '主要監視対象', 'FEATURE_CANDIDATE': '主要機能の監視候補', 'SUPPLEMENTAL': '補助ページ'}
REAL_CAPTURE_LABELS = {'NOT_APPROVED': '実サイト撮影：未承認（未実施）', 'NOT_CAPTURABLE': '撮影できません（撮影手順が未対応）',
                       'CAPTURED_ONCE': '撮影済み（限定承認で1回）'}


def plan_profiles(plan):
    return ' ／ '.join(f'{p["kind"]} {p["width"]}×{p["height"]}・{"ページ全体" if p["full_page"] else "表示領域のみ"}' for p in plan['profiles'])


def plan_summary(page):
    """Plain-language capture plan of one page for REVIEW / HOME. Empty when the page has no plan."""
    plan = page.get('plan')
    if not plan:
        return {'role': '', 'role_label': '', 'state_label': '', 'profiles': '', 'why': '', 'candidates': []}
    site = page.get('plan_site') or {}
    # Saved captures outrank the plan's (configuration-time) state: a captured page never reads "not captured".
    captured = isinstance(page['change'].get('captures'), list) and page['change']['captures']
    state = ('合成デモの撮影（実サイトの撮影ではありません）' if captured and page['change'].get('synthetic')
             else (('実サイト撮影：済み（Baseline自動作成・正式承認ではない・作成後の撮影と比較は未実施）' if baseline_standing(page['change']) in ('AUTO_UNCONFIRMED', 'AUTO_CONFIRMED')
                    else '実サイト撮影：済み（Baseline承認済み・承認後の撮影と比較は未実施）') if page['change'].get('comparison_after_approval') == 'NOT_RUN'
                   else ('実サイト撮影：済み（' + STANDING_LABELS[baseline_standing(page['change'])][0] + 'のBaselineと比較済み）' if baseline_standing(page['change']) else '実サイト撮影：済み（承認済みBaselineと比較済み）') if page['change'].get('baseline_approved')
                   else '実サイト撮影：済み（Baseline候補は未承認）') if captured else REAL_CAPTURE_LABELS[plan['real_capture']])
    return {'role': plan['role'], 'role_label': ROLE_LABELS[plan['role']], 'state_label': state,
            'profiles': plan_profiles(plan), 'why': plan.get('why') or '',
            'candidates': [{'label': c['label'], 'entry': c.get('entry') or '', 'state': REAL_CAPTURE_LABELS[c['real_capture']]}
                           for c in site.get('candidates', [])] if plan['role'] == 'PRIMARY' else []}


def plan_html(page):
    """Technical capture plan + dynamic-content handling for DETAIL. Empty when the page has no plan."""
    plan, site = page.get('plan'), page.get('plan_site') or {}
    if not plan:
        return ''
    rows = (('位置づけ', ROLE_LABELS[plan['role']]), ('撮影URL', plan['url']), ('撮影条件（計画）', plan_profiles(plan)),
            ('実サイト撮影', plan_summary(page)['state_label']), ('選んだ理由', plan.get('why') or ''))
    listing = ''.join(f'<dt>{e(k)}</dt><dd>{e(v)}</dd>' for k, v in rows if v)
    candidates = ''.join(f'<li><strong>{e(c["label"])}</strong>：{e(c.get("entry") or "")}（{e(REAL_CAPTURE_LABELS[c["real_capture"]])}）'
                         f'{"<br>" + e(c["blocker"]) if c.get("blocker") else ""}{"<br>" + e(c["why"]) if c.get("why") else ""}</li>'
                         for c in site.get('candidates', [])) if plan['role'] == 'PRIMARY' else ''
    stability = ''.join(f'<tr><th scope="row">{e(s["item"])}</th><td>{e(s["handling"])}</td></tr>' for s in site.get('stability', []))
    return (f'<section class="capture-plan" data-capture-plan="{e(plan["page_id"])}"><h3>画像監視の計画</h3><dl class="inspection-summary">{listing}</dl>'
            + (f'<h4>主要機能の監視候補</h4><ul>{candidates}</ul>' if candidates else '')
            + (f'<h4>撮影ごとに変わりうる要素と扱い（マスクはしません）</h4><div class="support-table"><table><thead><tr><th scope="col">要素</th>'
               f'<th scope="col">扱い</th></tr></thead><tbody>{stability}</tbody></table></div>' if stability and plan['role'] == 'PRIMARY' else '')
            + '</section>')


def _profile_line(c):
    p = c.get('profile') or {}
    return ' ／ '.join(str(x) for x in (f'{p.get("viewport_width")}×{p.get("viewport_height")}', p.get('locale'), p.get('timezone'),
                                         '配色 ' + str(p.get('color_scheme')), f'倍率 {p.get("device_scale_factor")}',
                                         'ページ全体' if p.get('full_page') else '表示領域のみ', 'UA ' + str(p.get('user_agent'))) if x is not None)


def _load_line(state):
    state = state if isinstance(state, dict) else {}
    if all(state.get(k) is None for k in ('readyState', 'scrollHeight', 'bodyTextLength')):
        return '未記録（この撮影の時点では記録していません）'
    return ' ／ '.join(str(x) for x in (f'readyState {state.get("readyState")}', f'ページの高さ {state.get("scrollHeight")} px',
                                        f'本文 {state.get("bodyTextLength")} 文字', f'画像 {state.get("images")}件（欠落 {state.get("brokenImages")}件）',
                                        f'フォント {state.get("fontsStatus")}'))


def facts_html(page):
    """Technical record of every saved capture of this page, for DETAIL / EVIDENCE. Empty when there is none."""
    saved = page['change'].get('captures')
    if not isinstance(saved, list) or not saved:
        return ''
    blocks = []
    registered = {b['candidate_id']: b for b in (page['change'].get('baseline_registry') or {}).get('baselines', [])}
    for c in saved:
        v = visual_view({'observed_at': c.get('captured_at'), 'visual': present(c.get('result'), None)})
        http = c.get('http') or {}
        response = ' ／ '.join(x for x in (str(http.get('status') or '未取得'), 'TLS ' + str(http.get('tls') or '未取得'),
                                         'リダイレクトなし' if not http.get('redirect') and not http.get('location') else 'リダイレクトあり') if x)
        cand = c.get('candidate') or {}
        rows = (('撮影', STATUS_LABELS.get(c.get('status'), '未確認') + '（画像が撮れたことを示すだけで、サイトの表示品質の保証ではありません）'),
                ('撮影日時（JST・通信窓の開始）', jst(c.get('captured_at'))), ('画像サイズ', ' × '.join(map(str, c.get('image_size') or [])) + ' px' if c.get('image_size') else '未取得'),
                ('Baseline候補（撮影時点の記録）', f'{cand.get("approval_state") or "未取得"}（USER未承認）／ {cand.get("candidate_id") or "未取得"}'
                 + (f' → 現在：{STANDING_LABELS[baseline_standing(page["change"])][0] if baseline_standing(page["change"]) else "承認済み"} Baseline v{registered[cand["candidate_id"]]["version"]}（下の「Baselineの登録記録」）'
                    if cand.get('candidate_id') in registered else '')),
                ('画像SHA-256', c.get('sha256') or '未取得'), ('候補digest', cand.get('digest') or '未取得'),
                ('撮影・比較のJob ID', c.get('job_id') or '未取得'),
                ('比較したBaseline', (lambda pin: f'{pin["candidate_id"]}（version {pin["version"]}）' if isinstance(pin, dict) else '比較なし')((c.get('result') or {}).get('baseline'))),
                ('差分ピクセル', (lambda m: f'{m["changed_pixels"]:,} / {m["total_pixels"]:,}（RGBA完全一致・閾値0）' if isinstance(m, dict) and m.get('total_pixels') else '比較なし')((c.get('result') or {}).get('metrics'))),
                ('撮影条件fingerprint', c.get('fingerprint') or '未取得'), ('CaptureProfile', _profile_line(c)),
                ('撮影条件の認証', '未認証（PROFILE_UNATTESTED）' if c.get('profile_trust') != 'ATTESTED' else '認証済み'),
                ('Chromium', c.get('browser_version') or '未取得'), ('ページ応答（撮影前HEAD）', response),
                ('2回撮影の一致', {True: '一致', False: '不一致（連続した2枚の画像に差があります）'}.get(c.get('repeat_identical'), '未取得')),
                ('描画の安定（信頼側の確認）', stability_line(c.get('result'), c.get('repeat_identical'))
                 + ''.join(f' ／ {x["t_ms"]}ms {x["sha256"][:12]}' for x in ((c.get('result') or {}).get('capture_stability') or {}).get('shots', []))),
                ('読み込み状態（ブラウザ報告）', _load_line(c.get('load_state'))),
                ('通信記録（CONNECT監査）', v['audit']), ('画像検査（運用判定）', v['label'] + (' ／ ' + v['detail'] if v['detail'] else '')))
        listing = ''.join(f'<dt>{e(k)}</dt><dd>{e(val)}</dd>' for k, val in rows)
        raw = {'network_audit': (c.get('result') or {}).get('network_audit'), 'browser_audit': (c.get('result') or {}).get('browser_audit'),
               'checks': c.get('checks'), 'operational': (c.get('result') or {}).get('operational')}
        blocks.append(f'<section class="capture-facts" data-capture-facts="{e(c.get("kind"))}"><h4>{e(c.get("kind"))} の撮影記録</h4><dl class="inspection-summary">{listing}</dl>'
                      f'<details><summary>通信監査・ブラウザ監査・チェック結果（JSON）</summary><pre>{e(json.dumps(raw, ensure_ascii=False, indent=2))}</pre></details></section>')
    return '<h3>撮影の記録（技術情報）</h3>' + ''.join(blocks)


def instruction_text(registry):
    """The recorded basis of an automatic Baseline, with the profiles that were really captured (older records fixed it to both).
    Display only: the stored record is never rewritten."""
    text = str(registry.get('instruction', ''))
    if registry.get('formal_approval'):
        text = text.replace('。利用者は未確認', '。のちにUSERがこのBaselineを正式承認（下記）')
    kinds = '・'.join(b['kind'] for b in registry.get('baselines', []))
    return text.replace('（Desktop・Mobileとも完了・STABLE）', f'（{kinds}完了・STABLE）') if kinds else text


def baseline_html(page):
    """Formal Baseline registration record and the synthetic offline demo of it, for DETAIL. Empty when the page has neither."""
    registry = page['change'].get('baseline_registry')
    if not registry:
        return ''
    source = registry['source_run']
    blocks = []
    for b in registry['baselines']:
        st = b.get('stability') or {}
        rows = (('Baseline ID', b['candidate_id']), ('状態', f'{b["status"]}（version {b["version"]}・{b["kind"]} 専用。DesktopとMobileは別々のBaseline）'),
                ('承認日時（JST）', jst(b['approved_at'])), ('承認者', b['actor']), ('撮影日時（JST・通信窓の開始）', jst(b['captured_at'])),
                ('撮影条件', f'{b["viewport"][0]}×{b["viewport"][1]}・{"ページ全体" if b["full_page"] else "表示領域のみ"}'),
                ('画像SHA-256', b['png_sha256']), ('候補digest（承認時に確認）', b['candidate_digest']), ('撮影条件fingerprint', b['profile_fingerprint']),
                ('安定性記録', f'{st.get("value")}（{st.get("attempts")}回撮影・{st.get("elapsed_ms")} ms・{st.get("source")}）'
                 + ''.join(f' ／ {x["t_ms"]}ms {x["sha256"][:12]}' for x in st.get('shots', []))),
                ('品質・撮影条件の認証', f'{b["quality"]} ／ {b["profile_reason"]}（承認では変わりません）'))
        blocks.append(f'<section class="capture-facts" data-baseline="{e(b["kind"])}"><h4>{e(b["kind"])} Baseline</h4><dl class="inspection-summary">'
                      + ''.join(f'<dt>{e(k)}</dt><dd>{e(v)}</dd>' for k, v in rows) + '</dl></section>')
    others = ' ／ '.join(f'{o["run_id"]}：{", ".join(o["candidate_ids"])}（同じ画像のSHA-256 {len(o["same_image_sha256"])}件・別の候補ID）'
                         for o in registry.get('distinct_from', []))
    standing = baseline_standing(page['change'])
    formal = registry.get('formal_approval')
    record = (('Baselineの位置づけ', STANDING_LABELS[standing][1] if standing else '未確認'), ('承認の根拠', instruction_text(registry)),
              *((('正式承認（USER）', f'{jst(formal["approved_at"])}・{formal["actor"]}（Baselineのバージョン・画像・証拠は承認の前後で同じです。撮影品質は未評価のままです）'),)
                if formal else ()), ('登録方法', registry['mechanism']), ('登録先', registry['registry_id']),
              ('元の撮影証拠', f'{source["run_id"]}（{source["task"]}）・export-sha256.json {source["export_sha256_json"]}・登録の前後で変更なし'),
              ('候補IDの重複確認', others or '未確認'), ('承認対象外の候補', '自動承認なし（承認は上記の2件のみ）'))
    demo = page['change'].get('offline_demo')
    demo_rows = ''
    if demo:
        demo_rows = ''.join(f'<tr><th scope="row">{e(s["title"])}</th>' + ''.join(
            f'<td>{e(k["kind"])}：{e(k["verdict"])}' + (f'（変化 {k["changed_pixels"]:,} px）' if k['verdict'] != 'UNKNOWN' else f'（{e("／".join(k["reasons"]))}）')
            + f'<br><small>result {e(k["result_id"])} ／ job {e(k["job_id"])}</small></td>' for k in s['kinds'].values()) + '</tr>' for s in demo['scenarios'])
        demo_rows = (f'<h4>オフライン実証の記録（合成データ・{e(demo["run_id"])}）</h4><p>承認済みBaselineの画像と、そこから作った画像を、'
                     '製品と同じ比較処理（ComparisonService）で比べた記録です。撮影・通信・ブラウザの記録は合成で、実サイトの撮影・監視結果・障害履歴ではありません。</p><div class="support-table"><table><thead><tr><th scope="col">実証</th>'
                     f'<th scope="col">Desktop</th><th scope="col">Mobile</th></tr></thead><tbody>{demo_rows}</tbody></table></div>')
    return ('<section class="capture-plan" data-baseline-registry><h3>Baselineの登録記録</h3><dl class="inspection-summary">'
            + ''.join(f'<dt>{e(k)}</dt><dd>{e(v)}</dd>' for k, v in record) + '</dl>' + ''.join(blocks) + demo_rows + '</section>')
