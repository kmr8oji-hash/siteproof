"""Read-only REVIEW 05 presentation over the existing HOME projection.

The saved screenshot is the main thing on the screen; what happened (captured / approved / compared / changed / quality)
is shown as five separate states; technical records (SHA-256, fingerprint, audits) stay in DETAIL / EVIDENCE and a folded block.
Images come only from build()'s page-bound, digest-checked exports.
No service calls, approval, capture, database access or network access.
"""
import json
import re

from .baseline_registry import STANDING_LABELS, baseline_standing
from .captures import cards, capture_label, plan_summary
from .home import e, jst, shell, support_navigation, visual_view

_ROLES = ('baseline', 'current', 'diff')
_ALL_ROLES = _ROLES + ('mobile', 'mobile_baseline', 'mobile_diff')
_COMPARE_ONLY = ('baseline', 'diff', 'mobile_baseline', 'mobile_diff')
_KINDS = ('changed', 'unchanged', 'pending', 'unknown', 'none', 'ok')
_CARD_FIELDS = ('key', 'label', 'status', 'status_label', 'image', 'size', 'viewport', 'captured', 'range', 'frame', 'health',
                'baseline', 'diff', 'change', 'change_label')


def compare_reason(observed, approved, baseline_label, compared, ready):
    """Why there is (not yet) a before/after comparison. Always an explicit sentence, never an empty panel."""
    if ready:
        return ''
    if not observed:
        return '未撮影のため、比較する画像がありません。'
    if not approved:
        return ('Baselineが未承認のため、比較はまだ行っていません（比較未実施）。撮影画像を確認してBaselineとして承認すると、'
                '次回の撮影から変更前（Baseline）と今回の画像を比べられます。' if baseline_label == '未承認'
                else 'Baselineがないため、比較できません（比較未実施）。')
    return '比較結果を確定できません（判定不能）。理由は詳細を確認してください。' if compared else '比較結果がありません（比較未実施）。'


DEMO_LABELS = {'unchanged': '変更なし（合成データ）', 'changed': '変更あり（合成データ）', 'unknown': '判定不能（UNKNOWN）'}
# What the right-hand image of each scenario really is. None of them is a real-site capture.
DEMO_CAPTIONS = {'unchanged': '保存済みBaselineと同じ画像をもう一度入力したもの（実サイトの撮影ではありません）',
                 'changed': 'Baselineに赤い帯を描き足した合成画像（実サイトの撮影ではありません）',
                 'unstable': '画像はBaselineと同じ。撮影の安定性記録だけを「不安定」にした合成データ（実サイトの撮影ではありません）'}


def demo_view(page):
    """The synthetic offline demo of an approved Baseline, as page-bound image paths. None when the page has none.

    Only for the comparison panel: it never becomes the page's state, change or history. An undecided scenario shows no diff.
    """
    demo = page['change'].get('offline_demo')
    if not demo or page['change'].get('baseline_approved') is not True:
        return None
    tid, available = page['target_id'], set(page.get('available_assets', []))
    own = lambda role: f'evidence/{tid}/{role}.png' if role and role in available else None
    scenarios = []
    for s in demo['scenarios']:
        kinds = {}
        for tab, k in s['kinds'].items():
            base, after = own(k['baseline_role']), own(k['current_role'])
            if not (base and after):
                continue
            change = {'NO_VISUAL_CHANGE_DETECTED': 'unchanged', 'VISUAL_CHANGED': 'changed'}.get(k['verdict'], 'unknown')
            detail = (f'変化したピクセル {k["changed_pixels"]:,} / {k["total_pixels"]:,}（RGBA完全一致で判定・閾値0）' if change != 'unknown'
                      else '判定不能：' + '／'.join(k['reasons']) + '。差分画像は確定しないため表示しません')
            kinds[tab] = {'baseline': base, 'after': after, 'diff': own(k['diff_role']) if change != 'unknown' else None,
                          'change': change, 'label': DEMO_LABELS[change], 'detail': detail, 'caption': DEMO_CAPTIONS[s['key']]}
        scenarios.append({'key': s['key'], 'title': s['title'], 'kinds': kinds})
    return {'label': demo['label'], 'scenarios': scenarios}


def page_view(page, source):
    tid = page['target_id']
    if not re.fullmatch(r'[a-z0-9-]+', tid):
        raise ValueError('unsafe review page id')
    change = page['change']
    if change.get('page_id', tid) != tid or change.get('url', page['url']) != page['url']:
        raise ValueError('cross-page review refused')
    available = set(page.get('available_assets', []))
    result = change.get('result') or {}
    paths = {
        role: f'evidence/{tid}/{role}.png'
        if role in available and re.fullmatch(r'[a-f0-9]{64}', str(result.get(role + '_sha256', '')))
        else None for role in _ALL_ROLES}
    approved = change.get('baseline_approved') is True
    verified = change.get('source_availability') == 'VERIFIED'
    ready = (approved and verified and change['state'] in ('CHANGED', 'UNCHANGED')
             and all(paths[role] for role in _ROLES))
    kind = ('changed' if change['state'] == 'CHANGED' else 'unchanged') if ready else 'pending'
    observed = bool(change.get('observed_at'))
    baseline = (((STANDING_LABELS[baseline_standing(change)][0] if baseline_standing(change) else '承認済み') if approved else '未承認')
                if approved or (change.get('baseline_approved') is False and observed)
                else '未取得')
    state = {'CHANGED': '変更あり', 'UNCHANGED': '変更なし'}.get(change['state'], '未確認')
    visual = visual_view(change)
    if not ready:
        for role in _COMPARE_ONLY:
            paths[role] = None
    shots = cards(page, paths, ready)
    shot_label, shot_kind = capture_label(shots)
    compared = bool(result) and change.get('metrics') is not None
    plan = plan_summary(page)
    # A formally registered Baseline that has not been compared with any later capture (no new monitoring has run).
    registry = change.get('baseline_registry') if approved and change.get('comparison_after_approval') == 'NOT_RUN' else None
    # SiteProof's own first-capture Baseline (actor AUTO_ACTOR) is not a formal USER approval; the wording must not say it is.
    standing = baseline_standing(change)
    auto = bool(registry) and standing in ('AUTO_UNCONFIRMED', 'AUTO_CONFIRMED')
    demo = demo_view(page)
    if not observed:
        message = ('未撮影：このページはまだ撮影していません。' + ('実サイトの撮影はUSERの承認後に行います（比較未実施）。'
                   if (page.get('plan') or {}).get('real_capture') == 'NOT_APPROVED' else '比較も未実施です。'))
    elif not approved:
        message = ('撮影は成功しました。まだBaselineとして承認されていないため、変更の有無は判定できません（画像比較は未実施）。'
                   '画像が意図どおりかは、ご自身の目で確認してください。' if shot_kind == 'ok'
                   else 'Baseline未承認・未取得：確定した差分画像は表示しません。')
    elif visual['kind'] == 'unknown':
        message = ((visual['image'] + '。' if visual.get('image') else '') + '画像検査は判定不能：' + (visual['detail'] or '理由は詳細を確認してください')
                   + '。確定した差分画像は表示しません。')
    elif not result or change.get('metrics') is None:
        message = '比較結果なし：保存済みの確定結果がありません。'
    elif not ready:
        message = '比較未確定：結果・画像の不足、鮮度または証拠の検証状態を詳細で確認してください。'
    else:
        message = ('画像変更を検知しました。不具合や品質FAILの確定ではありません。'
                   if kind == 'changed' else '画像差分はありません。ページ全体の品質PASSではありません。')
    if registry:
        versions = '・'.join(f'{b["kind"]} v{b["version"]}' for b in registry['baselines'])
        message = ((f'Baseline（{versions}）はSiteProofが初回の安定した撮影から自動作成したものです（正式な承認ではありません）。作成後の実サイト撮影はまだ行っていないため、実サイトの画像比較は未実施です。'
                    if auto else f'Baseline（{versions}）はUSERが承認済みです。承認後の実サイト撮影はまだ行っていないため、実サイトの画像比較は未実施です。')
                   + ('比較機能の動作は、下の「オフライン実証（合成データ）」で確認できます。' if demo else ''))
        # The saved capture-time check said "Baseline pending"; that was true then and is not repeated as today's state.
        visual = {**visual, 'kind': 'none', 'label': '実サイト比較：未実施', 'detail': '撮影の時点ではBaseline未承認だったため比較していません（承認は撮影の後）'}
    if kind in ('changed', 'unchanged'):
        change_label, change_kind = state, kind
        change_note = ((visual['image'] + '。' + visual['quality'] + '。') if visual.get('image') else '') + (
            '画像に差があります（不具合の確定ではありません）' if kind == 'changed' else '画像の差は検出されませんでした（品質PASSではありません）')
        list_label, list_kind = state, kind
    else:
        change_label, change_kind, change_note = (('判定不能（UNKNOWN）', 'unknown', (visual['image'] + '。' + visual['quality'] + '。変更の有無は確定しません')
                                                   if visual.get('image') else '比較結果を確定できません') if compared
                                                  else ('判定なし', 'none', '画像比較が未実施のため'))
        list_label, list_kind = (('Baseline' + STANDING_LABELS[standing][0] if standing else 'Baseline承認済み', 'ok') if registry else ('未撮影', 'none') if not observed else ('撮影に失敗', 'unknown') if shots and shot_kind != 'ok'
                                 else ('Baseline未承認', 'pending') if change.get('baseline_approved') is False else ('判定不能', 'unknown'))
    history = sorted(page['http'].get('history', []), key=lambda h: h['at'], reverse=True)[:3]
    return {'id': tid, 'project': page.get('site_name', page['domain']),
        'site_id': page.get('site_id', page['domain']), 'label': page['label'], 'url': page['url'],
        'detail': 'details.html#' + tid, 'evidence_page': 'evidence.html#' + tid, 'metadata': f'evidence/{tid}/details.json',
        'change': change['state'], 'state_label': state, 'kind': kind,
        'change_label': change_label, 'change_kind': change_kind, 'change_note': change_note, 'list_label': list_label, 'list_kind': list_kind,
        'capture_label': shot_label, 'capture_kind': shot_kind, 'compared': compared,
        'compare_label': '実施済み' if compared else '実サイト：未実施' if registry else '未実施', 'compare_kind': 'ok' if compared else 'none',
        'baseline': 'approved' if approved else 'pending' if baseline == '未承認' else 'missing',
        'baseline_label': baseline, 'baseline_kind': 'ok' if approved else 'pending' if baseline == '未承認' else 'none',
        'baseline_note': ('承認待ち（PENDING）' if baseline == '未承認' else
                          '・'.join(f'{b["kind"]} v{b["version"]}' for b in registry['baselines']) + (f'（{STANDING_LABELS[standing][0]}・正式承認ではない）' if auto else '（USER承認）') if registry else ''),
        'verified': verified,
        'evidence_label': ('画像未取得' if not (paths['current'] or paths['mobile']) else
                           '整合確認済み（記録）' if verified else '未検証'),
        'profile_label': '認証状態は詳細参照' if change.get('profile_trust') == 'ATTESTED' else '未認証',
        'observed': jst(change.get('observed_at')), 'message': message,
        'caption': ('合成デモ / 品質UNKNOWN' if source == 'FIXTURE' else ('自動作成Baselineの撮影画像 / 品質UNKNOWN' if auto else '承認済みBaselineの撮影画像 / 品質UNKNOWN') if registry
                    else '保存画像 / 品質UNKNOWN'),
        'history': [jst(h['at']) + ' · ' + h['event'] for h in history], 'cards': shots,
        'visual_kind': visual['kind'], 'visual_label': visual['label'],
        'visual_detail': visual['detail'], 'audit_label': visual['audit'], 'images': paths,
        'split_label': (visual['image'] + '。' + visual['quality']) if visual.get('image') else '',
        'primary': plan['role'] == 'PRIMARY', 'plan': plan, 'demo': demo,
        'compare_reason': (('Baselineは自動作成されたもの（正式な承認ではない）で、作成後の実サイト撮影がまだないため、実サイトの比較は未実施です（新しい監視は行っていません）。' if auto else 'Baselineは承認済みですが、承認後の実サイト撮影がまだないため、実サイトの比較は未実施です（新しい監視は行っていません）。')
                           if registry else compare_reason(observed, approved, baseline, compared, ready))}


def _chip(title, element, text, kind, note=None):
    extra = f'<small id="{note[0]}">{e(note[1])}</small>' if note else ''
    return f'<div><span>{e(title)}</span><strong class="review-status {kind}" id="{element}">{e(text)}</strong>{extra}</div>'


def _tabs(shots, selected):
    return ''.join(f'<button type="button" class="review-tab" role="tab" data-key="{e(c["key"])}" id="review-tab-{e(c["key"])}" aria-selected="{"true" if c is selected else "false"}" aria-controls="review-stage-view"{"" if c["image"] else " data-empty"}>{e(c["label"])}<small>{e(c["viewport"] or c["size"])}</small></button>'
                   for c in shots)


def _plan_box(plan):
    """The page's place in monitoring (primary / candidate / supplemental) in plain words. Hidden when the page has no plan."""
    candidates = ''.join(f'<li><strong>{e(c["label"])}</strong>：{e(c["entry"])}（{e(c["state"])}）</li>' for c in plan['candidates'])
    return (f'<div class="review-plan" id="review-plan"{"" if plan["role"] else " hidden"}><p><strong class="review-plan-role" id="review-plan-role">{e(plan["role_label"])}</strong>'
            f'<span id="review-plan-state">{e(plan["state_label"])}</span></p><p class="review-plan-profiles">撮影条件：<span id="review-plan-profiles">{e(plan["profiles"])}</span></p>'
            f'<p class="review-plan-why" id="review-plan-why">{e(plan["why"])}</p>'
            f'<div id="review-plan-candidates"{"" if candidates else " hidden"}><p>主要機能の監視候補</p><ul id="review-plan-candidate-list">{candidates}</ul></div></div>')


def _figure(role, title, path, label, caption, empty='画像未取得・比較未確定'):
    href, src = (f' href="{e(path)}"', f' src="{e(path)}"') if path else ('', '')
    return (f'<figure class="review-image {role}"><h4 id="review-title-{role}">{title}</h4><a id="review-link-{role}"{href}{"" if path else " hidden"} target="_blank" rel="noopener">'
            f'<img id="review-image-{role}"{src} alt="{e(label)} {title}"></a><div class="review-image-empty" id="review-empty-{role}"{" hidden" if path else ""}>{empty}</div>'
            f'<figcaption id="review-caption-{role}">{e(caption) if path else "確定した比較画像はありません"}</figcaption></figure>')


def _compare(initial, card):
    """Before / after of the shown profile: side by side, an overlay slider, or the diff alone. Always says why when there is none."""
    card = card or {}
    base, diff, after = card.get('baseline'), card.get('diff'), card.get('image') if card.get('baseline') else None
    reason = initial['compare_reason'] or ('' if base else 'このプロファイルには確定した比較画像がありません（比較未実施）。')
    label, kind = (card.get('change_label') or '比較なし', card.get('change') or 'none')
    demo = initial.get('demo')
    sources = ''.join(f'<button type="button" data-source="{e(k)}" aria-pressed="{"true" if k == "real" else "false"}">{e(t)}</button>'
                      for k, t in [('real', '実サイトの比較')] + [(s['key'], s['title']) for s in (demo or {}).get('scenarios', [])])
    modes = ''.join(f'<button type="button" data-mode="{m}" aria-pressed="{"true" if m == "side" else "false"}">{t}</button>'
                    for m, t in (('side', '並べて表示'), ('slider', 'スライダーで重ねる'), ('diff', '差分のみ')))
    slider_src = (f' src="{e(base)}"', f' src="{e(after)}"') if base and after else ('', '')
    return (f'<section class="review-compare" id="review-compare" aria-labelledby="review-compare-title"><div class="review-compare-bar">'
            f'<h3 id="review-compare-title">Baselineとの比較（<span id="review-compare-kind">{e(card.get("label") or "Desktop")}</span>）</h3>'
            f'<strong class="review-status {kind}" id="review-compare-result">{e(label)}</strong>'
            f'<div class="review-modes" id="review-modes" role="group" aria-label="比較の表示方法"{"" if base else " hidden"}>{modes}</div></div>'
            f'<div class="review-sources" id="review-sources" role="group" aria-label="比較の対象（実サイト／オフライン実証）"{"" if demo else " hidden"}>{sources}</div>'
            f'<p class="review-demo-note" id="review-demo-note" hidden>{e((demo or {}).get("label", ""))}。承認済みBaseline（実際の撮影画像）と、'
            f'そこから作った合成画像を、製品と同じ比較処理で比べた結果です。監視履歴・障害履歴には含めません。</p>'
            f'<p class="review-compare-empty" id="review-compare-empty"{" hidden" if base else ""}>{e(reason)}</p>'
            f'<p class="review-compare-detail" id="review-compare-detail" hidden></p>'
            f'<div class="review-compare-body" id="review-compare-body" data-mode="side"{"" if base else " hidden"}>'
            f'<div class="review-images">{_figure("baseline", "変更前（Baseline）", base, initial["label"], initial["caption"])}'
            f'{_figure("after", "今回の撮影", after, initial["label"], initial["caption"])}</div>'
            f'<div class="review-slider" id="review-slider"><div class="review-slider-frame"><img id="review-slider-before"{slider_src[0]} alt="変更前（Baseline）">'
            f'<div class="review-slider-top" id="review-slider-top"><img id="review-slider-after"{slider_src[1]} alt="今回の撮影"></div></div>'
            f'<label class="review-slider-control" for="review-slider-range"><span>変更前</span><input type="range" id="review-slider-range" min="0" max="100" value="50"><span>今回</span></label></div>'
            f'{_figure("diff", "差分画像（変化したピクセル）", diff, initial["label"], initial["caption"])}</div>'
            f'<p class="review-compare-note">差分は不具合の確定ではありません。動的な部分を隠す処理（マスク）はしていません。</p></section>')


def render(view):
    records = [page_view(page, view['source']) for page in view['pages']]
    has_image = lambda r: any(c['image'] for c in r['cards'])
    # Open on a change, else on the primary page (the top page) if it has a screenshot, else any page with one, else the primary page.
    initial = (next((r for r in records if r['kind'] == 'changed'), None)
               or next((r for r in records if r['primary'] and has_image(r)), None)
               or next((r for r in records if has_image(r)), None)
               or next((r for r in records if r['primary']), None)
               or (records[0] if records else None))
    folders = []
    groups = {}
    for record in records:
        groups.setdefault(record['site_id'], []).append(record)
    for group in groups.values():
        group.sort(key=lambda r: not r['primary'])  # the primary page first; the others keep their order
        choices = []
        for r in group:
            fields = {
                'id': r['id'], 'project': r['project'], 'label': r['label'], 'url': r['url'],
                'detail': r['detail'], 'change': r['change'], 'baseline': r['baseline'],
                'verified': str(r['verified']).lower(), 'current': r['images']['current'] or '',
                'baseline-image': r['images']['baseline'] or '', 'diff': r['images']['diff'] or '',
                'state-label': r['state_label'], 'evidence-label': r['evidence_label'],
                'profile-label': r['profile_label'], 'observed': r['observed'],
                'message': r['message'], 'caption': r['caption'],
                'visual-kind': r['visual_kind'], 'visual-label': r['visual_label'],
                'visual-detail': r['visual_detail'], 'audit-label': r['audit_label'], 'split': r['split_label'],
                'compared': str(r['compared']).lower(), 'capture-label': r['capture_label'], 'capture-kind': r['capture_kind'],
                'change-kind': r['change_kind'], 'baseline-note': r['baseline_note'], 'baseline-label': r['baseline_label'], 'compare-label': r['compare_label'],
                'captures': json.dumps([{k: c[k] for k in _CARD_FIELDS} for c in r['cards']], ensure_ascii=False),
                'history': json.dumps(r['history'], ensure_ascii=False),
                'plan': json.dumps(r['plan'], ensure_ascii=False), 'compare-reason': r['compare_reason'],
                'demo': json.dumps(r['demo'], ensure_ascii=False) if r['demo'] else '',
                'site': r['site_id'], 'search': r['project'] + ' ' + r['label']}
            attrs = ' '.join(f'data-{key}="{e(value)}"' for key, value in fields.items())
            current = ' aria-current="page"' if r is initial else ''
            primary = '<span class="review-primary" title="主要監視対象">主要</span>' if r['primary'] else ''
            choices.append(f'<a class="review-choice" id="{e(r["id"])}" data-review-choice {attrs} href="{e(r["detail"])}"{current}><span>{primary}{e(r["label"])}</span><span class="review-status {r["list_kind"]}">{e(r["list_label"])}</span></a>')
        changed = sum(r['kind'] == 'changed' for r in group)
        pending = sum(r['kind'] == 'pending' for r in group)
        opened = ' open' if initial in group else ''
        folders.append(f'<details class="review-project" data-review-project="{e(group[0]["site_id"])}"{opened}><summary><strong>{e(group[0]["project"])}</strong><span>{len(group)}ページ · 変更 {changed} · 比較未確定 {pending}</span></summary>{"".join(choices)}</details>')
    if initial is None:
        return shell(view, '<section class="panel"><h2>監視ページ未登録</h2><a href="index.html">HOMEへ戻る</a></section>', '差分レビュー')
    shots = initial['cards']
    first = next((c for c in shots if c['image']), shots[0] if shots else None)
    path = first['image'] if first else None
    empty_note = ('未撮影：このページはまだ撮影されていません' if not first else '未撮影：この表示サイズはまだ撮影していません'
                  if first['status'] == 'PLANNED' else '撮影に失敗しました（画像はありません）')
    link = f' href="{e(path)}"' if path else ''
    src = f' src="{e(path)}"' if path else ''
    stage = (f'<section class="review-stage" aria-labelledby="review-stage-title"><div class="review-stage-bar"><h3 id="review-stage-title">撮影画像</h3>'
             f'<div class="review-tabs" id="review-tabs" role="tablist" aria-label="表示する撮影画像（DesktopとMobile）">{_tabs(shots, first)}</div>'
             f'<div class="review-stage-actions"><button type="button" id="review-zoom"{"" if path else " hidden"}>拡大表示</button>'
             f'<a id="review-original" target="_blank" rel="noopener"{link}{"" if path else " hidden"}>原寸画像を開く</a></div></div>'
             f'<div class="review-stage-view" id="review-stage-view" role="tabpanel" data-frame="{e(first["frame"] if first else "desktop")}">'
             f'<a class="review-shot" id="review-link-current"{link}{"" if path else " hidden"} target="_blank" rel="noopener" aria-label="撮影画像を拡大して見る">'
             f'<img id="review-image-current"{src} alt="{e(initial["label"])} 撮影画像"></a>'
             f'<div class="review-image-empty" id="review-empty-current"{" hidden" if path else ""}>{e(empty_note)}</div></div>'
             f'<p class="review-stage-meta" id="review-stage-meta"><span id="review-shot-title">{e(first["label"] if first else "")}</span>'
             f'<span id="review-shot-when"{"" if first and first["status"] != "PLANNED" else " hidden"}>撮影 <time id="review-shot-time">{e(first["captured"] if first else "未取得")}</time> JST</span>'
             f'<span id="review-shot-size">{e(("画像 " + first["size"] + " px") if first and first["size"] else "")}</span>'
             f'<span id="review-shot-range">{e(first["range"] if first else "")}</span>'
             f'<span id="review-shot-health">{e(first["health"] if first else "")}</span></p>'
             f'<p class="review-caption" id="review-caption-current">{e(initial["caption"]) + "・元の画像を加工せずに表示しています" if path else "撮影画像はありません"}</p></section>')
    compare = _compare(initial, first)
    options = ''.join(f'<option value="{e(g[0]["site_id"])}">{e(g[0]["project"])}</option>' for g in groups.values())
    tools = ('<div class="review-tools" id="review-tools" hidden><label for="review-project">プロジェクト<select id="review-project"><option value="">すべてのプロジェクト</option>' + options
             + '</select></label><label for="review-search">ページを検索<input id="review-search" type="search" maxlength="200" autocomplete="off" placeholder="ページ名・プロジェクト名"></label>'
             + '<p id="review-list-count" role="status" aria-live="polite"></p></div><p id="review-list-empty" role="status" hidden>一致するページはありません。</p>')
    histories = ''.join(f'<li id="review-history-{i}"{"" if i < len(initial["history"]) else " hidden"}>{e(initial["history"][i]) if i < len(initial["history"]) else ""}</li>' for i in range(3))
    chips = (_chip('撮影', 'review-capture', initial['capture_label'], initial['capture_kind'])
             + _chip('Baseline', 'review-baseline', initial['baseline_label'], initial['baseline_kind'], ('review-baseline-note', initial['baseline_note']))
             + _chip('画像比較', 'review-compare-state', initial['compare_label'], initial['compare_kind'])
             + _chip('変更の有無', 'review-change', initial['change_label'], initial['change_kind'], ('review-change-note', initial['change_note']))
             + _chip('品質', 'review-quality', '未評価', 'none', ('review-quality-note', '撮影の成否と品質は別です')))
    body = f'''{support_navigation('review')}<div class="review-heading"><div><p>REVIEW · 総合品質：未評価</p><h2>差分レビュー</h2></div><a href="index.html">HOMEへ戻る ›</a></div>
<div class="review-layout" id="review-app"><nav class="review-sidebar" aria-label="プロジェクト・監視ページ"><h2>監視ページ</h2>{tools}{''.join(folders)}<noscript><p>ページのリンクから既存DETAILを確認できます。</p></noscript></nav>
<section class="review-selected panel" id="review-selected" data-selected-id="{e(initial['id'])}" aria-labelledby="review-page-title">
<div class="review-selected-head"><div><p id="review-project-title">{e(initial['project'])}</p><h2 id="review-page-title">{e(initial['label'])}</h2><p class="review-url" id="review-page-url">{e(initial['url'])}</p></div><a id="review-detail" href="{e(initial['detail'])}">詳細・証拠 ›</a></div>
<div class="review-state-row" id="review-states">{chips}</div>
{_plan_box(initial['plan'])}
{stage}
<p class="review-message{' pending' if initial['kind'] == 'pending' else ''}" id="review-message">{e(initial['message'])}</p>
{compare}
<details class="review-tech"><summary>検証情報・ページ履歴（技術者向け）</summary>
<div class="review-tech-grid"><div><span>画像検査（運用判定）</span><strong class="review-status {initial['visual_kind']}" id="review-visual">{e(initial['visual_label'])}</strong></div><div><span>証拠の整合性</span><strong class="review-status" id="review-evidence">{e(initial['evidence_label'])}</strong></div></div>
<p class="review-visual-detail" id="review-visual-detail">{e(initial['visual_detail'])}</p><p class="review-visual-detail">通信記録：<span id="review-audit">{e(initial['audit_label'])}</span> ／ 運用判定は品質保証ではありません</p>
<p class="review-observed">最後の監視（JST）：<span id="review-observed">{e(initial['observed'])}</span> ／ Renderer認証：<span id="review-profile">{e(initial['profile_label'])}</span> / 総合品質：未評価</p>
<p class="review-tech-links">SHA-256・撮影条件（fingerprint・CaptureProfile）・通信監査の全文は <a id="review-detail-tech" href="{e(initial['detail'])}">詳細（DETAIL）</a> と <a id="review-evidence-page" href="{e(initial['evidence_page'])}">証拠一覧（EVIDENCE）</a> にあります。 <a id="review-metadata" href="{e(initial['metadata'])}">記録JSON</a></p>
<h3>HTTP異常・復旧履歴</h3><ol>{histories}</ol><p id="review-history-empty"{' hidden' if initial['history'] else ''}>履歴未取得</p></details>
<p class="review-note">保存済みの撮影・比較を表示しています。撮影・比較は、この画面では行いません。Baselineの更新は、SiteProofアプリで開いたこの画面に表示される「新しい基準にする」（変更を検知した後・USERの明示操作）だけです。</p><p class="sr-only" id="review-selected-message" role="status" aria-live="polite">選択中：{e(initial['project'])} / {e(initial['label'])}</p>
</section></div>
<div class="review-lightbox" id="review-lightbox" role="dialog" aria-modal="true" aria-labelledby="review-lightbox-title" hidden><div class="review-lightbox-bar"><strong id="review-lightbox-title">撮影画像</strong><span><button type="button" id="review-lightbox-fit">画面に合わせる</button><button type="button" id="review-lightbox-close">閉じる（Esc）</button></span></div><div class="review-lightbox-body" id="review-lightbox-body" tabindex="0"></div></div>'''
    return shell(view, body, '差分レビュー')
