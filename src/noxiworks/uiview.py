"""What HOME says about monitoring, in plain Japanese, derived from the facts the app already has (monitor settings, the last inspection, the
permit, the five real-capture gates, the stop reason). Pure functions: no file, network, Docker or clock access, nothing is started or changed.

monitor_view() answers, for one registered site: which state is monitoring in, why it is stopped, whether "監視を開始" may be offered (and if
not, why), and what the user can do next. The server uses the same answer to refuse a start the screen would not offer, so the screen and the
server never disagree. explain_failure() turns the harness's internal check codes into a sentence a person can act on; it knows only the
codes listed here and never gives an unknown error a cause (the original text is always kept for "詳細を見る").
"""
import re

# internal code (substring of the recorded error) -> sentence. Only causes that are certain from the code itself.
KNOWN_FAILURES = (
    ('KD_candidate_saved_pending_and_only_the_registry_baselines_approved', 'Baselineの検証に失敗しました。安全のため監視を停止しました。'),
    ('KD_compared_with_the_formal_baseline_of_this_profile', 'Baselineとの比較の検証に失敗しました。安全のため監視を停止しました。'),
    ('HTTP_TIMEOUT', 'サイトの応答が遅れ、撮影が時間内に終わりませんでした。'),
    ('許可された撮影回数を使い切っています', '撮影許可の回数を使い切りました。'),
    ('PERMIT_PREFLIGHT_REFUSED', '撮影許可の確認で停止しました。'),
)
UNKNOWN_FAILURE = '検査に失敗しました。原因を分類できませんでした（「詳細を見る」に記録があります）。'
CODE = re.compile(r'\b[A-Z][A-Za-z0-9]*(?:_[A-Za-z0-9]+){2,}\b')


# what the USER does next, per monitoring state (HOME's top line); "" = nothing to do
NEXT_STEPS = {
    'MONITORING': '操作は不要です（自動で検査しています）',
    'RUNNING': '検査が終わるまでお待ちください',
    'STOPPED': '「監視を開始」を押すと、定期検査が始まります',
    'WAIT_BASELINE': '差分レビューで「初回Baselineを承認する」を押してください',
    'WAIT_CHANGE': '差分レビューで変更を確認し、「新しい基準にする」かどうか決めてください',
    'WAIT_DECISION': '差分レビューでBaselineの判断を済ませてください',
    'FAILED': '原因を確認してください（詳細を見る）。問題が解消したら「監視を開始」で再開できます',
    'COMPLETE': '必要なら「監視を開始」で再開できます（自動では再開しません）',
    'PERMIT_EXHAUSTED': '「監視設定を更新」で新しい撮影許可を作ってください',
    'PERMIT_EXPIRED': '「監視設定を更新」で新しい撮影許可を作ってください',
    'DISK_FULL': '保存容量を確保してから「監視を開始」を押してください',
    'NOT_READY': '「実サイト監視の準備」の未完了の項目を済ませてください',
    'WAITING': '「実サイト監視の準備」の未完了の項目を済ませてください',
    'SETUP_RUNNING': '別のウィンドウでセットアップを進めてください',
}


def explain_failure(error):
    """-> None (no error) or {'message', 'known', 'code', 'detail'}. `detail` is the original text, unchanged."""
    if not error:
        return None
    text = str(error)
    for code, message in KNOWN_FAILURES:
        if code in text:
            return {'message': message, 'known': True, 'code': code if code.isascii() else None, 'detail': text}
    found = CODE.search(text)
    return {'message': UNKNOWN_FAILURE, 'known': False, 'code': found.group(0) if found else None, 'detail': text}


def first_gap(readiness, permit):
    """The first thing that stops a capture, as one sentence; None when every gate holds."""
    if permit and permit.get('state') == 'EXHAUSTED':
        return '撮影許可の回数を使い切りました。「監視設定を更新」で新しい許可を作ってください。'
    if permit and permit.get('state') == 'EXPIRED':
        return '撮影許可の期限が切れています。「監視設定を更新」で新しい許可を作ってください。'
    for gate in readiness:
        if not gate['ok']:
            return f'撮影の条件が整っていません（{gate["label"]}：{gate["state"]}）。'
    return None


def monitor_view(*, enabled, running, paused_reason, last, readiness, permit, setup, hold, fixture_engine=False):
    """-> {'state', 'label', 'kind', 'reason', 'can_start', 'start_block', 'can_stop', 'failure'}. kind: ok | warn | error | info | none."""
    ready = all(g['ok'] for g in readiness) or fixture_engine
    gap = None if ready else first_gap(readiness, permit)
    failure = explain_failure((last or {}).get('error')) if (last or {}).get('outcome') == 'FAILED' else None

    def view(state, label, kind, reason, *, start=False, block=None, stop=False):
        return {'state': state, 'label': label, 'kind': kind, 'reason': reason, 'can_start': start, 'start_block': block, 'can_stop': stop, 'failure': failure,
                'next': NEXT_STEPS.get(state, '')}
    if setup and setup.get('state') in ('LAUNCHED', 'RUNNING'):
        return view('SETUP_RUNNING', 'セットアップ中', 'info', '別のウィンドウでセットアップを進めています。終わるとこの画面が更新されます。', block='セットアップが終わるまで開始できません。')
    if running:
        return view('RUNNING', '検査中', 'info', '検査を実行しています。終わるまでお待ちください（約3分）。', block='検査中です。')
    if enabled:
        if not ready:
            return view('WAITING', '監視は有効（撮影の条件待ち）', 'warn', (gap or '撮影の条件が整っていません。') + '条件が整うまで撮影しません。', stop=True)
        return view('MONITORING', '正常に監視中', 'ok', '定期的に検査しています。', stop=True)
    # stopped: say WHY first (the stop reason the monitor recorded), then fall back to the permit, then a plain user stop
    block_ready = None if ready else gap
    if paused_reason == 'COMPLETE':
        return view('COMPLETE', '計画した検査を完了して停止', 'ok', '予定していた回数の検査が終わったため、監視を止めました。自動では再開しません。', start=ready, block=block_ready)
    if paused_reason and paused_reason.startswith('ANOMALY:'):
        return view('FAILED', '検査失敗により停止', 'error', (failure['message'] if failure else '検査が正常に終わらなかったため、安全のため監視を止めました。') + '自動では再試行しません。',
                    start=ready, block=block_ready)
    # a decision wait is shown only while the decision is still OPEN (`hold` is what the monitor itself would hold for); once the USER decided, the
    # recorded stop reason is history and the monitor is simply stopped
    if paused_reason in ('DECISION:BASELINE_CREATED', 'ON_HOLD') and hold and '正式承認' in hold:
        return view('WAIT_BASELINE', 'あなたのBaseline確認待ち', 'warn', '初回のBaselineができました。差分レビューで画像を確認し、「初回Baselineを承認する」を押してください。承認するまで次の検査はしません。',
                    block='先にBaselineを正式承認してください（差分レビュー）。')
    if paused_reason == 'ON_HOLD' and hold and '変更' not in hold:
        return view('WAIT_DECISION', 'Baselineの判断待ち', 'warn', (hold or 'Baselineの判断が済んでいません。') + '差分レビューで確認してください。判断が済むまで次の検査はしません。',
                    block='先にBaselineの判断を済ませてください（差分レビュー）。')
    if paused_reason in ('DECISION:CHANGED', 'ON_HOLD') and hold and '変更' in hold:
        return view('WAIT_CHANGE', '変更確認待ち', 'warn', '変更を検知しました。差分レビューで内容を確認し、「新しい基準にする」かどうか決めてください。決めるまで次の検査はしません。',
                    block='先に変更を確認してください（差分レビュー）。')
    if paused_reason == 'DISK_FULL':
        return view('DISK_FULL', '保存容量の上限で停止', 'error', '保存容量が上限に達しました。保存済みの検査は削除していません。容量を確保してから開始してください。', start=ready, block=block_ready)
    if permit and permit.get('state') == 'EXHAUSTED':
        return view('PERMIT_EXHAUSTED', '許可回数を使い切って停止', 'error', '撮影許可の回数を使い切りました。「監視設定を更新」で新しい許可を作ると、再開できます。', block=gap)
    if permit and permit.get('state') == 'EXPIRED':
        return view('PERMIT_EXPIRED', '撮影許可の期限切れ', 'error', '撮影許可の期限が切れました。「監視設定を更新」で新しい許可を作ると、再開できます。', block=gap)
    if not ready:
        return view('NOT_READY', '停止中（実サイト監視の準備待ち）', 'warn', (gap or '撮影の条件が整っていません。') + '条件が整うまで撮影しません。', block=gap)
    if paused_reason == 'RESTORED':  # only the last fallback: a permit that ran out or a missing condition above is still what is shown
        return view('STOPPED', '停止中（バックアップから復元）', 'warn', 'バックアップから復元したコピーのため、監視は止めてあります。自動では検査しません。'
                    '元のデータフォルダと同時に使わず、内容を確認してから「監視を開始」を押してください。', start=True)
    return view('STOPPED', '停止中', 'warn', '監視は止まっています。自動では検査しません。「監視を開始」を押すと、定期検査を始めます。', start=True)
