"""Operational visual-change verdict (pure). Separate from the strict PASS/CHANGED quality.

VISUAL_CHANGED / NO_VISUAL_CHANGE_DETECTED only say that, under the configured exact-RGBA
policy, the current capture did or did not differ from the approved Baseline. They are not a
quality assurance and do not authenticate the renderer: PROFILE_UNATTESTED is kept in the
strict result and a matching SHA-256 proves byte equality only. Any broken, missing or
non-comparable precondition yields UNKNOWN; this module never produces PASS/CHANGED.
"""
from src.runtime.request_audit import audit_problems as browser_audit_problems, check_browser_audit

VISUAL_CHANGED = 'VISUAL_CHANGED'
NO_VISUAL_CHANGE_DETECTED = 'NO_VISUAL_CHANGE_DETECTED'
UNKNOWN = 'UNKNOWN'

# The only strict reason that does not block the operational verdict. Every other reason
# (unstable capture, attestation mismatch, failed checks, evidence faults, ...) stays blocking.
TOLERATED_REASONS = frozenset({'PROFILE_UNATTESTED'})


AUDIT_SCHEMAS = ('siteproof.network-audit.v1', 'siteproof.network-audit.v2')


def _counts_valid(section, keys):
    entries = section.get('entries') if type(section) is dict else None
    if type(entries) is not list or any(type(e) is not dict or type(e.get('count')) is not int
                                        or e['count'] < 0 for e in entries):
        return False
    return all(section.get(k) == sum(e['count'] for e in entries if e.get('decision') == d) for k, d in keys)


def _audit_valid(audit):
    if type(audit) is not dict or audit.get('schema') not in AUDIT_SCHEMAS:
        return False
    keys = (('allowed', 'ALLOW'), ('blocked', 'BLOCK'), ('failed', 'FAILED'))
    if audit['schema'].endswith('v1'):
        return _counts_valid(audit, keys)
    prelude, anchor = audit.get('prelude'), audit.get('anchor')
    return (_counts_valid(audit, keys + (('idle', 'IDLE'),))
            and type(prelude) is dict and _counts_valid(prelude, keys + (('idle', 'IDLE'),))
            and type(anchor) is dict and type(anchor.get('seen')) is bool)


def audit_problems(audit, prefix=''):
    """Reasons why a connection audit cannot support a verdict. Missing is never "0 blocked"."""
    if audit is None:
        return [prefix + 'NETWORK_AUDIT_MISSING']
    if type(audit) is dict and audit.get('source') == 'UNAVAILABLE':
        return [prefix + 'NETWORK_AUDIT_UNAVAILABLE']  # No trusted ledger existed for that capture.
    if not _audit_valid(audit) or audit.get('source') != 'TRUSTED_CONNECT_PROXY':
        return [prefix + 'NETWORK_AUDIT_INVALID']
    problems = []
    if audit['complete'] is not True:
        problems.append(prefix + 'NETWORK_AUDIT_INCOMPLETE')
    if audit['schema'].endswith('v2'):
        # Records before the job's own document connection are kept apart, not discarded. Without that
        # connection nothing can be separated, and nothing that was ALLOWed before it can be explained.
        if audit['anchor']['seen'] is not True:
            problems.append(prefix + 'NETWORK_AUDIT_ANCHOR_MISSING')
        if audit['prelude']['allowed']:
            problems.append(prefix + 'PRELUDE_CONNECTION_ALLOWED')
    if not (audit['allowed'] or audit['blocked'] or audit['failed']):
        problems.append(prefix + 'NETWORK_AUDIT_EMPTY')  # A loaded page always connects at least once.
    if audit['blocked']:
        problems.append(prefix + 'RESOURCE_BLOCKED')
    if audit['failed']:
        problems.append(prefix + 'RESOURCE_FAILED')
    return problems


def operational_verdict(*, reasons, metrics, policy, baseline, source, baseline_source,
                        execution, cleanup_confirmed, profile_trust,
                        network_audit=None, baseline_network_audit=None,
                        browser_audit=None, baseline_browser_audit=None):
    blockers = [r for r in reasons if r not in TOLERATED_REASONS]
    changed = metrics.get('changed_pixels') if type(metrics) is dict else None
    threshold = policy.get('maximum_changed_pixels') if type(policy) is dict else None
    if baseline is None:
        blockers.append('BASELINE_UNSET')
    if execution != 'COMPLETED':
        blockers.append('EXECUTION_NOT_COMPLETED')
    if metrics is None:
        blockers.append('COMPARISON_NOT_RUN')
    elif type(changed) is not int or type(threshold) is not int:
        blockers.append('METRICS_INVALID')
    if baseline is not None and (type(source) is not str or not source or baseline_source != source):
        # Unset on either side is not "same source".
        blockers.append('BASELINE_SOURCE_MISMATCH')
    blockers += audit_problems(network_audit)
    # What the page's browser context says failed to load (TLS, connection, HTTP). Untrusted, so it can only add
    # reasons; a missing, malformed or unfinished report is a reason too, and a clean one proves nothing.
    blockers += browser_audit_problems(browser_audit)
    if baseline is not None:
        blockers += audit_problems(baseline_network_audit, 'BASELINE_')
        blockers += browser_audit_problems(baseline_browser_audit, 'BASELINE_')
    if cleanup_confirmed is not True:
        blockers.append('CLEANUP_UNCONFIRMED')
    blockers = list(dict.fromkeys(blockers))
    if blockers:
        verdict = UNKNOWN
        changed = threshold = None
    else:
        verdict = VISUAL_CHANGED if changed > threshold else NO_VISUAL_CHANGE_DETECTED
    return {'schema': 'siteproof.operational-verdict.v1', 'verdict': verdict, 'reasons': blockers,
            'basis': 'EXACT_RGBA_PIXEL_DIFF', 'changed_pixels': changed, 'threshold': threshold,
            'assurance': 'NONE', 'renderer_authenticity': 'NOT_ASSERTED',
            'profile_trust': profile_trust,
            'notes': ['PROFILE_UNATTESTED'] if profile_trust == 'UNATTESTED' else []}


VERDICT_LABELS = {VISUAL_CHANGED: '画像の変化あり・要確認', NO_VISUAL_CHANGE_DETECTED: '設定条件では変化未検出',
                  UNKNOWN: '画像検査の判定不能'}
REASON_LABELS = {
    'RESOURCE_BLOCKED': '撮影に必要な通信が遮断されました', 'RESOURCE_FAILED': '通信に失敗したリソースがあります',
    'NETWORK_AUDIT_MISSING': '通信記録がありません（旧データ）', 'NETWORK_AUDIT_UNAVAILABLE': '通信記録を取得できませんでした',
    'NETWORK_AUDIT_INCOMPLETE': '通信記録が不完全です', 'NETWORK_AUDIT_EMPTY': '通信記録に接続がありません',
    'NETWORK_AUDIT_INVALID': '通信記録が不正です', 'NETWORK_AUDIT_ANCHOR_MISSING': '撮影対象ページへの接続が記録されていません',
    'PRELUDE_CONNECTION_ALLOWED': '撮影前に許可された接続があります',
    'TLS_VALIDATION_FAILED': 'TLS証明書の検証に失敗したリソースがあります', 'RESOURCE_LOAD_FAILED': 'リソースの読み込みに失敗しました',
    'BROWSER_AUDIT_UNAVAILABLE': 'ブラウザ側の読み込み記録を取得できませんでした', 'BROWSER_AUDIT_INCOMPLETE': 'ブラウザ側の読み込み記録が不完全です',
    'BROWSER_AUDIT_INVALID': 'ブラウザ側の読み込み記録が不正です', 'PAGE_SCRIPT_ERROR': 'ページでJavaScriptエラーが発生しました',
    'BASELINE_UNSET': 'Baselineが未設定です',
    'BASELINE_PENDING': 'Baselineが未承認です', 'BASELINE_NOT_APPROVED': 'Baselineが未承認です',
    'PROFILE_MISMATCH': '撮影条件がBaselineと一致しません', 'BASELINE_SOURCE_MISMATCH': '撮影元がBaselineと一致しません',
    'COMPARISON_NOT_RUN': '画像比較が実行されていません', 'CAPTURE_UNSTABLE': '撮影が安定していません',
    'CLEANUP_UNCONFIRMED': '実行環境の後始末が未確認です', 'CHECK_NOT_PASSED': '撮影の必須チェックが成功していません',
    'CHECK_FAILED': '撮影チェックが失敗しました', 'EVIDENCE_MISSING': '証拠が欠けています',
    'DISPLAY_STATE_MISMATCH': '結果が古いか、保存時の判定と一致しません', 'THRESHOLD_UNDEFINED': '判定の閾値が未定義です',
    'EXECUTION_NOT_COMPLETED': '撮影が完了していません', 'METRICS_INVALID': '比較値が不正です'}


def reason_label(code):
    code = str(code)
    if code in REASON_LABELS:
        return REASON_LABELS[code]
    if code.startswith('BASELINE_') and code[9:] in REASON_LABELS:
        return 'Baseline側：' + REASON_LABELS[code[9:]]
    return code


def _summary(audit):
    if audit is None:
        state = 'MISSING'
    elif type(audit) is dict and audit.get('source') == 'UNAVAILABLE':
        state = 'UNAVAILABLE'
    elif not _audit_valid(audit) or audit.get('source') != 'TRUSTED_CONNECT_PROXY':
        state = 'INVALID'
    else:
        state = 'RECORDED'
    out = {'state': state, 'complete': state == 'RECORDED' and audit.get('complete') is True,
           'allowed': None, 'blocked': None, 'failed': None, 'refused': []}
    if state == 'RECORDED':
        out.update({k: audit[k] for k in ('allowed', 'blocked', 'failed')})
        out['refused'] = [{k: e.get(k) for k in ('host', 'port', 'decision', 'reason', 'count')}
                          for e in audit['entries'] if e.get('decision') in ('BLOCK', 'FAILED')][:5]
        out['idle'] = audit.get('idle', 0)
        pre = audit.get('prelude')
        out['prelude'] = ({k: pre[k] for k in ('allowed', 'blocked', 'failed', 'idle')} if type(pre) is dict else None)
    return out


def _browser_summary(audit):
    problems = browser_audit_problems(audit)
    if audit is None or any(p in ('BROWSER_AUDIT_UNAVAILABLE', 'BROWSER_AUDIT_INVALID') for p in problems):
        return {'state': 'UNAVAILABLE' if audit is None or problems == ['BROWSER_AUDIT_UNAVAILABLE'] else 'INVALID',
                'complete': False, 'failed': None, 'http_errors': None, 'tls': None, 'script_errors': None}
    clean = check_browser_audit(audit)  # Rebuilt: a stored dict is never read directly.
    return {'state': 'RECORDED', 'complete': clean['complete'], 'failed': clean['failed'], 'http_errors': clean['http_errors'],
            'tls': sum(f['count'] for f in clean['failures'] if f['class'] == 'TLS_VALIDATION_FAILED'),
            'script_errors': clean.get('script_errors')}  # None: this audit predates script-error recording


def image_comparison(result):
    """The pixel comparison by itself (a fact about two PNGs), apart from whether the inspection can be trusted. A comparison that
    did not run, or whose numbers are malformed, is NOT_COMPARED -- never a guessed "no change"."""
    metrics, policy = result.get('metrics'), result.get('policy')
    changed = metrics.get('changed_pixels') if type(metrics) is dict else None
    threshold = policy.get('maximum_changed_pixels') if type(policy) is dict else None
    if result.get('baseline') is None or type(changed) is not int or type(threshold) is not int or changed < 0:
        return {'state': 'NOT_COMPARED', 'changed_pixels': None, 'label': '画像比較：未実施'}
    if changed > threshold:
        return {'state': 'CHANGED', 'changed_pixels': changed, 'label': f'画像比較：変更あり（{changed:,}px）'}
    return {'state': 'UNCHANGED', 'changed_pixels': changed, 'label': f'画像比較：変更なし（{changed:,}px）'}


def inspection_quality(verdict, reasons):
    """Whether the inspection itself can carry a verdict (the operational result): OK or UNKNOWN with its reasons."""
    if verdict == UNKNOWN:
        labels = [reason_label(r) for r in reasons]
        return {'state': 'UNKNOWN', 'reasons': list(reasons), 'label': '検査品質：判定不能（' + '／'.join(labels or ['理由不明']) + '）',
                'codes': '・'.join(reasons)}
    return {'state': 'OK', 'reasons': [], 'label': '検査品質：問題なし', 'codes': ''}


def present(result, state=None):
    """Display projection of a saved comparison result. Never invents an audit or a verdict.

    No `operational` record (pre-S1-A data) -> recorded=False and no verdict. A recorded
    verdict is re-checked against the saved audit and, when given, the displayed state, and
    can only be downgraded to UNKNOWN, never promoted.
    """
    result = result if type(result) is dict else {}
    op = result.get('operational')
    if type(op) is not dict or op.get('schema') != 'siteproof.operational-verdict.v1':
        return {'recorded': False, 'verdict': None, 'label': '運用判定の記録なし（旧データ）', 'reasons': [],
                'reason_labels': [], 'audit': _summary(result.get('network_audit')),
                'image': image_comparison(result), 'quality': {'state': 'UNRECORDED', 'reasons': [], 'label': '検査品質：記録なし（旧データ）', 'codes': ''},
                'unattested': True}
    audit = result.get('network_audit')
    problems = audit_problems(audit) + browser_audit_problems(result.get('browser_audit'))
    verdict = op.get('verdict') if op.get('verdict') in VERDICT_LABELS else UNKNOWN
    reasons = [r for r in (op.get('reasons') or []) if type(r) is str] if type(op.get('reasons')) is list else []
    if verdict != UNKNOWN and problems:
        verdict, reasons = UNKNOWN, problems + reasons
    if state is not None and verdict != UNKNOWN and {'CHANGED': VISUAL_CHANGED,
                                                      'UNCHANGED': NO_VISUAL_CHANGE_DETECTED}.get(state) != verdict:
        verdict, reasons = UNKNOWN, reasons + ['DISPLAY_STATE_MISMATCH']
    if verdict == UNKNOWN and not reasons:
        reasons = ['COMPARISON_NOT_RUN']
    reasons = list(dict.fromkeys(reasons if verdict == UNKNOWN else []))
    return {'recorded': True, 'verdict': verdict, 'label': VERDICT_LABELS[verdict], 'reasons': reasons,
            'reason_labels': [reason_label(r) for r in reasons], 'audit': _summary(audit),
            'image': image_comparison(result),
            'quality': (inspection_quality(verdict, reasons) if result.get('baseline') is not None  # not compared: nothing to judge yet
                        else {'state': 'NOT_COMPARED', 'reasons': [], 'label': '検査品質：比較なし（Baselineを作る撮影・未承認）', 'codes': ''}),
            'browser': _browser_summary(result.get('browser_audit')),
            'unattested': op.get('profile_trust') != 'ATTESTED'}
