"""Capture stability: when is a screenshot a settled render, and how does the trusted side check the claim?

The producer (`stable_capture`) takes screenshots spaced in time until the last `required_identical` of them are byte-identical AND
span at least `min_span_ms`, within `max_attempts` and a total time budget. A first render that differs (TTN: the first full-page
screenshot re-rasterises its fixed footer once, so later shots differ from it by 21 px of anti-aliasing) is simply not part of the
settled run. Two early identical shots taken close together do not count when the policy asks for a longer span. If no settled run
is found in time the capture still completes, but it is UNSTABLE: never a verdict, never masked.

Trust: the producer's report is untrusted. `verify` (trusted side, used by the S3 Worker and the M5 profile observer alike) checks the
two PNGs it actually received against the reported hashes, re-derives the settled run from the reported shot list, and requires
the policy it asked for. Anything missing, malformed or inconsistent is UNSTABLE. A STABLE result only says "the last shots
repeated"; it is not a quality verdict and not renderer authenticity.
"""
import hashlib
import re
import time

SCHEMA = 'siteproof.capture-stability.v1'
DEFAULT_POLICY = {'settle_ms': 0, 'interval_ms': 300, 'required_identical': 2, 'min_span_ms': 0, 'max_attempts': 4, 'max_total_ms': 4000}
BOUNDS = {'settle_ms': (0, 10000), 'interval_ms': (50, 5000), 'required_identical': (2, 5), 'min_span_ms': (0, 10000),
          'max_attempts': (2, 10), 'max_total_ms': (500, 30000)}
_SHA = re.compile(r'[0-9a-f]{64}\Z')


def policy(value=None):
    """A complete, bounded policy. None = the default; anything malformed or out of bounds raises (never silently widened)."""
    merged = dict(DEFAULT_POLICY)
    if value is not None:
        if type(value) is not dict or set(value) - set(DEFAULT_POLICY):
            raise ValueError('invalid stability policy')
        merged.update(value)
    for key, (low, high) in BOUNDS.items():
        if type(merged[key]) is not int or not low <= merged[key] <= high:
            raise ValueError('stability policy out of bounds: ' + key)
    if merged['max_attempts'] < merged['required_identical']:
        raise ValueError('max_attempts below required_identical')
    return merged


def settled(shots, rules):
    """shots: [(t_ms, sha256 or bytes), ...] in order. True when the trailing run of identical shots has at least
    `required_identical` shots and spans at least `min_span_ms` (first to last shot of that run)."""
    if not shots:
        return False
    run = [shots[-1]]
    for shot in reversed(shots[:-1]):
        if shot[1] != run[0][1]:
            break
        run.insert(0, shot)
    return len(run) >= rules['required_identical'] and run[-1][0] - run[0][0] >= rules['min_span_ms']


def stable_capture(take, rules, budget_seconds, *, clock=time.monotonic, sleep=time.sleep):
    """take(timeout_seconds) -> PNG bytes. -> (evidence_png, previous_png, report). Never exceeds `budget_seconds` by more than one shot."""
    rules = policy(rules)
    start = clock()
    end = start + min(rules['max_total_ms'] / 1000, max(budget_seconds, 0.0))
    if rules['settle_ms']:
        sleep(max(0.0, min(rules['settle_ms'] / 1000, end - clock())))
    shots = []  # (t_ms, png)
    while True:
        remaining = end - clock()
        if remaining <= 0 and shots:
            break
        png = take(max(remaining, 0.5))
        shots.append((round((clock() - start) * 1000), png))
        if settled(shots, rules) or len(shots) >= rules['max_attempts']:
            break
        if end - clock() <= 0:
            break
        sleep(min(rules['interval_ms'] / 1000, max(0.0, end - clock())))
    stable = settled(shots, rules)
    report = {'schema': SCHEMA, 'value': 'STABLE' if stable else 'UNSTABLE', 'policy': rules, 'attempts': len(shots),
              'elapsed_ms': round((clock() - start) * 1000),
              'shots': [{'t_ms': t, 'sha256': hashlib.sha256(p).hexdigest()} for t, p in shots],
              'reason': None if stable else ('MAX_ATTEMPTS' if len(shots) >= rules['max_attempts'] else 'TIME_BUDGET')}
    return shots[-1][1], (shots[-2][1] if len(shots) > 1 else b''), report


def verify(report, evidence_png, previous_png, expected_policy=None):
    """Trusted re-check. -> a rebuilt record whose `value` is STABLE only if every check passes; otherwise UNSTABLE with a reason."""
    def unstable(reason, rebuilt=None):
        return {'schema': SCHEMA, 'value': 'UNSTABLE', 'reason': reason, 'source': 'worker:stability-policy-v1', **(rebuilt or {})}
    try:
        if type(report) is not dict or report.get('schema') != SCHEMA:
            return unstable('NOT_REPORTED')
        rules = policy(report['policy'])
        if expected_policy is not None and rules != policy(expected_policy):
            return unstable('POLICY_MISMATCH')
        shots = report['shots']
        if (type(shots) is not list or not 1 <= len(shots) <= rules['max_attempts'] or report['attempts'] != len(shots)
                or any(type(s) is not dict or type(s.get('t_ms')) is not int or s['t_ms'] < 0 or not _SHA.match(str(s.get('sha256')))
                       for s in shots)
                or any(b['t_ms'] < a['t_ms'] for a, b in zip(shots, shots[1:]))
                or type(report['elapsed_ms']) is not int or not 0 <= report['elapsed_ms'] <= 120000):
            return unstable('REPORT_INVALID')
    except (KeyError, TypeError, ValueError):
        return unstable('REPORT_INVALID')
    rebuilt = {'policy': rules, 'attempts': len(shots), 'elapsed_ms': report['elapsed_ms'],
               'shots': [{'t_ms': s['t_ms'], 'sha256': s['sha256']} for s in shots]}
    received = [hashlib.sha256(evidence_png).hexdigest(), hashlib.sha256(previous_png).hexdigest() if previous_png else None]
    if shots[-1]['sha256'] != received[0] or (len(shots) > 1 and shots[-2]['sha256'] != received[1]):
        return unstable('RECEIVED_IMAGES_DIFFER_FROM_REPORT', rebuilt)
    if not settled([(s['t_ms'], s['sha256']) for s in shots], rules) or report.get('value') != 'STABLE':
        return unstable('NOT_SETTLED', rebuilt)
    if previous_png != evidence_png:  # The two images the worker holds must themselves be identical, byte for byte.
        return unstable('RECEIVED_IMAGES_NOT_IDENTICAL', rebuilt)
    return {'schema': SCHEMA, 'value': 'STABLE', 'reason': None, 'source': 'worker:stability-policy-v1', **rebuilt}
