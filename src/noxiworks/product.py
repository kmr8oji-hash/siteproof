"""Fixed-page adapters around AWS-B and M1/M5. All I/O is explicitly injected/local."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import ssl
from urllib.parse import urlsplit

from src.aws_b.handler import run
from src.aws_b.model import MonitorConfig, format_utc, parse_utc
from src.aws_b.view import summarize
from src.comparison.operational import present
from src.core.model import validate_id
from src.runtime.stability import policy as stability_policy

CONFIG = Path(__file__).with_name('targets.json')
SOURCES = {'EMPTY', 'FIXTURE', 'AWS_EXPORT', 'LOCAL_CAPTURE'}
REAL_SOURCES = ('AWS_EXPORT', 'LOCAL_CAPTURE')


def settings(path=None):
    # SITEPROOF_TARGETS: the local app points its page generation at a user-registered site (src/noxiworks/app.py).
    config = json.loads(Path(path or os.environ.get('SITEPROOF_TARGETS') or CONFIG).read_text('utf-8'))
    extra = os.environ.get('SITEPROOF_DISPLAY_TARGETS')
    if extra and not path:
        # DISPLAY-ONLY pages (the AWS-B pages found in an imported archive): shown on HOME next to the registered site, never part of the registered site's
        # signed targets.json (which a permit pins) and never capturable. Registered ids always win.
        more = json.loads(Path(extra).read_text('utf-8'))
        have_pages, have_sites = {p['target_id'] for p in config.get('pages', [])}, {s['site_id'] for s in config.get('sites', [])}
        config = {**config, 'sites': [*config.get('sites', []), *[s for s in more.get('sites', []) if s['site_id'] not in have_sites]],
                  'pages': [*config.get('pages', []), *[p for p in more.get('pages', []) if p['target_id'] not in have_pages]]}
    sites = {}
    for site in config.get('sites', []):
        validate_id(site['site_id'], 'site_id')
        u = urlsplit(site['origin'])
        registration = site.get('registration_domain')
        if (site['site_id'] in sites or u.scheme != 'https' or not u.hostname
                or u.username or u.password or u.path or u.query or u.fragment or u.port not in (None, 443)
                or registration and not (u.hostname == registration or u.hostname.endswith('.' + registration))
                or registration is None and not site.get('registration_managed_by')):
            raise ValueError('invalid site/registration policy')
        sites[site['site_id']] = site
    ids = set()
    for page in config['pages']:
        if sites:
            site = sites[page['site_id']]
            if urlsplit(page['url']).netloc != urlsplit(site['origin']).netloc:
                raise ValueError('page/site origin mismatch')
            page.update(site_name=site['name'], domain=urlsplit(site['origin']).hostname,
                registration_domain=site.get('registration_domain'),
                registration_managed_by=site.get('registration_managed_by'))
        validate_id(page['target_id'], 'target_id')
        u = urlsplit(page['url'])
        if (page['target_id'] in ids or u.scheme != 'https' or u.username or u.password
                or u.port not in (None, 443) or u.query or u.fragment or not u.hostname
                or not u.path.startswith('/') or u.path.startswith('//')
                or not (u.hostname == page['domain'] or u.hostname.endswith('.' + page['domain']))):
            raise ValueError('invalid or duplicate target')
        ids.add(page['target_id'])
    for name in ('http_interval_seconds', 'capture_interval_seconds', 'tls_stale_seconds', 'domain_stale_seconds'):
        if type(config[name]) is not int or config[name] <= 0:
            raise ValueError('positive interval required')
    return config


def trial_config(trial=None):
    """Explicit temporary sixth target only. The normal targets.json stays unchanged."""
    config = settings()
    if trial is None:
        return config
    import re
    if (type(trial) is not dict or set(trial) != {'schema', 'trial_id', 'fixture_url', 'absolute_end_at'}
            or trial['schema'] != 'siteproof.aws-b-trial.v1'
            or not isinstance(trial['trial_id'], str) or not re.fullmatch(r'[0-9]{8}-[0-9]{6}', trial['trial_id'])
            or parse_utc(trial['absolute_end_at']) is None or not isinstance(trial['fixture_url'], str)):
        raise ValueError('invalid explicit trial contract')
    url = trial['fixture_url']
    if not re.fullmatch(r'https://[a-z0-9]{1,63}\.lambda-url\.us-east-1\.on\.aws/', url):
        raise ValueError('exact us-east-1 Function URL required')
    host = urlsplit(url).hostname
    config['trial'] = deepcopy(trial)
    config['http_interval_seconds'] = 900
    config['pages'].append({'target_id': 'aws-b-http-fixture', 'site_id': 'aws-b-trial',
        'site_name': 'AWS-B 一時試験', 'label': 'HTTP障害・復旧fixture', 'url': url,
        'domain': host, 'registration_domain': None, 'registration_managed_by': 'AWS',
        'trial_fixture': True, 'trial_id': trial['trial_id']})
    return config


def local_capture_config(config, local):
    """Pages that were captured locally but are not monitoring targets. targets.json stays unchanged.

    Each one must be a plain https page of an already registered site (same origin), never a new host.
    """
    if local is None:
        return config
    if type(local) is not dict or local.get('schema') != 'siteproof.local-capture.v1' or type(local.get('pages')) is not list:
        raise ValueError('invalid local capture contract')
    sites = {s['site_id']: s for s in config.get('sites', [])}
    known = {p['target_id'] for p in config['pages']}
    for page in local['pages']:
        validate_id(page['target_id'], 'target_id')
        site = sites.get(page.get('site_id'))
        u = urlsplit(page['url'])
        if (site is None or page['target_id'] in known or u.scheme != 'https' or f'{u.scheme}://{u.netloc}' != site['origin']
                or u.query or u.fragment or u.username or u.port not in (None, 443) or u.path in ('', '/') or not u.path.startswith('/')
                or not isinstance(page.get('label'), str) or not page['label']):
            raise ValueError('invalid local capture page')
        known.add(page['target_id'])
        config['pages'].append({'target_id': page['target_id'], 'site_id': page['site_id'], 'site_name': site['name'], 'label': page['label'],
            'url': page['url'], 'domain': u.hostname, 'registration_domain': site.get('registration_domain'),
            'registration_managed_by': site.get('registration_managed_by'), 'local_capture': True})
    return config


PLAN = Path(__file__).with_name('capture_plan.json')
PLAN_ROLES = ('PRIMARY', 'FEATURE_CANDIDATE', 'SUPPLEMENTAL')
PLAN_STATES = ('NOT_APPROVED', 'NOT_CAPTURABLE', 'CAPTURED_ONCE')


def capture_plan(config=None, path=None):
    """Which pages of which site are captured, with which profiles. -> {'pages': {page_id: entry}, 'sites': {site_id: stability}}.

    A plan only describes; it starts nothing and approves nothing. A PRIMARY page must be a registered target (same URL).
    """
    config = config or settings()
    raw = json.loads(Path(path or os.environ.get('SITEPROOF_CAPTURE_PLAN') or PLAN).read_text('utf-8'))
    if type(raw) is not dict or raw.get('schema') != 'siteproof.capture-plan.v1' or type(raw.get('sites')) is not list:
        raise ValueError('invalid capture plan')
    sites = {s['site_id']: s for s in config.get('sites', [])}
    targets = {p['target_id']: p for p in config['pages']}
    pages, stability = {}, {}
    for site in raw['sites']:
        known = sites.get(site.get('site_id'))
        if known is None or site['site_id'] in stability:
            raise ValueError('capture plan site is not registered')
        stability[site['site_id']] = [{'item': str(s['item']), 'handling': str(s['handling'])} for s in site.get('stability', [])]
        for page in site['pages']:
            validate_id(page['page_id'], 'target_id')
            u = urlsplit(page['path'])
            kinds = [p.get('kind') for p in page['profiles']]
            if (page['page_id'] in pages or page['role'] not in PLAN_ROLES or page['real_capture'] not in PLAN_STATES
                    or u.scheme or u.netloc or u.query or u.fragment or not page['path'].startswith('/') or page['path'].startswith('//')
                    or not isinstance(page.get('label'), str) or not page['label'] or len(set(kinds)) != len(kinds) or not kinds
                    or not set(kinds) <= {'Desktop', 'Mobile'}
                    or any(type(p[k]) is not int or not 1 <= p[k] <= 4096 for p in page['profiles'] for k in ('width', 'height'))
                    or any(type(p['full_page']) is not bool for p in page['profiles'])):
                raise ValueError('invalid capture plan page')
            url = known['origin'] + page['path']
            registered = page['page_id'] in targets
            if registered and (targets[page['page_id']]['url'] != url or targets[page['page_id']]['site_id'] != site['site_id']):
                raise ValueError('capture plan page differs from its registered target')
            if page['role'] == 'PRIMARY' and not registered:
                raise ValueError('a primary capture page must be a registered monitoring target')
            try:  # Optional per-page stability policy; malformed or out of bounds = an invalid plan (never widened silently).
                stable = stability_policy(page['stability']) if 'stability' in page else None
            except ValueError:
                raise ValueError('invalid capture plan stability policy') from None
            pages[page['page_id']] = {**{k: page.get(k) for k in ('page_id', 'role', 'label', 'path', 'real_capture', 'why', 'entry', 'blocker')},
                                      'site_id': site['site_id'], 'url': url, 'registered': registered, 'stability': stable,
                                      'profiles': [{k: p[k] for k in ('kind', 'width', 'height', 'full_page')} for p in page['profiles']]}
        if sum(p['role'] == 'PRIMARY' for p in pages.values() if p['site_id'] == site['site_id']) > 1:
            raise ValueError('one primary capture page per site')
    return {'pages': pages, 'sites': stability}


def snapshot_config(snapshot):
    return local_capture_config(trial_config(snapshot.get('trial')), snapshot.get('local_capture'))


def site_configs(config=None):
    """One unchanged M1 workspace per configured site; no site-specific branches."""
    config = config or settings()
    groups = {}
    for page in config['pages']:
        key = page.get('site_id', urlsplit(page['url']).hostname)
        validate_id(key, 'site_id')
        groups.setdefault(key, {**config, 'pages': []})['pages'].append(page)
    return groups


def page_by_id(target_id, config=None):
    return next(p for p in (config or settings())['pages'] if p['target_id'] == target_id)


def registered_page(page, config=None):
    registered = {p['target_id']: p for p in (config or settings())['pages']}
    fixed = registered.get(page.get('target_id'))
    if fixed is None or page.get('url') != fixed['url']:
        raise ValueError('unregistered target or URL')
    return fixed


def monitor_config(page, *, table, absolute_end_at, config=None, **options):
    page = registered_page(page, config)
    u = urlsplit(page['url'])
    return MonitorConfig.from_env({**options, 'TARGET_ID': page['target_id'],
        'TARGET_HOSTNAME': u.hostname, 'TARGET_PATH': u.path,
        'POLICY_VERSION': options.get('POLICY_VERSION', 'p1'),
        'TABLE_NAME': table, 'ABSOLUTE_END_AT': absolute_end_at})


def run_page(page, event, deps, *, config=None):
    """One existing handler per page, with the same claims, generation and deadline."""
    page = registered_page(page, config)
    u = urlsplit(page['url'])
    if (deps.config.target_id, deps.config.hostname, deps.config.path) != (page['target_id'], u.hostname, u.path):
        raise ValueError('page/config mismatch')
    return run(event, deps)


def deployment_plan(template, config=None):
    """Separate stacks reuse the original template; original LIVE runbook stays intact."""
    config = config or settings()
    # This product default is independent from the initial 5-minute LIVE test.
    seconds = config['http_interval_seconds']
    if type(seconds) is not int or not 60 <= seconds <= 86400 or seconds % 60:
        raise ValueError('whole-minute bounded product schedule required')
    if seconds % 3600 == 0:
        count = seconds // 3600
        unit = 'hour' if count == 1 else 'hours'
    else:
        count = seconds // 60
        unit = 'minute' if count == 1 else 'minutes'
    expression = f'rate({count} {unit})'
    plans = []
    for page in config['pages']:
        body = deepcopy(template)
        if expression not in body['Parameters']['ScheduleExpression']['AllowedValues']:
            body['Parameters']['ScheduleExpression']['AllowedValues'].append(expression)
        seconds = config['http_interval_seconds']
        alarm_period = body['Parameters'].get('AlarmPeriodSeconds')   # only templates that still carry per-page alarms
        if alarm_period is not None:
            alarm_period['Default'] = seconds
            if seconds not in alarm_period['AllowedValues']:
                alarm_period['AllowedValues'].append(seconds)
                body['Rules']['AlarmIntervalMatchesSchedule']['Assertions'][0]['Assert']['Fn::Or'].append(
                    {'Fn::And': [{'Fn::Equals': [{'Ref': 'ScheduleExpression'}, expression]},
                                 {'Fn::Equals': [{'Ref': 'AlarmPeriodSeconds'}, str(seconds)]}]})
        body['Parameters']['ScheduleExpression']['Default'] = expression
        u = urlsplit(page['url'])
        defaults = {'TargetId': page['target_id'], 'TargetHostname': u.hostname, 'TargetPath': u.path}
        for key, value in defaults.items():
            body['Parameters'][key]['Default'] = value
            body['Parameters'][key]['AllowedValues'] = [value]
        plans.append({'target_id': page['target_id'], 'template': body,
            'parameters': {**defaults, 'ScheduleExpression': expression, 'ScheduleState': 'DISABLED',
                           **({'AlarmPeriodSeconds': seconds} if alarm_period is not None else {})},
            'requires': ['AbsoluteEndAt', 'CodeBucket', 'CodeKey', 'CodeObjectVersion', 'AlertTopicArn'],
            'capture': {'page_id': page['target_id'], 'site_id': page.get('site_id', u.hostname), 'url': page['url'],
                'interval_seconds': config['capture_interval_seconds'], 'state': 'NOT_SCHEDULED',
                'baseline': 'EXPLICIT_APPROVAL_REQUIRED', 'evidence_prefix': 'pages/' + page['target_id'] + '/'}})
    return plans


def text(item, key):
    value = item.get(key, {})
    return value.get('S') if isinstance(value, dict) else None


def numeric(item, key):
    try:
        value = float(item[key]['N'])
        return (int(value) if value.is_integer() else value) if math.isfinite(value) and value >= 0 else None
    except (KeyError, TypeError, ValueError):
        return None


def page_runs(page, data):
    head, runs = data.get('head'), data.get('runs', [])
    if head and (text(head, 'pk'), text(head, 'sk')) != ('CONTROL#' + page['target_id'], 'HEAD'):
        raise ValueError('cross-page control rejected')
    slots = {}
    for record in runs:
        if text(record, 'pk') != 'RUN#' + page['target_id']:
            raise ValueError('cross-page result rejected')
        slot = text(record, 'sk')
        if slot in slots and slots[slot] != record:
            raise ValueError('conflicting duplicate slot')
        slots[slot] = record
    return head, sorted(slots.values(), key=lambda r: text(r, 'sk') or '')


def http_view(page, data, now, interval):
    head, records = page_runs(page, data)
    valid_head = (head and numeric(head, 'execution_generation') is not None
                  and numeric(head, 'execution_generation') >= 1
                  and text(head, 'target_hostname') == urlsplit(page['url']).hostname
                  and text(head, 'policy_version'))
    current = [r for r in records if valid_head and r.get('execution_generation') == head.get('execution_generation')
               and r.get('policy_version') == head.get('policy_version')]
    view = summarize(head, current, now=now, interval_seconds=interval, stale_after_intervals=2)
    if head is None and not records:
        view.update(state='NOT_FETCHED', reason='NOT_FETCHED')
    if head and head.get('enabled', {}).get('BOOL') is False:
        view.update(state='STOPPED', reason='MONITORING_NOT_ARMED')
    latest = current[-1] if current else {}
    observed = parse_utc(text(latest, 'finished_at'))
    slot = parse_utc(text(latest, 'sk'))
    if latest and (observed is None or slot is None or observed > now or slot > now or observed < slot):
        view.update(state='UNKNOWN', reason='OBSERVATION_TIME_INVALID')
    # last_outcome: the saved outcome of that latest observation (PASS / FAIL / None); it says nothing about now.
    view.update(last_checked_at=text(latest, 'finished_at'), http_status=numeric(latest, 'http_status'), last_outcome=text(latest, 'outcome'),
                elapsed_ms=numeric(latest, 'elapsed_ms'),
                fresh_until=format_utc(slot + timedelta(seconds=interval * 2))
                if slot and observed and slot <= observed <= now else None)
    history, previous, generation = [], None, None
    for record in records:
        if text(record, 'state') != 'RECORDED':
            continue
        outcome = text(record, 'outcome')
        this_generation = (record.get('execution_generation', {}).get('N'), text(record, 'policy_version'))
        if this_generation != generation:
            previous, generation = None, this_generation
        at = parse_utc(text(record, 'finished_at'))
        if at is None or at > now or parse_utc(text(record, 'sk')) is None:
            continue
        # UNKNOWN breaks continuity: it is never evidence of recovery.
        if outcome == 'FAIL' and previous != 'FAIL':
            history.append({'at': text(record, 'finished_at'), 'event': '異常を検知', 'target_id': page['target_id']})
        if outcome == 'PASS' and previous == 'FAIL':
            history.append({'at': text(record, 'finished_at'), 'event': '復旧を確認', 'target_id': page['target_id']})
        previous = outcome
    view['history'] = history
    return view


def expiry_view(observation, *, scope, now, max_age):
    observation = observation or {}
    observed = parse_utc(observation.get('observed_at'))
    expires = parse_utc(observation.get('expires_at'))
    base = {**observation, 'scope': scope, 'state': 'UNKNOWN', 'remaining_days': None}
    if observation.get('scope') != scope or not observation.get('source'):
        return {**base, 'reason': '未取得・取得元不明'}
    if observed is None or expires is None or not 0 <= (now - observed).total_seconds() <= max_age:
        return {**base, 'reason': '期限不明・観測が古い／不正'}
    days = math.floor((expires - now).total_seconds() / 86400)
    return {**base, 'remaining_days': days, 'state': 'EXPIRED' if expires <= now else 'WARNING' if days <= 30 else 'OK',
            'reason': '観測した期限に基づく（自動更新予定は未反映）'}


def tls_observation(host, pages, raw):
    found = []
    for page in pages:
        if urlsplit(page['url']).hostname != host:
            continue
        _, runs = page_runs(page, raw.get(page['target_id'], {}))
        found.extend(r for r in runs if text(r, 'state') == 'RECORDED' and parse_utc(text(r, 'finished_at')))
    if not found:
        return None
    latest = max(found, key=lambda r: text(r, 'finished_at'))
    end = text(latest, 'tls_not_after')
    if parse_utc(end) is None:
        try:
            end = format_utc(datetime.fromtimestamp(ssl.cert_time_to_seconds(end), timezone.utc))
        except (ValueError, TypeError, OverflowError):
            end = None
    return {'scope': host, 'expires_at': end, 'observed_at': text(latest, 'finished_at'), 'source': 'AWS-B TLS handshake (imported)'}


def _change_state(value, page, now, interval):
    value = value or {}
    if value and (value.get('page_id') != page['target_id'] or value.get('url') != page['url']):
        raise ValueError('cross-page capture rejected')
    at = parse_utc(value.get('observed_at'))
    base = {**value, 'state': 'UNKNOWN', 'quality': 'UNKNOWN', 'reason': '初回撮影待ち・Baseline未設定'}
    if not at:
        return base
    if not 0 <= (now - at).total_seconds() <= interval * 2:
        return {**base, 'reason': '撮影結果の鮮度不足／時刻不正'}
    reasons = value.get('reasons', [])
    if not value.get('baseline_approved') or value.get('source_availability') != 'VERIFIED':
        return {**base, 'reason': 'Baseline未承認・証拠未検証'}
    metrics = value.get('metrics')
    if metrics is None or any(r not in ('PROFILE_UNATTESTED', 'CAPTURE_UNSTABLE') for r in reasons):
        return {**base, 'reason': '比較未完了・検証条件不足'}
    changed = metrics.get('changed_pixels')
    if type(changed) is not int or changed < 0:
        return {**base, 'reason': '差分値不正'}
    return {**base, 'state': 'CHANGED' if changed else 'UNCHANGED',
        'reason': ('差分あり・要確認（不具合の確定ではありません）' if changed else 'ピクセル差分なし')
                  + ('／撮影条件未認証' if reasons else '')}


def change_view(value, page, now, interval, *, require_operational=False):
    """Strict-compatible state, only ever downgraded to UNKNOWN by the saved operational verdict.

    Results saved before the operational record existed are shown as "not recorded"; for
    imported real data (`require_operational`) they cannot stay a "no change" either.
    """
    out = _change_state(value, page, now, interval)
    result = (value or {}).get('result')
    visual = present(result, out['state'])
    if out['state'] in ('CHANGED', 'UNCHANGED'):
        if visual['recorded'] and visual['verdict'] == 'UNKNOWN':
            out = {**out, 'state': 'UNKNOWN', 'reason': '画像検査は判定不能：' + '／'.join(visual['reason_labels'])}
        elif not visual['recorded'] and require_operational:
            out = {**out, 'state': 'UNKNOWN', 'reason': '運用判定の記録なし（旧データ）'}
    return {**out, 'visual': present(result, out['state'])}


def collect_comparison(service, page, job_id, observed_at):
    """Existing M5 service verifies S1/manifest, approved baseline and image difference.

    No capture or approval is performed here. Invoke only on a working copy of evidence.
    Returns bytes for a static export; no arbitrary evidence URL is trusted.
    """
    _, plan, job = service.plan(job_id)
    if plan['page_id'] != page['target_id'] or job.snapshot.intent.target_url != page['url']:
        raise ValueError('capture target mismatch')
    result = service.compare(job_id)
    checked = service.result(result['result_id'])
    assets = {}
    for role in ('current', 'baseline', 'diff'):
        if role == 'baseline' and not result.get('baseline_job_id') or role == 'diff' and not result.get('diff_sha256'):
            continue
        try:
            assets[role + '.png'] = service.result_image(result['result_id'], role)
        except Exception:
            checked['source_availability'] = 'UNAVAILABLE'
    # Export the verified S1 manifest bindings as part of the evidence, not just pixels.
    manifests = {}
    for role, jid in (('current', job_id), ('baseline', result.get('baseline_job_id'))):
        if jid:
            try:
                manifests[role] = service.evidence_pin(service.observe(jid)[2])
            except Exception:
                checked['source_availability'] = 'UNAVAILABLE'
    pin = result.get('baseline')
    approved = bool(pin) and service.baselines.get(pin['candidate_id']).is_valid_approval()
    return {'page_id': page['target_id'], 'url': page['url'], 'observed_at': observed_at,
        'baseline_approved': approved, 'source_availability': checked['source_availability'],
        'metrics': result['metrics'], 'reasons': result['reasons'], 'profile_trust': result['profile_trust'],
        'quality': 'UNKNOWN', 'result': checked, 'manifests': manifests}, assets


def dashboard(snapshot, *, now, config=None):
    config = config or snapshot_config(snapshot)
    if snapshot.get('schema') != 'siteproof.noxiworks.v1' or snapshot.get('source') not in SOURCES:
        raise ValueError('unknown snapshot/source')
    if snapshot['source'] in REAL_SOURCES:
        for change in snapshot.get('changes', {}).values():
            result = change.get('result', {})
            if result.get('source') == 'SYNTHETIC_FIXTURE' or result.get('trust_domain') == 'OFFLINE_TEST':
                raise ValueError('fixture evidence cannot be labelled AWS export')
    refresh = snapshot.get('http_export', {})
    if refresh.get('acquisition') == 'READ_ONLY_REFRESH':
        interval = refresh.get('interval_seconds')
        if type(interval) is not int or not 60 <= interval <= 86400:
            raise ValueError('invalid refresh interval')
        config = {**config, 'http_interval_seconds': interval}
        errors = refresh.get('read_errors', {})
        if (type(errors) is not dict or set(errors) - {p['target_id'] for p in config['pages']}
                or any(code != 'READ_FAILED' for code in errors.values())):
            raise ValueError('invalid refresh errors')
    else:
        errors = {}
    raw = snapshot.get('http', {})
    allowed = {p['target_id'] for p in config['pages']}
    if (set(raw) | set(snapshot.get('changes', {}))) - allowed:
        raise ValueError('unregistered target')
    pages = []
    for page in config['pages']:
        pages.append({**page, 'http': http_view(page, raw.get(page['target_id'], {}), now, config['http_interval_seconds']),
            'change': change_view(snapshot.get('changes', {}).get(page['target_id']), page, now, config['capture_interval_seconds'],
                                  require_operational=snapshot['source'] in REAL_SOURCES)})
    for page in pages:
        if page.get('trial_fixture') and page['http']['state'] == 'NOT_FETCHED':
            page['http'].update(state='UNKNOWN', reason='NO_OBSERVATION')
        if page['target_id'] in errors:
            page['http'].update(state='UNKNOWN', reason='READ_FAILED', http_status=None, elapsed_ms=None, last_checked_at=None, fresh_until=None)
    # Capture plan (configuration only): what this page is captured with, and the site's feature candidates / stability notes.
    plan = capture_plan(config)
    for page in pages:
        entry = plan['pages'].get(page['target_id'])
        site = page.get('site_id')
        page['plan'] = deepcopy(entry) if entry and entry['url'] == page['url'] else None
        page['plan_site'] = ({'stability': deepcopy(plan['sites'][site]),
                              'candidates': [deepcopy(c) for c in plan['pages'].values() if c['site_id'] == site and c['role'] == 'FEATURE_CANDIDATE']}
                             if site in plan['sites'] else None)
    hosts =sorted({urlsplit(p['url']).hostname for p in config['pages']})
    domains = sorted({p.get('registration_domain', p['domain']) for p in config['pages'] if p.get('registration_domain', p['domain'])})
    expiry = []
    for host in hosts:
        obs = snapshot.get('tls', {}).get(host) or tls_observation(host, config['pages'], raw)
        if obs and snapshot['source'] == 'FIXTURE':
            obs = {**obs, 'source': 'SYNTHETIC_FIXTURE'}
        expiry.append({'kind': 'TLS証明書', **expiry_view(obs, scope=host, now=now, max_age=config['tls_stale_seconds'])})
    for domain in domains:
        expiry.append({'kind': 'ドメイン登録', **expiry_view(snapshot.get('domains', {}).get(domain), scope=domain,
            now=now, max_age=config['domain_stale_seconds'])})
    for key, group in site_configs(config).items():
        page = group['pages'][0]
        if 'registration_domain' in page and page['registration_domain'] is None:
            expiry.append({'kind': 'ドメイン登録', 'scope': page['domain'], 'site_id': key,
                'state': 'PROVIDER_MANAGED', 'remaining_days': None, 'expires_at': None,
                'observed_at': None, 'source': page['registration_managed_by'],
                'reason': '提供元管理。サイト自身の登録更新期限の対象外'})
    # Monitoring status / history / events: recomputed from saved observations; a schedule state only from a provider record.
    from .monitoring import build as monitoring_view
    history = snapshot.get('monitoring_history', [])
    if {h['target_id'] for h in history} - allowed:
        raise ValueError('unregistered history target')
    monitoring = monitoring_view(pages, history, snapshot.get('schedule'), now, http_interval=config['http_interval_seconds'],
                                 capture_interval=config['capture_interval_seconds'], synthetic=snapshot['source'] == 'FIXTURE')
    # This is a static projection, not a live provider connection. Even a fresh
    # saved PASS says nothing about the state when someone later opens its HTML.
    return {'source': snapshot['source'], 'monitoring': monitoring,
        'source_mode': ('REFRESH_SNAPSHOT' if snapshot['source'] == 'AWS_EXPORT' and refresh.get('acquisition') == 'READ_ONLY_REFRESH' and refresh.get('historical') is not True else {'AWS_EXPORT': 'HISTORICAL', 'FIXTURE': 'SAMPLE', 'EMPTY': 'NOT_FETCHED', 'LOCAL_CAPTURE': 'LOCAL_CAPTURE'}[snapshot['source']]),
        'http_refresh': deepcopy(refresh) if refresh.get('acquisition') == 'READ_ONLY_REFRESH' else {},
        'current_monitoring_state': 'UNKNOWN',
        'generated_at': format_utc(now), 'pages': pages, 'expiry': expiry,
        'history': sorted([h for p in pages for h in p['http']['history']], key=lambda h: h['at'], reverse=True),
        'http_interval_seconds': config['http_interval_seconds'], 'capture_interval_seconds': config['capture_interval_seconds']}


def empty_snapshot():
    return {'schema': 'siteproof.noxiworks.v1', 'source': 'EMPTY', 'http': {}, 'changes': {}, 'tls': {}, 'domains': {}}


def export_http(stores, snapshot=None, config=None, *, source="AWS_EXPORT"):
    """Read from explicitly supplied DynamoStore adapters; caller owns AWS permission.

    No boto3 client is constructed. Each store may point to its own page stack/table.
    Domain/RDAP is deliberately not fetched.
    """
    config = config or settings()
    if source not in ('FIXTURE', 'AWS_EXPORT'):
        raise ValueError('explicit export source required')
    if source == 'AWS_EXPORT' and snapshot and snapshot.get('source') == 'FIXTURE':
        raise ValueError('fixture snapshot cannot be relabelled AWS export')
    out = deepcopy(snapshot) if snapshot else empty_snapshot()
    out['source'] = source
    out['http'] = {p['target_id']: {'head': stores[p['target_id']].head(p['target_id']),
        'runs': stores[p['target_id']].recent_runs(p['target_id'], limit=56)} for p in config['pages']}
    return out
