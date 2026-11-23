"""One-command read-only HOME refresh. No scheduler/service/provider is started.

Outputs are owned, versioned D: directories. Only latest.html and refresh-state.json
are atomically replaced; prior generations and incomplete failures are retained.
AWS CLI is invoked only by the explicit --refresh-config + --aws-read entry point.
"""
from datetime import datetime, timezone
from html import escape
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from src.aws_b.model import format_utc, head_key
from src.aws_b.store import build_recent_query
from .aws_b_data import LocalReadStore, read_export, read_stores, _read
from .home import build
from .product import settings, trial_config

SCHEMA = 'siteproof.home-refresh.v1'


def load_config(path):
    path = Path(path).absolute()
    value = _read(path.parent, path.name)
    if (set(value) not in ({'schema', 'profile', 'region', 'tables', 'interval_seconds'}, {'schema', 'profile', 'region', 'tables', 'interval_seconds', 'trial'})
            or value['schema'] != 'siteproof.aws-b-refresh.v1'
            or value['profile'] != 'siteproof-live' or value['region'] != 'us-east-1'
            or type(value['interval_seconds']) is not int or not 60 <= value['interval_seconds'] <= 86400):
        raise ValueError('invalid explicit refresh configuration')
    config = trial_config(value.get('trial'))
    if value.get('trial') is not None and value['interval_seconds'] != 900:
        raise ValueError('fixture trial requires 15-minute interval')
    tables = value['tables']
    if (type(tables) is not dict or set(tables) != {p['target_id'] for p in config['pages']}
            or any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}', v) for v in tables.values())
            or len(set(tables.values())) != len(tables)):
        raise ValueError('distinct explicit registered tables required')
    return value


def cli_stores(config, *, runner=None, environ=None):
    """Only GetItem/Query, using existing request builder and LocalReadStore.

    No credential lookup here. An existing AWS CLI authentication session (the user's own `aws login` / profile) must already
    be established and separately authorized for AWS reads before this is called. Any AWS config / cache location that is set
    must be an absolute path (no drive is required); unset ones use the AWS CLI defaults.
    """
    env = dict(os.environ if environ is None else environ)
    for key in ('AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_LOGIN_CACHE_DIRECTORY', 'USERPROFILE'):
        if env.get(key) and not Path(env[key]).is_absolute():
            raise ValueError('absolute AWS authentication paths required')
    if any(env.get(k) for k in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                                'AWS_ENDPOINT_URL', 'AWS_ENDPOINT_URL_DYNAMODB', 'AWS_WEB_IDENTITY_TOKEN_FILE')):
        raise ValueError('ambiguous credential/endpoint environment refused')
    env.update(AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')
    runner = runner or subprocess.run

    def call(operation, request):
        result = runner(['aws', 'dynamodb', operation, '--profile', config['profile'],
            '--region', config['region'], '--endpoint-url', 'https://dynamodb.us-east-1.amazonaws.com', '--cli-input-json', json.dumps(request),
            '--output', 'json', '--no-cli-pager', '--no-paginate',
            '--cli-connect-timeout', '5', '--cli-read-timeout', '10'],
            capture_output=True, text=True, encoding='utf-8', timeout=30, env=env)
        if result.returncode != 0 or len(result.stdout.encode('utf-8')) > 4*1024*1024:
            raise ValueError('READ_FAILED')
        return json.loads(result.stdout.lstrip('\ufeff'))

    stores = {}
    for page in trial_config(config.get('trial'))['pages']:
        tid, table = page['target_id'], config['tables'][page['target_id']]
        try:
            query = call('query', build_recent_query(table, tid, 56))
            control = call('get-item', {'TableName': table,
                'Key': {k: {'S': v} for k,v in head_key(tid).items()}, 'ConsistentRead': True})
            if type(query.get('Items')) is not list or control.get('Item') is not None and type(control['Item']) is not dict:
                raise ValueError('invalid response')
            stores[tid] = LocalReadStore(tid, control.get('Item'), query['Items'])
        except Exception:
            stores[tid] = None  # read_stores clears it and records READ_FAILED.
    return stores


def _check_path(path):
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError('linked refresh paths refused')


def _root(output):
    root = Path(output).absolute()
    _check_path(root)
    marker = root / 'managed.json'
    if root.exists():
        if not marker.is_file() or _read(root, 'managed.json') != {'schema': SCHEMA}:
            raise ValueError('existing non-refresh output refused')
    else:
        root.mkdir(parents=True, exist_ok=False)
        with marker.open('x', encoding='utf-8') as f:
            json.dump({'schema': SCHEMA}, f)
    for name in ('versions', 'latest.html', 'refresh-state.json', '.refresh-lock'):
        _check_path(root / name)
    (root / 'versions').mkdir(exist_ok=True)
    return root


def _atomic(path, text):
    tmp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    with tmp.open('x', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


def _entry(relative, failed=False):
    if relative is not None and not re.fullmatch(r'versions/[A-Za-z0-9-]+/index\.html', relative):
        raise ValueError('invalid generation reference')
    refresh = f'<meta http-equiv="refresh" content="0; url={relative}">' if relative and not failed else ''
    link = f'<p><a href="{escape(relative, quote=True)}">保存記録を開く（現在状態を保証しません）</a></p>' if relative else ''
    message = '更新失敗 · 現在の監視状態：UNKNOWN。前回のUPを現在状態として表示しません。' if failed else '取得時点の監視記録です。自動更新なし・閲覧時の状態はUNKNOWNです。'
    return f'<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">{refresh}<title>SiteProof 更新</title></head><body><h1>SiteProof</h1><p>{message}</p>{link}</body></html>'


def report_failure(output):
    """Fail the stable entry closed even when configuration/CLI setup fails first."""
    root = _root(output)
    lock = root / '.refresh-lock'
    lock.mkdir(exist_ok=False)
    try:
        last = _read(root, 'refresh-state.json').get('last_success') if (root / 'refresh-state.json').exists() else None
        _atomic(root / 'latest.html', _entry(last, failed=True))
    finally:
        lock.rmdir()


def update(output, *, now=None, stores=None, export_directory=None, interval_seconds=900,
           source='AWS_EXPORT', context=None, trial=None):
    """Injected readers OR existing local export; no AWS client construction here."""
    if (stores is None) == (export_directory is None):
        raise ValueError('choose exactly one read source')
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    root = _root(output)
    lock = root / '.refresh-lock'
    lock.mkdir(exist_ok=False)  # Refuse concurrent refresh; never steal a lock.
    last_success = None
    try:
        state_file = root / 'refresh-state.json'
        if state_file.exists():
            old = _read(root, 'refresh-state.json')
            if old.get('schema') != SCHEMA:
                raise ValueError('invalid owned refresh state')
            last_success = old.get('last_success')
            if last_success:
                _entry(last_success)  # Validate before it can become a link.
        if export_directory is not None:
            snapshot = read_export(export_directory)
            snapshot['http_export'].update(acquisition='READ_ONLY_REFRESH', fetched_at=format_utc(now),
                interval_seconds=interval_seconds, read_errors={}, historical=True)
        else:
            snapshot = read_stores(stores, now=now, interval_seconds=interval_seconds, source=source, context=context, trial=trial)
        generation = now.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
        stage = root / ('.incomplete-' + generation)
        version = root / 'versions' / generation
        view = build(stage, snapshot, now=now)
        from tools.export_capture_fixture import verify_links
        verify_links(stage)  # Files/fragments/safe navigation only, never requests URLs.
        os.replace(stage, version)
        relative = 'versions/' + generation + '/index.html'
        errors = snapshot['http_export'].get('read_errors', {})
        status = 'PARTIAL' if errors else 'OK'
        if not errors:
            last_success = relative
        state = {'schema': SCHEMA, 'status': status, 'fetched_at': format_utc(now),
            'last_success': last_success, 'generation': relative, 'read_errors': errors}
        _atomic(state_file, json.dumps(state, ensure_ascii=False, indent=2) + '\n')
        _atomic(root / 'latest.html', _entry(relative))
        return {**state, 'entry': str(root / 'latest.html'), 'version': str(version), 'view': view}
    except Exception:
        # Preserve the last good snapshot; the stable entry explicitly fails closed.
        _atomic(root / 'latest.html', _entry(last_success, failed=True))
        raise
    finally:
        lock.rmdir()  # Only the empty lock created by this invocation.
