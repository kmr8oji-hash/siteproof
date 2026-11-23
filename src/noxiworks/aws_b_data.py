"""Local AWS-B GetItem/Query response bridge. No boto3, sockets, credentials or HTTP.

python -B -m src.noxiworks.aws_b_data --fixture-output NEW_D_DIRECTORY
python -B -m src.noxiworks --aws-b-input DIRECTORY --out NEW_D_DIRECTORY
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import argparse
import json
from pathlib import Path
import stat

from src.aws_b.handler import Deps
from src.aws_b.model import EVENT_SCHEMA, format_utc
from src.aws_b.probe import ProbeResult
from src.aws_b.store import DynamoStore
from src.core.model import CheckOutcome
from .product import settings, export_http, page_runs, monitor_config, run_page, trial_config

SCHEMA = 'siteproof.aws-b-export.v1'
MAX_FILE_BYTES = 4 * 1024 * 1024


def _read(root, relative):
    path = root / relative
    current = root
    for part in ('', *Path(relative).parts):
        if part:
            current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('links/junctions are not export inputs')
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('invalid or oversized export file')
    return json.loads(path.read_text('utf-8-sig'))


class LocalReadStore:
    """DynamoStore's reader interface, backed solely by SDK/CLI response JSON."""
    def __init__(self, target_id, head, runs):
        self.target_id, self.head_item, self.run_items = target_id, head, runs

    def head(self, target_id):
        if target_id != self.target_id:
            raise ValueError('cross-page read')
        return deepcopy(self.head_item)

    def recent_runs(self, target_id, limit=56):
        if target_id != self.target_id:
            raise ValueError('cross-page read')
        return deepcopy(sorted(self.run_items, key=lambda r: r.get('sk', {}).get('S', ''), reverse=True)[:limit])


def read_export(directory):
    root = Path(directory).absolute()
    metadata = _read(root, 'manifest.json')
    if (metadata.get('schema') != SCHEMA or metadata.get('source') not in ('FIXTURE', 'AWS_EXPORT')
            or type(metadata.get('target_ids')) is not list):
        raise ValueError('explicit export schema/source/targets required')
    ids = metadata['target_ids']
    config = trial_config(metadata.get('trial'))
    pages = {p['target_id']: p for p in config['pages']}
    if len(ids) != len(set(ids)) or set(ids) - set(pages):
        raise ValueError('unregistered/duplicate export target')
    stores = {}
    for target_id, page in pages.items():
        head, runs = None, []
        if target_id in ids:
            control = _read(root, target_id + '/head.json')
            query = _read(root, target_id + '/runs.json')
            if type(control) is not dict or type(query) is not dict or type(query.get('Items')) is not list:
                raise ValueError('GetItem/Query response shape invalid')
            if metadata['source'] != 'FIXTURE' and any(r.get('_siteproof_source') == 'FIXTURE' for r in (control, query)):
                raise ValueError('synthetic response cannot be labelled AWS export')
            head, runs = control.get('Item'), query['Items']
            if head is not None and type(head) is not dict or any(type(r) is not dict for r in runs):
                raise ValueError('DynamoDB item shape invalid')
            page_runs(page, {'head': head, 'runs': runs})
        stores[target_id] = LocalReadStore(target_id, head, runs)
    context = _read(root, 'context.json') if (root / 'context.json').exists() else None
    if context and context.get('trial') != metadata.get('trial'):
        raise ValueError('cross-trial context rejected')
    snapshot = export_http(stores, snapshot=context, config=config, source=metadata['source'])
    if 'trial' in metadata:
        snapshot['trial'] = config['trial']
    snapshot['http_export'] = {'schema': SCHEMA, 'exported_at': metadata.get('exported_at'),
        'history_limit_per_page': 56, 'source_authentication': 'NOT_VERIFIED'}
    return snapshot


def read_stores(stores, *, now, interval_seconds=900, source='AWS_EXPORT', context=None, trial=None):
    """Freeze existing reader interfaces, then reuse export_http; never reuse old UP.

    A per-page read/binding error clears that page and is explicitly UNKNOWN.
    Reading runs before HEAD observes a stop/generation change after the query.
    """
    config = trial_config(trial)
    if context and context.get('trial') != trial:
        raise ValueError('cross-trial context rejected')
    if trial is not None and interval_seconds != 900:
        raise ValueError('fixture trial requires 15-minute interval')
    pages = config['pages']
    if set(stores) != {p['target_id'] for p in pages}:
        raise ValueError('exact registered readers required')
    if type(interval_seconds) is not int or not 60 <= interval_seconds <= 86400:
        raise ValueError('invalid monitor interval')
    frozen, errors = {}, {}
    for page in pages:
        tid = page['target_id']
        try:
            runs = stores[tid].recent_runs(tid, limit=56)
            head = stores[tid].head(tid)
            if type(runs) is not list or len(runs) > 56 or any(type(r) is not dict for r in runs) or head is not None and type(head) is not dict:
                raise ValueError('invalid reader response')
            page_runs(page, {'head': head, 'runs': runs})
        except Exception:
            # Never persist exception text, credentials, or the prior page's result.
            head, runs = None, []
            errors[tid] = 'READ_FAILED'
        frozen[tid] = LocalReadStore(tid, head, runs)
    snapshot = export_http(frozen, snapshot=context, config=config, source=source)
    if trial is not None:
        snapshot['trial'] = config['trial']
    snapshot['http_export'] = {'schema': SCHEMA, 'acquisition': 'READ_ONLY_REFRESH',
        'fetched_at': format_utc(now), 'interval_seconds': interval_seconds,
        'read_errors': errors, 'history_limit_per_page': 56, 'source_authentication': 'NOT_VERIFIED'}
    return snapshot


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)


def write_fixture(output, now=None):
    """Existing handler -> conditional Dynamo writes -> typed response files.

    Uses the existing FakeDynamo and injected ProbeResult only. Never calls run_probe
    or the Lambda entry point that constructs real adapters. No image/approval data.
    """
    from tests.aws_fakes import FakeDynamo
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pages = settings()['pages']
    client = FakeDynamo()
    store = DynamoStore(client, 'offline-monitor-results')
    decisions, probes, lines = [], [], []
    # FAIL->PASS, PASS->FAIL, no observation, UNKNOWN, PASS; one distinct page each.
    scenarios = [('FAIL', 'PASS'), ('PASS', 'FAIL'), (), ('UNKNOWN',), ('PASS',)]
    for index, page in enumerate(pages):
        cfg = monitor_config(page, table='offline-monitor-results', absolute_end_at=format_utc(now + timedelta(hours=1)))
        store.arm(target_id=cfg.target_id, hostname=cfg.hostname, policy_version=cfg.policy_version,
            execution_generation=1, armed_at=format_utc(now - timedelta(minutes=10)))
        for step, outcome in enumerate(scenarios[index % len(scenarios)]):
            moment = now - timedelta(minutes=5) if len(scenarios[index % len(scenarios)]) > 1 and step == 0 else now
            # Explicit fixture outcomes; the configured URL is never contacted.
            def probe(deadline, outcome=outcome, index=index, target=cfg.target_id):
                probes.append(target)
                status = None if outcome == 'UNKNOWN' else 503 if outcome == 'FAIL' else 200
                return ProbeResult(CheckOutcome(outcome), 'DNS_ERROR' if status is None else 'HTTP_' + str(status),
                    http_status=status, elapsed_ms=80 + index * 25,
                    tls_not_after=None if status is None else (now + timedelta(days=60)).strftime('%b %d %H:%M:%S %Y GMT'))
            deps = Deps(cfg, store, probe, lambda moment=moment: moment, lines.append,
                attempt_id=f'fixture-{index}-{step}')
            event = {'schema': EVENT_SCHEMA, 'target_id': cfg.target_id, 'scheduled_time': format_utc(moment), 'execution_generation': 1}
            decisions.append(run_page(page, event, deps))
            decisions.append(run_page(page, event, deps))  # Actual handler duplicate refusal.
        head, runs = store.head(cfg.target_id), store.recent_runs(cfg.target_id, limit=56)
        _write(output / cfg.target_id / 'head.json', {'Item': head, '_siteproof_source': 'FIXTURE'})
        _write(output / cfg.target_id / 'runs.json', {'Items': runs, 'Count': len(runs), '_siteproof_source': 'FIXTURE'})
    _write(output / 'manifest.json', {'schema': SCHEMA, 'source': 'FIXTURE', 'exported_at': format_utc(now),
        'target_ids': [p['target_id'] for p in pages]})
    _write(output / 'fixture-audit.json', {'source': 'FIXTURE', 'actual_http_requests': 0,
        'decisions': decisions, 'probe_stub_calls': probes, 'metric_lines': lines})
    return now


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-output', required=True, type=Path)
    args = parser.parse_args()
    write_fixture(args.fixture_output)
    print(str(args.fixture_output / 'manifest.json') + ' / FIXTURE / no network')


if __name__ == '__main__':
    main()
