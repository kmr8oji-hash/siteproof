"""AWS-B verify-state result (a local STATE_*.json) -> SiteProof schedule-state records for HOME. No AWS access, no network.

Run: py -3.15 -B tools/aws_b_schedule_state.py --state <...>\\STATE_RUNNING_<time>.json --out NEW_FILE.json
     py -3.15 -B -m src.noxiworks --archive ... --schedule NEW_FILE.json ...

The verify-state file is what the AWS-B operator scripts wrote after reading AWS (read-only) at that moment. Only a file whose
result MATCHES its expectation is accepted. Each registered page gets one `http` record: enabled = the provider was verified Running,
observed_at = when it was verified. HOME shows an old reading as "有効の記録あり・現在未確認", never as running now.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import format_utc, parse_utc
from src.noxiworks.monitoring import SCHEDULE_SCHEMA, schedule_record
from src.noxiworks.product import settings

ACCEPTED = {('Running', 'STATE_MATCHES_RUNNING'): True, ('Stopped', 'STATE_MATCHES_STOPPED'): False}


def records(state, source_name, config=None):
    """-> one validated http record per registered page, or ValueError."""
    key = (state.get('expect'), state.get('result'))
    observed = parse_utc(state.get('at'))
    if key not in ACCEPTED or observed is None or state.get('mismatches') != 0:
        raise ValueError('not a matching AWS-B verify-state result')
    checks = {c.get('check'): c.get('ok') for c in state.get('checks', [])}
    if ACCEPTED[key] and checks.get('scheduler-5-ENABLED') is not True:
        raise ValueError('Running result without the enabled-schedules check')
    pages = (config or settings())['pages']
    return [schedule_record({'schema': SCHEDULE_SCHEMA, 'target_id': p['target_id'], 'channel': 'http', 'enabled': ACCEPTED[key],
                             'last_finished_at': None, 'last_outcome': None, 'next_due_at': None, 'observed_at': format_utc(observed),
                             'source': f'AWS-B verify-state（ローカル記録 {source_name}）'}) for p in pages]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        out = records(json.loads(args.state.read_text('utf-8-sig')), args.state.name)
    except (OSError, ValueError) as exc:
        print('REFUSED: ' + str(exc), file=sys.stderr)
        return 1
    with args.out.open('x', encoding='utf-8') as stream:  # new file only
        json.dump(out, stream, ensure_ascii=False, indent=2)
    print(f'{len(out)} records, enabled={out[0]["enabled"]}, observed_at={out[0]["observed_at"]} -> {args.out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
