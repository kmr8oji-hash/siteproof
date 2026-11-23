"""Local static export only: python -B -m src.noxiworks --out NEW_DIR [--sample | --snapshot FILE]."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from .home import build
from .product import empty_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sample', action='store_true')
    group.add_argument('--snapshot', type=Path)
    group.add_argument('--aws-b-input', type=Path, help='Local GetItem/Query response directory; no AWS access')
    group.add_argument('--refresh-config', type=Path, help='Explicit table/profile/interval configuration')
    group.add_argument('--archive', type=Path, metavar='ARCHIVE_DIR',
                       help='Local AWS-B run archive (src.noxiworks.archive), verified and read as of now: saved HTTP results, never live; no AWS access')
    parser.add_argument('--refresh', action='store_true', help='Versioned refresh from --aws-b-input; repeat --out safely')
    parser.add_argument('--aws-read', action='store_true', help='Explicit GetItem/Query gate; separate LIVE authorization required')
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--local-capture', type=Path, metavar='RUN_DIR', action='append',
                        help='Saved capture run (read-only, repeatable): shows its real screenshots with their PENDING Baseline candidates. '
                             'Alone, or on top of --snapshot; never approves, compares, or touches the network/AWS')
    parser.add_argument('--baseline-registry', type=Path, metavar='REGISTRY_DIR',
                        help='Formal Baseline registry (tools/register_baseline.py) of a --local-capture page: shows it as approved (read-only)')
    parser.add_argument('--offline-demo', type=Path, metavar='DEMO_DIR',
                        help='Synthetic offline comparison demo (tools/offline_baseline_demo.py) of that registry; shown apart, never as a result')
    parser.add_argument('--baseline-older', type=Path, metavar='REGISTRY_DIR', action='append', default=[],
                        help='an earlier version of the Baseline registry (kept by a Baseline update): runs compared with it stay readable')
    parser.add_argument('--history-run', type=Path, metavar='RUN_DIR', action='append', default=[],
                        help='Earlier saved run of a shown page (read-only, repeatable): adds monitoring history only, no images')
    parser.add_argument('--schedule', type=Path, metavar='FILE',
                        help='Schedule state written by a monitor provider / runner (siteproof.schedule-state.v1 list). Read-only; '
                             'without it every channel is shown as 予定・未稼働. Nothing is scheduled or run by this export')
    parser.add_argument('--now', help='Fixed UTC time for an offline simulation (e.g. 2026-11-22T00:00:00Z)')
    parser.add_argument('--targets', type=Path, help="your site's targets.json (default: the author's pages)")
    parser.add_argument('--capture-plan', type=Path, help="your site's capture_plan.json (default: the author's plan)")
    args = parser.parse_args()
    if args.targets:
        os.environ['SITEPROOF_TARGETS'] = str(args.targets.resolve())
    if args.capture_plan:
        os.environ['SITEPROOF_CAPTURE_PLAN'] = str(args.capture_plan.resolve())
    if args.history_run and not args.local_capture:
        parser.error('--history-run needs --local-capture')
    if args.baseline_older and not args.baseline_registry:
        parser.error('--baseline-older needs --baseline-registry')
    if (args.baseline_registry or args.offline_demo) and not args.local_capture or args.offline_demo and not args.baseline_registry:
        parser.error('--baseline-registry needs --local-capture; --offline-demo needs --baseline-registry')
    if args.local_capture and (args.sample or args.aws_b_input or args.refresh_config or args.refresh or args.assets):
        parser.error('--local-capture can only be combined with --snapshot or --archive')
    if args.aws_read and not args.refresh_config:
        parser.error('--aws-read is valid only with --refresh-config')
    if args.refresh_config or args.refresh:
        if args.assets or args.refresh_config and args.refresh or args.refresh and not args.aws_b_input:
            parser.error('refresh requires one explicit source and no image regeneration')
        if args.refresh_config and not args.aws_read:
            parser.error('--refresh-config requires --aws-read and separate AWS read approval')
        from .refresh import update, load_config, cli_stores, report_failure
        try:
            if args.refresh_config:
                config = load_config(args.refresh_config)
                result = update(args.out, stores=cli_stores(config), interval_seconds=config['interval_seconds'], trial=config.get('trial'))
            else:
                result = update(args.out, export_directory=args.aws_b_input)
        except Exception as exc:
            try:
                report_failure(args.out)
            except Exception:
                pass  # Never steal a concurrent lock or overwrite an unowned directory.
            print('REFRESH_FAILED / current state UNKNOWN / ' + type(exc).__name__)
            raise SystemExit(1)
        print(result['entry'])
        print(result['status'] + ' / read-only snapshot; no monitoring started')
        if result['status'] != 'OK':
            raise SystemExit(1)
        return
    now = datetime.now(timezone.utc)
    if args.now:
        from src.aws_b.model import parse_utc
        now = parse_utc(args.now)
        if now is None:
            parser.error('--now must be a UTC time like 2026-11-22T00:00:00Z')
    snapshot, assets = empty_snapshot(), args.assets
    if args.snapshot:
        if args.snapshot.stat().st_size > 4*1024*1024:
            parser.error('snapshot too large')
        snapshot = json.loads(args.snapshot.read_text('utf-8'))
    if args.aws_b_input:
        from .aws_b_data import read_export
        snapshot = read_export(args.aws_b_input)
    if args.sample:
        from .sample import make_sample
        # A separate sibling directory is new-only; existing evidence is never replaced.
        assets = Path(args.out).with_name(Path(args.out).name + '-sample-assets')
        snapshot = make_sample(assets, now)
    archive_extra = None
    if args.archive:
        # The existing archive reader, evaluated at `now`: an old PASS becomes STALE, never "up". The banner shows the archive's own
        # acquisition time, not this export's time. The fixture trial target stays in its separate block (home_extra).
        from .archive import Archive
        from .product import settings
        archive = Archive(args.archive)
        problems = archive.verify()
        if problems:
            parser.error('archive refused: ' + '; '.join(problems)[:300])
        pages = settings()['pages']
        snapshot = archive.home_snapshot(pages, now=now)
        snapshot['http_export']['fetched_at'] = archive.fetched_at()
        archive_extra = archive.home_extra({p['target_id'] for p in pages})
    if args.schedule:
        if args.schedule.stat().st_size > 1024 * 1024:
            parser.error('schedule file too large')
        schedule = json.loads(args.schedule.read_text('utf-8'))
        from .monitoring import schedule_record
        try:
            snapshot = {**snapshot, 'schedule': [schedule_record(r) for r in schedule]}
        except (TypeError, ValueError) as exc:
            parser.error('schedule refused: ' + str(exc))
    if args.local_capture:
        from .local_capture import LocalCaptureRefused, attach
        try:
            registry = None
            if args.baseline_registry:
                from .baseline_registry import read as read_registry
                registry = read_registry(args.baseline_registry)
                from .baseline_registry import standing
                from .baseline_registry import valid_formal
                registry = {**registry, 'standing': standing(args.baseline_registry, registry),
                            'formal_approval': valid_formal(args.baseline_registry, registry['baselines'])}
            older = [read_registry(d) for d in args.baseline_older] if args.baseline_older else []
            snapshot, pngs = attach(snapshot, args.local_capture, registry, args.history_run, older=older)
            if registry:
                from .baseline_registry import attach as attach_registry, is_source_shown, public
                if is_source_shown(snapshot, registry):  # approved, nothing captured or compared since
                    snapshot, pngs = attach_registry(snapshot, pngs, registry, args.offline_demo)
                elif args.offline_demo:
                    parser.error('--offline-demo belongs to the registry source run, which is not shown')
                elif registry['page_id'] in snapshot['changes']:  # a later run compared with it: keep the record for DETAIL
                    page = snapshot['changes'][registry['page_id']]
                    snapshot = {**snapshot, 'changes': {**snapshot['changes'], registry['page_id']: {**page, 'baseline_registry': public(registry)}}}
        except (LocalCaptureRefused, KeyError, ValueError, OSError) as exc:
            parser.error('capture run refused: ' + type(exc).__name__ + ': ' + str(exc)[:200])
        # The PNGs are copied out of the run into a throw-away staging directory; build() re-verifies every digest and copies them again.
        with tempfile.TemporaryDirectory(prefix='siteproof-capture-') as staging:
            for tid, roles in pngs.items():
                (Path(staging) / tid).mkdir()
                for role, raw in roles.items():
                    (Path(staging) / tid / (role + '.png')).write_bytes(raw)
            view = build(args.out, snapshot, now=now, assets=staging, archive=archive_extra)
        print(str(Path(args.out).resolve() / 'review.html'))
    else:
        view = build(args.out, snapshot, now=now, assets=assets, archive=archive_extra)
    print(str(Path(args.out).resolve() / 'index.html'))
    print(view['source'] + ' / offline export only / no AWS or network')


if __name__ == '__main__':
    main()
