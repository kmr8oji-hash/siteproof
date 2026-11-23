"""Real-site capture for the registered site: the existing harness tests/runtime/validate_s3t.py behind a SIGNED monitoring permit.

The app never captures a real site by itself. RealCapture.capture() runs only when ALL of readiness() hold:
  1. owner        the signed permit records an ownership check (method + time; CLOUDFLARE_ACCOUNT_CONTROL also matches the host and the
                  pinned evidence file, permit.cloudflare_ownership_problems); the self-declaration at registration is not enough
  2. permission   <site>/real/permit.json is validly signed (src/noxiworks/permit.py: OpenSSH `ssh-keygen -Y verify` against the USER's
                  <data>/trust/allowed_signers) and covers this site, page, host, the hash-pinned targets.json / capture_plan.json of
                  the site, this moment (valid_from..valid_until) and one more run (max_runs; the harness counts runs in <data>/trust/permit-ledger)
  3. identity     the permit's identity pins (harness, Worker, broker, reaper, network rules, target files ...) equal the current files,
                  an image ID is pinned; after the Baseline: the permit allows comparing (AUTO_INITIAL_THEN_COMPARE) and the Baseline
                  was created under this same permit
  4. environment  the Docker CLI and ssh-keygen exist (the harness checks the image, owns every container; this module starts none)
  5. harness      the page is a top page `/` (the harness Worker and the broker accept nothing else)
Then it runs the harness in a separate process with --permit / --trust / --target-dir, the --expect derived from the signed identity
(permit.derive_expect: + the Baseline pins in compare mode, nothing else), SITEPROOF_* overrides removed. The harness re-verifies the
signature, the target files and the derived --expect before any container starts; DNS-resolved single IPv4:443 grant, broker / proxy
egress, redirect refusal, connect / browser audits, TTL windows and the reaper stay inside the harness unchanged. The result is accepted
only if local_capture.load verifies it, it passed, and it is not labelled synthetic. Real runs live apart from anything synthetic.
The app holds no private key and has no code path that signs: it cannot issue a permit.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

from src.aws_b.model import format_utc
from src.noxiworks import permit as permits

ROOT = Path(__file__).resolve().parents[2]
HARNESS = 'tests/runtime/validate_s3t.py'
HARNESS_MODULE = 'tests.runtime.validate_s3t'  # run as a module from ROOT: as a script, `src` is not importable
HARNESS_TIMEOUT = 3600
_ENGINE = {'at': 0.0, 'ok': False}  # docker info, cached briefly: the HOME page asks for readiness often


def docker_engine_answers(max_age=60):
    """True if the Docker engine answers (Docker Desktop running), not merely the CLI being installed. A run started without it
    fails inside the harness and still counts against the permit, so this is checked before."""
    if time.monotonic() - _ENGINE['at'] > max_age:
        try:
            ok = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        _ENGINE.update(at=time.monotonic(), ok=ok)
    return _ENGINE['ok']
# The identity must pin at least these (the harness, its Workers, the network controls, the shared permit verifier and the code that
# reads the target files): what decides WHERE a run may connect can never change between signing and capture.
REQUIRED_PINS = ('tests/runtime/validate_s3t.py', 'tests/runtime/s3t_worker.py', 'tests/runtime/s3_worker.py', 'tests/runtime/egress_broker.py',
                 'tests/runtime/egress_reaper.py', 'tests/runtime/netpolicy_hardened.py', 'src/noxiworks/permit.py', 'src/noxiworks/product.py')


class BaselineSwitchIncomplete(ValueError):
    """A Baseline update was approved but its switch did not finish. Not a failure to approve and not a success: nothing was lost, the new
    Baseline is kept with its intent, and retrying only completes the switch."""


class RealCaptureRefused(ValueError):
    pass


CAPTURE_REASONS = {'HTTP_TIMEOUT': 'ページへの接続が時間切れになりました', 'LOAD_TIMEOUT': 'ページの読み込みが時間切れになりました',
                   'CAPTURE_TIMEOUT': '画面の撮影が時間切れになりました', 'BROWSER_START_TIMEOUT': 'ブラウザの起動が時間切れになりました',
                   'HTTP_FAILED': 'ページへの接続に失敗しました', 'LOAD_FAILED': 'ページの読み込みに失敗しました',
                   'CAPTURE_FAILED': '画面の撮影に失敗しました'}


def failure_cause(evidence):
    """A plain-language cause from the harness's own record of a run that did not succeed (never invented: only what it recorded), or None."""
    try:
        report = json.loads((Path(evidence) / 'validation-result.json').read_text('utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(report, dict):
        return None
    if report.get('gate_failed'):
        return '安全確認で停止しました（' + str(report['gate_failed'])[:100] + '）'
    for kind, capture in (report.get('captures') or {}).items():
        if isinstance(capture, dict) and capture.get('execution') not in (None, 'COMPLETED'):
            reason = str(capture.get('reason') or capture.get('execution'))
            return (f'{kind}の撮影が完了しませんでした：{CAPTURE_REASONS.get(reason, "撮影が完了しませんでした")}（{reason}）。'
                    'サイトの応答の遅れなど一時的な原因の可能性があります（原因の詳細は証拠に記録されています）。許可の回数は1回使用済みです')
    if report.get('error_type'):
        return '撮影ハーネスでエラーが起きました（' + str(report['error_type']) + '）'
    failed = [k for k, v in (report.get('checks') or {}).items() if v is not True]
    return ('確認項目が成立しませんでした（' + '、'.join(failed[:3]) + ('…' if len(failed) > 3 else '') + '）') if failed else None


def harness_target():
    """The page the harness captured under the legacy, unsigned TTN exception (SP-D52 / SP-D54); kept so that site keeps its page id."""
    from src.noxiworks.product import CONFIG, settings
    page = next((p for p in settings(CONFIG)['pages'] if p['target_id'] == 'ttn-home'), None)
    return {'target_id': 'ttn-home', 'url': page['url']} if page else None


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RealCapture:
    def __init__(self, site, docker_found=None, runner=None):
        self.site = site
        self.dir = site.root / 'real'
        self.trust = site.root.parents[1] / 'trust' / 'allowed_signers'  # <data>/trust: placed by the USER, never written by the app
        self.docker_found = docker_found  # tests inject True/False; None (the real app) = decided lazily by _engine()
        self.runner = runner or self._subprocess

    # ---- the signed permit
    def permit(self):
        """-> (permit or None, error or None). Only a validly signed permit is ever returned."""
        try:
            return permits.verify_signature(self.dir / 'permit.json', self.trust), None
        except permits.PermitRefused as exc:
            return None, str(exc)

    def used(self, permit):
        """Runs counted against this permit in the shared ledger the harness writes (permit.reserve_run); the app only reads it."""
        try:
            return permits.used_runs(self.trust, permit.get('permit_id'))
        except permits.PermitRefused:
            return 10 ** 9  # an unusable permit id counts as exhausted

    def registry_pins(self):
        from src.noxiworks.baseline_runtime import expected_baseline, read_registry
        registry = self.site.real_registry()
        if registry is None:
            return None
        return {**expected_baseline(read_registry(registry)), 'registry_export_sha256': sha(registry / 'export-sha256.json')}

    # ---- Baseline update: the USER approves the new capture of a CHANGED inspection as the next Baseline version
    def baseline_update_state(self):
        """What the screens may offer, read back from disk (cheap: no registry re-hash here; build() re-verifies everything).
        state NONE (nothing to decide) | AVAILABLE (the newest inspection changed and can become the Baseline) | BLOCKED (changed or
        undecided but not approvable; `reason` says why). It never decides anything and never changes a file."""
        from src.noxiworks.baseline_update import check_updatable, pending, pending_reason
        registry, runs = self.site.real_registry(), self.site.real_runs()  # real_registry() tries to finish an interrupted switch first
        if pending(self.dir):
            return {'state': 'SWITCH_PENDING', 'run_id': runs[-1].name if runs else '',
                    'versions': ({b['kind']: b['version'] for b in json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))['baselines']}
                                 if registry is not None else {}),
                    'reason': 'Baselineの切替が未完了です。新しいBaselineは保全されています。「切替を完了する」で再試行してください'
                              + (f'（理由：{pending_reason(self.dir)}）' if pending_reason(self.dir) else '')}
        if registry is None or not runs:
            return {'state': 'NONE'}
        try:
            record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
            run = runs[-1]
            if run.name == record['source_run']['run_id']:
                return {'state': 'NONE'}  # the newest inspection is the one the current Baseline was made from
            summary = self.site.summary(run)
            if not summary['compared']:
                return {'state': 'NONE'}
            verdicts = {p['verdict'] for p in summary['profiles'].values()}
            if verdicts == {'NO_VISUAL_CHANGE_DETECTED'}:
                return {'state': 'NONE'}
            current = {b['kind']: b['version'] for b in record['baselines']}
            compared_with = {}
            for kind in summary['profiles']:
                result = json.loads((run / f'{kind}-run-result.json').read_text('utf-8'))
                comp = next(r for r in result['comparison']['results'] if r.get('job_id') == summary['profiles'][kind]['job_id'])
                compared_with[kind] = (comp.get('baseline') or {}).get('version')
            reason = check_updatable(summary)
            if reason is None and compared_with != current:
                reason = 'この検査の後にBaselineが変わっています。もう一度検査してください'
            return {'state': 'BLOCKED' if reason else 'AVAILABLE', 'reason': reason, 'run_id': run.name, 'versions': current,
                    'profiles': {k: {f: p.get(f) for f in ('verdict', 'changed_pixels', 'image_label', 'stability')} for k, p in summary['profiles'].items()}}
        except (OSError, ValueError, KeyError, StopIteration):
            return {'state': 'BLOCKED', 'reason': 'この検査の記録を読み取れません'}

    def update_baseline(self, run_id, expected_versions, now, actor):
        """Approve the newest inspection's captures as the next Baseline version. Caller holds the monitor lock (no inspection runs).
        Nothing changes unless every check passes: the new registry is built beside the current one, proven to be pinned by the next
        capture exactly like the current one, and only then does it take its place (the current one stays as history)."""
        import tempfile
        from tools.register_baseline import Stop
        from src.noxiworks import baseline_update
        from src.noxiworks.baseline_runtime import check_bindings, open_runtime, read_registry, stage
        if baseline_update.pending(self.dir):
            # a switch that was started is finished (or refused with its reason) before anything else: the same approval is never made twice
            status, reason = baseline_update.finish_switch(self.dir, retry=True)
            if status != 'DONE':
                raise BaselineSwitchIncomplete('Baselineの切替が未完了です。新しいBaselineは保全されています。時間をおいて再試行してください'
                                               + (f'（理由：{reason}）' if reason else ''))
            registry = self.site.real_registry()
            return {**json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8')), 'recovered': True}
        state = self.baseline_update_state()
        if state['state'] != 'AVAILABLE':
            raise RealCaptureRefused(state.get('reason') or '承認できる検査結果がありません')
        if state['run_id'] != run_id:
            raise RealCaptureRefused('承認できるのは最新の検査だけです。画面を更新してください')
        if expected_versions != state['versions']:
            raise RealCaptureRefused('画面に表示したBaselineの版が現在の版と一致しません（別の更新が済んでいます）。画面を更新してください')
        registry = self.site.real_registry()
        run = self.dir / 'runs' / run_id / run_id
        plan = json.loads((self.site.root / 'capture_plan.json').read_text('utf-8'))
        profiles = next(pg for s in plan['sites'] for pg in s['pages'] if pg['page_id'] == self.site.page_id)['profiles']
        new_dir = self.dir / ('.tmp-registry-update-' + run_id)
        shutil.rmtree(new_dir, ignore_errors=True)  # an earlier attempt that never started a switch (no intent exists: checked above)

        def discard():
            if not baseline_update.pending(self.dir):  # an intent names this folder: it is the new Baseline, never removed
                shutil.rmtree(new_dir, ignore_errors=True)
        try:
            record = baseline_update.build(run, registry, new_dir, actor, '撮影画像と差分を確認し、画面の「新しい基準にする」でUSERが正式に承認',
                                           profiles, self.site.summary(run), now)
            # the same proof every capture needs: the next job pins exactly this registry's head of each profile
            with tempfile.TemporaryDirectory(prefix='siteproof-verify-', ignore_cleanup_errors=True) as tmp:
                workspace = Path(tmp) / 'ws'
                stage(new_dir, workspace)
                check_bindings(open_runtime(workspace), read_registry(new_dir), profiles)
            permit, _ = self.permit()
            old_origin = self._registry_origin()
            origin = {'origin': 'USER_UPDATE', 'permit_id': (permit or {}).get('permit_id') or old_origin.get('permit_id'),
                      'created_at': format_utc(now), 'registry_export_sha256': baseline_update.export_hash(new_dir),
                      'versions': {b['kind']: b['version'] for b in record['baselines']}, 'update_of_run': run_id,
                      'previous_registry_export_sha256': old_origin.get('registry_export_sha256')}
            baseline_update.switch(self.dir, new_dir, origin)
        except baseline_update.SwitchIncomplete as exc:
            raise BaselineSwitchIncomplete('Baselineの切替が未完了です。新しいBaselineは保全されています。画面の「切替を完了する」で再試行してください'
                                           + (f'（理由：{exc.reason}）' if exc.reason else '')) from None
        except Stop as exc:
            discard()
            raise RealCaptureRefused('Baselineを更新できませんでした（現在のBaselineはそのままです）：' + str(exc)) from None
        except Exception:
            discard()
            raise
        return record

    def approve_baseline(self, expected, now, actor):
        """The USER formally approves the Baseline that is current (version unchanged). Caller holds the monitor lock.
        Refuses unless the registry is intact (every file equals its export hash), the next job would pin exactly it, and what the USER saw is
        what is current. Writes one record next to the registry; permit, ledger, registry, images and evidence are not touched."""
        import tempfile
        from tools.register_baseline import Stop
        from src.noxiworks import baseline_update
        from src.noxiworks.baseline_runtime import check_bindings, open_runtime, read_registry, stage
        registry = self.site.real_registry()
        if registry is None or baseline_update.pending(self.dir):
            raise RealCaptureRefused('正式承認できるBaselineがありません（切替が未完了の場合は、先に切替を完了してください）')
        try:
            record = read_registry(registry)  # manifest-checked: a registry that differs from its hashes is refused here
            plan = json.loads((self.site.root / 'capture_plan.json').read_text('utf-8'))
            profiles = next(pg for s in plan['sites'] for pg in s['pages'] if pg['page_id'] == self.site.page_id)['profiles']
            with tempfile.TemporaryDirectory(prefix='siteproof-verify-', ignore_cleanup_errors=True) as tmp:
                workspace = Path(tmp) / 'ws'
                stage(registry, workspace)
                check_bindings(open_runtime(workspace), record, profiles)
            return baseline_update.approve_current(self.dir, record, expected, actor, now)
        except Stop as exc:
            raise RealCaptureRefused('正式承認できませんでした（Baselineはそのままです）：' + str(exc)) from None
        except ValueError as exc:
            if isinstance(exc, RealCaptureRefused):
                raise
            raise RealCaptureRefused('正式承認できませんでした（Baselineの証拠が記録と一致しません）：' + str(exc)[:200]) from None

    def path_problem(self):
        """A message when this site's data folder is too deep for the Browser bundle's bind mount (Windows), else None. Pure path arithmetic."""
        from tests.runtime.browser_bundle import staged_path_problem
        sample = '00000000T000000Z-00-real'  # the run id format (fixed length)
        return staged_path_problem(ROOT, self.dir / 'runs' / ('.tmp-' + sample) / sample)

    def _engine(self, gates_ok):
        """True / False, or None = not asked. The Docker engine is queried (`docker info`) only once every other gate holds, i.e. after
        the USER has signed a permit for this site; registering a site or opening a page never touches Docker."""
        if self.docker_found is not None:
            return self.docker_found
        if shutil.which('docker') is None:
            return False
        return docker_engine_answers() if gates_ok else None

    def readiness(self, now):
        info = self.site.info
        permit, error = self.permit()
        scope = permits.check_scope(permit, site_info=info, page_id=self.site.page_id, target_dir=self.site.root, now=now,
                                    used_runs=self.used(permit)) if permit else [error]
        checks = []
        own = (permit or {}).get('ownership') or {}
        own_problems = [p for p in scope if p.startswith('所有権')]  # CLOUDFLARE_ACCOUNT_CONTROL: also the host + evidence match
        own_ok = bool(permit) and not own_problems
        checks.append({'key': 'owner', 'label': '本人管理サイトの確認', 'ok': own_ok,
                       'state': (f"確認済み（{own['method']}・{own['verified_at']}・署名付き許可に記録）" if own_ok
                                 else '未確認：' + '、'.join(own_problems) if permit and own.get('method') else '未確認（自己申告のみ）'),
                       'guide': 'サイト登録時の「自分が管理するサイト」の確認だけでは撮影しません。下の「初回セットアップ」で所有権を確認します'
                                '（workers.devのサイトはCloudflareのアカウントで自動確認、それ以外は確認用ファイルかDNSのTXTレコード）。'})
        scope_only = [p for p in scope if not p.startswith(('所有権', '撮影構成'))]
        checks.append({'key': 'permission', 'label': '監視許可（署名付き：対象・期間・回数）', 'ok': bool(permit) and not scope_only,
                       'state': (f"有効（{permit['permit_id']}・{permit['valid_until']}まで・残り{permit['max_runs'] - self.used(permit)}回）"
                                 if permit and not scope_only else '無効：' + '、'.join(scope_only)),
                       'guide': '撮影してよい対象・期間・回数を書いた監視許可に、あなたの鍵で署名したものが必要です。「初回セットアップ」（期限が近いときは「監視設定を更新」）で作成・署名します。'
                                'SiteProofは許可を発行できず、確認するだけです。'})
        id_problems = self._identity_problems(permit) if permit else ['署名付きの監視許可がありません']
        checks.append({'key': 'identity', 'label': '撮影構成の同一性（署名時の構成と一致）', 'ok': not id_problems,
                       'state': '一致' if not id_problems else '未確認：' + '、'.join(id_problems),
                       'guide': '署名したときの撮影の仕組み（プログラムと撮影環境）が、今も同じであることを毎回確認します。SiteProofを更新した後は「監視設定を更新」で署名し直してください。'})
        tool = permits.ssh_keygen() is not None
        path_problem = self.path_problem()
        top = urlsplit(info['url']).path == '/'
        engine = self._engine(all(c['ok'] for c in checks) and not id_problems and top)
        checks.append({'key': 'environment', 'label': '撮影環境（Docker・署名検証）', 'ok': bool(engine) and tool,
                       'state': ('Docker CLI・ssh-keygen あり（撮影イメージの照合と隔離の確認は撮影ハーネスが起動前に行います）' if engine and tool
                                 else 'Dockerの確認は、署名付き許可など他の条件が整ってから行います（現在は確認していません）' if engine is None and tool
                                 else '・'.join(x for x, ok in (('Docker Desktopが起動していません（Dockerのエンジンが応答しません）', engine is not False),
                                                                ('ssh-keygenが見つかりません', tool)) if not ok)),
                       'guide': 'Docker Desktop が起動している必要があります。止まっているときは「Docker Desktopを起動」を押してください。'})
        checks.append({'key': 'harness', 'label': '実撮影ハーネスの対応', 'ok': top and not path_problem,
                       'state': (path_problem or '対応（署名付き許可の対象を撮影）') if top else 'トップページ（/）以外は未対応',
                       'guide': 'SiteProofが撮影するのは、登録したサイトのトップページ（/）だけです。'})
        return checks

    def _identity_problems(self, permit):
        problems = []
        files = (permit.get('identity') or {}).get('files') or {}
        if not set(REQUIRED_PINS) <= set(files):
            problems.append('撮影ハーネス・通信制御・許可検証のファイルを固定していません')
        if any(not (ROOT / rel).is_file() or sha(ROOT / rel) != digest for rel, digest in files.items()):
            problems.append('固定したファイルが現在のファイルと一致しません')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', str((permit.get('identity') or {}).get('image_id', ''))):
            problems.append('撮影イメージIDが固定されていません')
        from src.noxiworks.baseline_update import pending
        if pending(self.dir):
            problems.append('Baselineの更新の切替が未完了です（新しいBaselineは保全されています。画面の「切替を完了する」で再試行してください）')
        if self.site.real_registry() is not None:
            origin = self._registry_origin()
            if permit.get('baseline_policy') != 'AUTO_INITIAL_THEN_COMPARE':
                problems.append('この許可はBaselineとの比較を含みません')
            elif origin.get('permit_id') != permit.get('permit_id') and not self._carried_over(permit, origin):
                problems.append('Baselineが別の監視許可で作成されています（新しい許可に、そのBaselineを引き継ぐ署名付きの記録がありません）')
            elif origin.get('registry_export_sha256') != sha(self.site.real_registry() / 'export-sha256.json'):
                problems.append('Baselineが作成時の内容と一致しません')
        elif permit.get('baseline_policy') == 'NONE':
            problems.append('この許可はBaselineの作成を含みません')
        return problems

    @staticmethod
    def _carried_over(permit, origin):
        """A renewal names the Baseline it adopts (permit id + registry hash) under the USER's signature (tools/setup_monitoring.py)."""
        carried = permit.get('baseline_carryover') or {}
        return (carried.get('permit_id') == origin.get('permit_id') is not None
                and carried.get('registry_export_sha256') == origin.get('registry_export_sha256') is not None)

    def _registry_origin(self):
        f = self.dir / 'registry-origin.json'
        return json.loads(f.read_text('utf-8')) if f.is_file() else {}

    def ready(self, now):
        return all(c['ok'] for c in self.readiness(now))

    # ---- one real capture through the harness
    @staticmethod
    def _subprocess(args, env):
        log = Path(args[args.index('--evidence') + 1]).parent / 'harness-output.log'  # kept with the run (also when it fails)
        with open(log, 'wb') as out:
            return subprocess.run(args, cwd=ROOT, env=env, timeout=HARNESS_TIMEOUT, stdout=out, stderr=subprocess.STDOUT).returncode

    def capture(self, now):
        from src.noxiworks.local_capture import LocalCaptureRefused, load
        from src.noxiworks.baseline_registry import read as read_registry
        checks = self.readiness(now)
        missing = [c['label'] + '：' + c['state'] for c in checks if not c['ok']]
        if missing:
            raise RealCaptureRefused('実サイト撮影の条件が整っていません：' + ' ／ '.join(missing))
        permit, _ = self.permit()
        registry = self.site.real_registry()
        expect = permits.derive_expect(permit, self.registry_pins() if registry is not None else None)
        runs = self.dir / 'runs'
        runs.mkdir(parents=True, exist_ok=True)
        run_id = f'{now:%Y%m%dT%H%M%SZ}-{len(list(runs.iterdir())) % 100:02d}-real'
        tmp = runs / ('.tmp-' + run_id)
        tmp.mkdir()
        (tmp / 'expect.json').write_text(json.dumps(expect, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        evidence = tmp / run_id  # the harness creates it (mkdir exist_ok=False) and writes the S3-1T export into it
        args = [sys.executable, '-B', '-m', HARNESS_MODULE, '--evidence', str(evidence), '--expect', str(tmp / 'expect.json'),
                '--permit', str(self.dir / 'permit.json'), '--trust', str(self.trust), '--target-dir', str(self.site.root)]
        if registry is not None:
            args += ['--baseline-registry', str(registry)]
        env = {k: v for k, v in os.environ.items() if not k.startswith('SITEPROOF_')}
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        code = self.runner(args, env)  # the harness counts the run in the permit ledger before any container (fail-closed)
        try:
            if code != 0 or not (evidence / 'validation-result.json').is_file():
                raise RealCaptureRefused(f'撮影ハーネスが完了しませんでした（終了コード {code}）。記録は {run_id}-failed に残しています')
            report = json.loads((evidence / 'validation-result.json').read_text('utf-8'))
            if report.get('synthetic') is True or report.get('passed') is not True:
                cause = None if report.get('synthetic') is True else failure_cause(evidence)
                raise RealCaptureRefused((cause + '。' if cause else '') + '撮影ハーネスの結果が「成功した実撮影」ではありません（合成データ・未完了は受け取りません）')
            created = json.loads((evidence / 'workspace-created.json').read_text('utf-8'))
            if created.get('url') != self.site.info['url'] or created.get('page_id') != self.site.page_id:
                raise RealCaptureRefused('撮影されたページが登録したページと一致しません')
            env_targets = {'SITEPROOF_TARGETS': str(self.site.root / 'targets.json'), 'SITEPROOF_CAPTURE_PLAN': str(self.site.root / 'capture_plan.json')}
            saved = {k: os.environ.get(k) for k in env_targets}
            os.environ.update(env_targets)  # the loader checks the run against THIS site's targets (as the pages are generated)
            try:
                load(evidence, read_registry(registry) if registry is not None and report.get('baseline_compared') else None)
            except LocalCaptureRefused as exc:
                raise RealCaptureRefused('撮影結果の検証に失敗しました：' + str(exc)[:200]) from None
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        except RealCaptureRefused:
            tmp.rename(runs / (run_id + '-failed'))  # kept as evidence, never shown, never deleted
            raise
        tmp.rename(runs / run_id)
        return self.site.summary(runs / run_id / run_id)

    def create_baseline(self, summary, now, actor):
        """The first real Baseline from the first stable real capture under this permit, through tools/register_baseline.register."""
        from tools.register_baseline import Stop, register
        permit, error = self.permit()
        if permit is None or permit.get('baseline_policy') != 'AUTO_INITIAL_THEN_COMPARE':
            raise RealCaptureRefused('監視許可がBaselineの自動作成を含みません')
        if self.site.real_registry() is not None or (self.dir / 'registry-history').exists() or (self.dir / 'baseline-switch.json').exists():
            raise RealCaptureRefused('実撮影のBaselineはすでにあります')  # also while a Baseline update is unfinished: never start a second line
        run = self.dir / 'runs' / summary['run_id'] / summary['run_id']
        approvals = []
        for kind, p in summary['profiles'].items():
            result = json.loads((run / f'{kind}-run-result.json').read_text('utf-8'))
            approvals.append((kind, p['candidate'], result['state']['jobs'][0]['evidence']['digest']))
        plan = json.loads((self.site.root / 'capture_plan.json').read_text('utf-8'))
        profiles = next(pg for s in plan['sites'] for pg in s['pages'] if pg['page_id'] == self.site.page_id)['profiles']
        try:
            record = register(run, self.dir / 'registry', approvals, actor,
                              f"監視許可 {permit['permit_id']} の範囲内で、初回の安定した実撮影（{'・'.join(summary['profiles'])}完了・STABLE）から自動作成。利用者は未確認",
                              page_id=self.site.page_id, profiles=profiles)
        except Stop as exc:
            raise RealCaptureRefused('実撮影のBaselineを作成できませんでした：' + str(exc)) from None
        (self.dir / 'registry-origin.json').write_text(json.dumps({'origin': 'AUTO_INITIAL', 'permit_id': permit['permit_id'], 'created_at': format_utc(now),
                                                                   'registry_export_sha256': sha(self.dir / 'registry' / 'export-sha256.json')}) + '\n', encoding='utf-8')
        return record
