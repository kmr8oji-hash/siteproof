"""One user-registered site in the local app: register -> capture -> human Baseline approval -> later captures compared.

Everything goes through the existing product pieces: capture.create_runtime (workspace, site, page, Desktop/Mobile profiles),
baseline_runtime.prepare_job / open_runtime (each job bound to the approved Baseline of its profile, if any), RuntimeService.run
(S1 evidence), ComparisonService, SQLiteBaselineStore.decide (one-shot APPROVED). Each capture is saved as a run directory in the
S3-1T export shape and the approval as a registry in the tools/register_baseline.py shape, so the unchanged static pages
(local_capture / baseline_registry) verify and show them.

Capture mode in MVP v1.0 is OFFLINE FIXTURE only: the capture step is the offline stand-in (tools/offline_baseline_demo) that hands
back a synthetic page image; no browser starts and nothing connects to the site. Every run says synthetic: true, so the pages show
it as 合成デモ. Real capture needs an ownership check, an approved egress grant and the pinned capture environment
(docs/REAL_CAPTURE.md); readiness() reports each of them and real capture stays disabled until all are met (not implemented).
Several pages: Site works on any unit folder (a site's first page is the site folder, a further page <site>/pages/<site id>-p2..p5); register_page() adds
one. A unit shares nothing with another (see src/noxiworks/sites.py).
approve() makes the newest capture Baseline v1. It is called by site_monitor for the first inspection whose Desktop and Mobile
captures completed and were STABLE (origin AUTO_INITIAL, shown as "自動作成（未確認）" until the user confirms it, which is a
separate record), or with origin USER for a person's approval. A detected change never calls it; replacing a Baseline is not
implemented.
"""
from datetime import timedelta
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

from src.aws_b.model import format_utc
from src.baseline.model import BaselineStatus
from src.comparison import preview
from src.comparison.operational import present
from src.comparison.service import MAX_PIXELS
from src.noxiworks import sites
from src.runtime.stability import policy

PROFILES = {'Desktop': {'kind': 'Desktop', 'width': 1440, 'height': 900, 'full_page': True},
            'Mobile': {'kind': 'Mobile', 'width': 390, 'height': 844, 'full_page': True}}
IMAGE_HEIGHTS = {'Desktop': 1200, 'Mobile': 1400}  # the synthetic "full page" is taller than the viewport
STABILITY = {'settle_ms': 500, 'interval_ms': 400, 'required_identical': 3, 'min_span_ms': 800, 'max_attempts': 8, 'max_total_ms': 15000}  # a tall page's full-page shot takes ~1 s
FIXTURES = {'same': '同じ画面（初回・変更なし）', 'changed': '変更あり（画面上部に赤い帯）', 'unstable': '撮影が不安定（撮影ごとに画像が変わる）'}
ACTOR = 'ローカル利用者（SiteProofアプリの画面で承認）'
RUN_ID = re.compile(r'^\d{8}T\d{6}Z-\d{2}-(same|changed|unstable)$')
BLOCKED_HOSTS = ('localhost', '.localhost', '.local', '.internal', '.lan', '.home', '.invalid', '.test', '.example')


class SiteRefused(ValueError):
    pass


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


def check_input(name, url, kinds):
    """-> (name, origin, page url, path, kinds). Only a public https page of a named host; one page per site."""
    name = (name or '').strip()
    if not 1 <= len(name) <= 60 or any(ord(c) < 32 for c in name):
        raise SiteRefused('サイト名は1〜60文字で入力してください')
    u = urlsplit((url or '').strip())
    host = (u.hostname or '').lower()
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if (u.scheme != 'https' or not host or u.username or u.password or u.query or u.fragment or literal or '.' not in host
            or host.endswith(BLOCKED_HOSTS) or host in BLOCKED_HOSTS):
        raise SiteRefused('URLは https:// で始まる公開サイトのページを入力してください（IPアドレス・localhost・ログイン情報・?や#は使えません）')
    try:
        port = u.port
    except ValueError:
        port = -1
    if port not in (None, 443):
        raise SiteRefused('ポート番号つきのURLは使えません')
    path = u.path or '/'
    if not path.startswith('/') or path.startswith('//') or len(path) > 200 or not re.fullmatch(r"[A-Za-z0-9/._~%!$&'()*+,;=:@-]*", path):
        raise SiteRefused('ページのパスに使えない文字があります')
    kinds = [k for k in ('Desktop', 'Mobile') if k in set(kinds or [])]
    if not kinds:
        raise SiteRefused('Desktop と Mobile の少なくとも1つを選んでください')
    origin = f'https://{host}'
    return name, origin, origin + path, path, kinds


def page_image(width, height, accent):
    """A plain synthetic web page (flat colours) standing in for a capture of the site: obviously not the real site."""
    px = bytearray(b'\xf4\xf6\xfa\xff' * (width * height))

    def rect(x0, y0, x1, y1, rgba):
        x0, x1 = max(0, x0), min(width, x1)
        for y in range(max(0, y0), min(height, y1)):
            px[(y * width + x0) * 4:(y * width + x1) * 4] = bytes(rgba) * (x1 - x0)

    m = max(12, width // 40)
    rect(0, 0, width, 64, accent)
    rect(m, 20, m + width // 6, 44, (236, 240, 248, 255))
    rect(m, 96, width - m, 96 + height // 5, (210, 224, 244, 255))
    cols = 3 if width >= 800 else 1
    card = (width - m * (cols + 1)) // cols
    y = 96 + height // 5 + m
    while y + 180 < height - 96:
        for c in range(cols):
            x = m + c * (card + m)
            rect(x, y, x + card, y + 160, (255, 255, 255, 255))
            rect(x + 16, y + 20, x + card // 2, y + 36, (120, 136, 160, 255))
            rect(x + 16, y + 52, x + card - 16, y + 60, (200, 208, 220, 255))
        y += 160 + m
    rect(0, height - 72, width, height, (48, 56, 72, 255))
    return preview.png(width, height, px, max_pixels=MAX_PIXELS)


class Site:
    """data/sites/<site_id>/: site.json, targets.json, capture_plan.json, workspace/, runs/<id>/<id>, registry/, ui/<gen>."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.info = json.loads((self.root / 'site.json').read_text('utf-8'))
        self.page_id = self.info['page_id']

    # ---- registration
    @classmethod
    def register(cls, sites_dir, name, url, kinds, owner_confirmed, now):
        if owner_confirmed is not True:
            raise SiteRefused('「自分が管理するサイトです」の確認が必要です')
        name, origin, page_url, path, kinds = check_input(name, url, kinds)
        site_id = 'site-' + hashlib.sha256(origin.encode()).hexdigest()[:8]
        from src.noxiworks.real_capture import harness_target
        target = harness_target()
        page_id = target['target_id'] if target and target['url'] == page_url else site_id + '-p1'
        root = Path(sites_dir) / site_id
        if root.exists():
            raise SiteRefused('このサイトはすでに登録されています')
        tmp = Path(sites_dir) / ('.tmp-' + site_id)
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        owner = {'declared': True, 'declared_at': format_utc(now), 'verified': False}
        cls._write_unit(tmp, site_id=site_id, page_id=page_id, name=name, origin=origin, page_url=page_url, path=path,
                        label='トップページ' if path == '/' else path, kinds=kinds, owner=owner, now=now)
        tmp.rename(root)
        return cls(root)

    @staticmethod
    def _write_unit(tmp, *, site_id, page_id, name, origin, page_url, path, label, kinds, owner, now):
        """The files of one unit folder (a site's first page or a further page): the same layout, nothing shared with any other unit."""
        from src.noxiworks.capture import create_runtime
        profiles = [PROFILES[k] for k in kinds]
        host = urlsplit(origin).hostname
        targets = {'schema': 'siteproof.targets.v1', 'http_interval_seconds': 21600, 'capture_interval_seconds': 86400,
                   'tls_stale_seconds': 172800, 'domain_stale_seconds': 2592000,
                   'pages': [{'target_id': page_id, 'site_id': site_id, 'label': label, 'url': page_url}],
                   'sites': [{'site_id': site_id, 'name': name, 'origin': origin, 'registration_domain': host}]}
        plan = {'schema': 'siteproof.capture-plan.v1', 'sites': [{'site_id': site_id, 'stability': [], 'pages': [
            {'page_id': page_id, 'role': 'PRIMARY', 'label': label, 'path': path, 'profiles': profiles, 'real_capture': 'NOT_APPROVED',
             'stability': STABILITY, 'why': 'SiteProofアプリで登録したページです。'}]}]}
        (tmp / 'targets.json').write_text(json.dumps(targets, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (tmp / 'capture_plan.json').write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        create_runtime(tmp / 'workspace', {'pages': [{'target_id': page_id, 'label': label, 'url': page_url, 'site_name': name,
                                                      'profiles': profiles}]})
        (tmp / 'runs').mkdir()
        (tmp / 'ui').mkdir()
        info = {'schema': 'siteproof.app-site.v1', 'site_id': site_id, 'page_id': page_id, 'name': name, 'origin': origin, 'url': page_url,
                'label': label, 'kinds': kinds, 'registered_at': format_utc(now), 'owner': owner, 'capture_mode': 'OFFLINE_FIXTURE'}
        (tmp / 'site.json').write_text(json.dumps(info, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return info

    @classmethod
    def register_page(cls, site, path_or_url, label, kinds, now):
        """Add a further page (same origin) of `site` (its first page) as a unit folder <site>/pages/<site id>-p2..p5. -> the new page's Site.
        Nothing is copied from the first page or any other page (no permit, grant, Baseline, run, history, setting): the page starts with image
        monitoring OFF and HTTP not configured. The harness captures only the top page `/`, so a further page has no image capture (never a substitute)."""
        first = sites.site_root_of(site.root)
        if Path(site.root).resolve() != first:
            raise SiteRefused('ページを追加できるのは、サイトの最初のページからだけです')
        first_info = json.loads((first / 'site.json').read_text('utf-8'))
        text = (path_or_url or '').strip()
        label = (label or '').strip() or (text if text.startswith('/') else urlsplit(text).path or '/')
        if not 1 <= len(label) <= 60 or any(ord(c) < 32 for c in label):
            raise SiteRefused('ページ名は1〜60文字で入力してください')
        if text.startswith('/') and not text.startswith('//'):
            text = first_info['origin'] + text
        _, origin, page_url, path, kinds = check_input(first_info['name'], text, kinds)
        if origin != first_info['origin']:
            raise SiteRefused('追加できるのは、このサイトと同じホスト（' + urlsplit(first_info['origin']).hostname + '）のページだけです')
        from src.noxiworks import http_authority
        wrong = http_authority.target_problems({'url': page_url})  # what the HTTP monitor could never check ('..', over-long or odd paths) is not added
        if wrong:
            raise SiteRefused('このページは追加できません：' + '／'.join(wrong))
        units = sites.units(first)
        known = {json.loads((u / 'site.json').read_text('utf-8'))['url'] for u in units}
        if page_url in known:
            raise SiteRefused('このページはすでに登録されています')
        folder = first / 'pages'
        taken = {p.name for p in folder.iterdir()} if folder.is_dir() else set()  # any folder, broken or hidden ones too: an id is never used twice
        if len(units) >= sites.MAX_PAGES:
            raise SiteRefused(f'1つのサイトに登録できるページは、最初のページを含めて{sites.MAX_PAGES}つまでです')
        free = [f"{first.name}-p{n}" for n in range(2, sites.MAX_PAGES + 1) if f"{first.name}-p{n}" not in taken and f".tmp-{first.name}-p{n}" not in taken]
        if not free:
            raise SiteRefused('ページの番号（p2〜p%d）を使い切りました。番号は再利用しません' % sites.MAX_PAGES)
        page_id = free[0]
        folder.mkdir(exist_ok=True)
        tmp = folder / ('.tmp-' + page_id)
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        try:
            cls._write_unit(tmp, site_id=first.name, page_id=page_id, name=first_info['name'], origin=origin, page_url=page_url, path=path, label=label, kinds=kinds,
                            owner=first_info.get('owner') or {'declared': True, 'declared_at': format_utc(now), 'verified': False}, now=now)
            from src.noxiworks.site_monitor import default_settings
            (tmp / 'monitor.json').write_text(json.dumps({**default_settings(now), 'enabled': False, 'next_due_at': None}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            tmp.rename(folder / page_id)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        return cls(folder / page_id)

    # ---- saved state
    def runs(self):
        return sorted(p / p.name for p in (self.root / 'runs').iterdir() if RUN_ID.match(p.name) and (p / p.name).is_dir())

    def registry(self):
        r = self.root / 'registry'
        return r if (r / 'APPROVAL-RECORD.json').is_file() else None

    def summary(self, run):
        """Per profile: verdict, reasons, changed pixels, stability, compared? (read back from the saved run, not from memory)."""
        report = json.loads((run / 'validation-result.json').read_text('utf-8'))
        out = {}
        for kind in self.info['kinds']:
            result = json.loads((run / f'{kind}-run-result.json').read_text('utf-8'))
            job = result['state']['jobs'][0]
            comp = next(r for r in result['comparison']['results'] if r.get('job_id') == job['job_id'])
            op = comp.get('operational') or {}
            shown = present(comp, None)  # the same projection the pages use
            out[kind] = {'job_id': job['job_id'], 'execution': job['execution'], 'compared': comp.get('baseline') is not None,
                         'verdict': op.get('verdict'), 'reasons': op.get('reasons') or [],
                         'changed_pixels': (comp.get('metrics') or {}).get('changed_pixels'),
                         'stability': (comp.get('capture_stability') or {}).get('value'), 'candidate': 'capture-' + job['job_id'],
                         'image_label': shown['image']['label'], 'quality_label': shown['quality']['label']}
        return {'run_id': run.name, 'captured_at': min(w['opened_at'] for w in report['windows'].values()),
                'compared': report['baseline_compared'], 'fixture': run.name.rsplit('-', 1)[1], 'profiles': out}

    def stage(self):
        runs = self.runs()
        if not runs:
            return 'NO_CAPTURE'
        if self.registry():
            return 'COMPARING'
        last = self.summary(runs[-1])
        return 'READY_TO_APPROVE' if self.approvable(last) is None else 'CAPTURE_AGAIN'

    @staticmethod
    def approvable(summary):
        """None if the newest capture can become the Baseline; else the reason shown to the user."""
        for kind, p in summary['profiles'].items():
            if p['execution'] != 'COMPLETED':
                return f'{kind}の撮影が完了していません'
            if p['stability'] != 'STABLE':
                return f'{kind}の撮影が安定していません。もう一度撮影してから承認してください'
        return None

    def readiness(self, docker_found):
        """What real capture of THIS site would need. All four must hold; none can be completed from the app today."""
        return [
            {'key': 'owner', 'label': '本人管理サイトの確認', 'ok': False,
             'state': '自己申告のみ（未検証）',
             'guide': '登録時に「自分が管理するサイト」と確認しました。サイトに確認用ファイルを置いて照合する方式を予定していますが、照合には実サイトへのアクセスが必要なため、まだ実装していません。'},
            {'key': 'egress', 'label': '通信許可（撮影してよい通信先と期間）', 'ok': False,
             'state': '未承認',
             'guide': '実サイトの撮影は、サイト・期間・通信先を限定した承認記録（識別ファイル）がある場合だけ行います。このサイトの承認記録はありません。'},
            {'key': 'environment', 'label': '撮影環境（Docker・固定した撮影イメージ）', 'ok': False,
             'state': 'Docker CLIあり（撮影イメージは未確認）' if docker_found else 'Dockerが見つかりません',
             'guide': '撮影は、固定したChromiumイメージを Docker で動かし、通信制御を通して行います。イメージの準備手順はまだ公開していません。'},
            {'key': 'harness', 'label': '実撮影ハーネスの対応', 'ok': False,
             'state': 'このサイトは未対応' if self.info['url'].endswith('/') and self.info['url'].count('/') == 3 else 'トップページ（/）以外の画像撮影は未対応',
             'guide': '現在の実撮影ハーネスは、承認済みの1ページ（Tokyo Trouble Navi トップページ）専用です。任意のサイトへの対応は未実装です（docs/REAL_CAPTURE.md）。'
                      '撮影できるのはトップページ（/）だけで、追加したページの画像を撮影することはできません（別のページの画像で代用することもしません）。'}]

    # ---- capture (offline fixture)
    def capture(self, fixture, now):
        from src.noxiworks.baseline_runtime import comparison_export, open_runtime, prepare_job
        from src.worker.capture import capture, MemoryChannel
        from tests.comparison.support import synthetic_browser_audit
        from tools.offline_baseline_demo import RESOURCES, DemoLease, StoredImageDriver, changed_image, stability_record
        if fixture not in FIXTURES:
            raise SiteRefused('不明な撮影画像です')
        runtime = open_runtime(self.root / 'workspace')
        rules = policy(STABILITY)
        accent = tuple(int(self.info['site_id'][5 + i * 2:7 + i * 2], 16) // 2 for i in range(3)) + (255,)
        files, windows, exports, compared = {}, {}, {}, set()
        for n, kind in enumerate(self.info['kinds']):
            p = PROFILES[kind]
            base = page_image(p['width'], IMAGE_HEIGHTS[kind], accent)
            edited = changed_image(base)
            image = edited if fixture == 'changed' else base
            stability = stability_record(image, edited if fixture == 'unstable' else None, rules)
            batch, job_id, plan = prepare_job(runtime, self.page_id, kind)
            lease = DemoLease(runtime.repo.get_job(job_id).snapshot.intent.target_url)

            def factory(request, remaining, image=image, job_id=job_id, lease=lease, stability=stability):
                out = capture(request, StoredImageDriver(image, lease.ledger), lease, RESOURCES)
                runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))  # synthetic: no browser ran
                runtime.record_capture_stability(job_id, stability)
                return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed

            opened = now + timedelta(seconds=10 * n)
            runtime.run(batch, factory, lease, RESOURCES)
            compared.add(plan['baseline'] is not None)
            # This job's comparison result and Baseline candidate only (what local_capture / summary read): the full state lists
            # every earlier result and candidate, which would make each saved run larger than the one before.
            files[f'{kind}-run-result.json'] = {'type': 'result', 'state': runtime.state(batch),
                                                'comparison': {'results': [r for r in runtime.comparison.state()['results'] if r.get('job_id') == job_id]},
                                                'baselines': [b for b in runtime.workspace.state()['baselines'] if b.get('candidate_id') == 'capture-' + job_id],
                                                'capture_info': {job_id: {'repeat_identical': stability['value'] == 'STABLE', 'synthetic': True}}}
            files[f'{kind}-head.json'] = {'synthetic': True, 'http_status': None, 'note': 'offline fixture capture: no request to the site'}
            files[f'{kind}-capture-meta.json'] = [{'job_id': job_id, 'reason': 'CAPTURE_COMPLETE', 'synthetic': True, 'sandbox': {}, 'runtime': {}}]
            exports.update(comparison_export(runtime, job_id))
            windows['CAPTURE-' + kind] = {'opened_at': format_utc(opened), 'closed_at': format_utc(opened + timedelta(seconds=5))}
        if len(compared) != 1:
            raise SiteRefused('Desktop と Mobile の比較状態が一致しません')
        files['validation-result.json'] = {'task': 'SITEPROOF-APP-OFFLINE-FIXTURE', 'synthetic': True, 'passed': True, 'baseline_approved': False,
                                           'baseline_compared': compared.pop(), 'aws_touched': False, 'site_modified': False,
                                           'monitoring_started': False, 'navigated_to_real_site': False, 'windows': windows}
        files['workspace-created.json'] = {'origin': self.info['origin'], 'url': self.info['url'], 'page_id': self.page_id}
        count = len(list((self.root / 'runs').iterdir()))
        run_id = f'{now:%Y%m%dT%H%M%SZ}-{count % 100:02d}-{fixture}'
        tmp = self.root / 'runs' / ('.tmp-' + run_id)
        run = tmp / run_id
        run.mkdir(parents=True)
        for name, body in files.items():
            (run / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        for name, raw in exports.items():
            (run / name).write_bytes(raw)
        # Only this run's own evidence folders (screenshot + manifest per job): the run stays verifiable on its own and storage grows
        # linearly. Copying the whole workspace (which holds every earlier capture) made each run larger than the last.
        for kind in self.info['kinds']:
            evidence = files[f'{kind}-run-result.json']['state']['jobs'][0].get('evidence') or {}
            for ref in {Path(evidence[k]).parent.as_posix() for k in ('artifact_ref', 'manifest_ref') if evidence.get(k)}:
                shutil.copytree(self.root / 'workspace' / ref, run / 'workspace' / ref, dirs_exist_ok=True)
        (run / 'export-sha256.json').write_text(json.dumps(tree(run), indent=2) + '\n', encoding='utf-8')
        tmp.rename(self.root / 'runs' / run_id)
        return self.summary(self.root / 'runs' / run_id / run_id)

    # ---- human approval of the newest capture
    def approve(self, run_id, now, actor=ACTOR, origin='USER'):
        """Approve the newest capture as Baseline v1. origin USER = a person clicked; AUTO_INITIAL = site_monitor's first stable inspection."""
        from src.noxiworks.baseline_runtime import open_runtime
        if self.registry():
            raise SiteRefused('Baselineはすでに承認済みです（更新は未対応）')
        runs = self.runs()
        if not runs or runs[-1].name != run_id:
            raise SiteRefused('承認できるのは最新の撮影だけです。画面を更新してください')
        run = runs[-1]
        summary = self.summary(run)
        reason = self.approvable(summary)
        if reason or summary['compared']:
            raise SiteRefused(reason or 'この撮影はすでに比較済みです')
        runtime = open_runtime(self.root / 'workspace')
        store = runtime.comparison.baselines
        report = json.loads((run / 'validation-result.json').read_text('utf-8'))
        baselines = []
        for kind, p in summary['profiles'].items():
            record = store.get(p['candidate'])
            if record.status is not BaselineStatus.PENDING or record.revision != 0:
                raise SiteRefused(f'{kind}の候補は承認待ちではありません')
            store.decide(p['candidate'], decision=BaselineStatus.APPROVED, actor=actor, expected_revision=0,
                         reviewed_digest=record.registered_digest, expected_current_version=0)
            history = store.history(record.candidate.page_id, record.candidate.profile_fingerprint)
            if len(history) != 1 or not history[0].record.is_valid_approval():
                raise SiteRefused(f'{kind}の承認を読み戻せませんでした')
            c = record.candidate
            prof = PROFILES[kind]
            baselines.append({'kind': kind, 'page_id': self.page_id, 'candidate_id': p['candidate'], 'job_id': p['job_id'], 'version': 1,
                              'status': 'APPROVED', 'revision': history[0].record.revision, 'candidate_digest': record.registered_digest,
                              'png_sha256': c.artifact_sha256, 'artifact_ref': c.artifact_ref, 'profile_fingerprint': c.profile_fingerprint,
                              'viewport': [prof['width'], prof['height']], 'full_page': prof['full_page'],
                              'captured_at': report['windows']['CAPTURE-' + kind]['opened_at'], 'stability': {'value': 'STABLE'},
                              'quality': 'UNKNOWN', 'profile_reason': 'PROFILE_UNATTESTED', 'source': 'OWNER_SITE_UNATTESTED',
                              'approved_at': format_utc(now), 'actor': actor})
        tmp = self.root / '.tmp-registry'
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        shutil.copytree(self.root / 'workspace', tmp / 'workspace')
        record = {'schema': 'siteproof.baseline-registry.v1', 'registry_id': 'registry', 'page_id': self.page_id, 'url': self.info['url'],
                  'decision': 'APPROVED', 'approved_at': format_utc(now), 'actor': actor, 'baseline_origin': origin,
                  'instruction': ('撮影画像を確認し、画面の「Baselineを承認」で承認' if origin == 'USER'
                                  else f"初回の安定した撮影（{'・'.join(b['kind'] for b in baselines)}完了・STABLE）から自動作成。利用者は未確認"),
                  'mechanism': 'SQLiteBaselineStore.decide (one-shot APPROVED)',
                  'synthetic': True, 'distinct_from': [], 'baselines': baselines,
                  'source_run': {'run_id': run.name, 'task': report['task'],
                                 'export_sha256_json': hashlib.sha256((run / 'export-sha256.json').read_bytes()).hexdigest()}}
        (tmp / 'APPROVAL-RECORD.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (tmp / 'export-sha256.json').write_text(json.dumps(tree(tmp), indent=2) + '\n', encoding='utf-8')
        tmp.rename(self.root / 'registry')
        return record

    # ---- the user's confirmation of an automatic Baseline (a separate record: the approved Baseline itself is never rewritten)
    # ---- real captures (src/noxiworks/real_capture.py) live apart from the offline fixture runs: never mixed on one page
    def real_runs(self):
        d = self.root / 'real' / 'runs'
        return sorted(p / p.name for p in d.iterdir() if re.fullmatch(r'\d{8}T\d{6}Z-\d{2}-real', p.name) and (p / p.name).is_dir()) if d.is_dir() else []

    def real_registry(self):
        from src.noxiworks.baseline_update import finish_switch
        finish_switch(self.root / 'real')  # an interrupted Baseline switch is completed (or left alone, fail closed) before anyone reads it
        r = self.root / 'real' / 'registry'
        return r if (r / 'APPROVAL-RECORD.json').is_file() else None

    def mode(self):
        """REAL once a real capture is saved (the pages then show real captures only), else OFFLINE_FIXTURE."""
        return 'REAL' if self.real_runs() else 'OFFLINE_FIXTURE'

    def baseline_state(self):
        """NONE / AUTO (created automatically, not looked at) / CONFIRMED (the user looked at it) / USER (approved by the user)."""
        real = self.mode() == 'REAL'
        registry = self.real_registry() if real else self.registry()
        if registry is None:
            return {'state': 'NONE', 'mode': self.mode()}
        record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
        out = {'approved_at': record['approved_at'], 'actor': record['actor'], 'source_run': record['source_run']['run_id'], 'mode': self.mode()}
        origin = record.get('baseline_origin')
        if real and (self.root / 'real' / 'registry-origin.json').is_file():  # register_baseline's record has no origin field
            origin = json.loads((self.root / 'real' / 'registry-origin.json').read_text('utf-8'))['origin']
        from src.noxiworks.baseline_registry import valid_formal
        if (origin or 'USER') == 'USER':
            return {'state': 'USER', **out, **self._versions(record)}
        formal = valid_formal(registry, record.get('baselines', []))
        if formal:  # the USER formally approved this exact Baseline (a separate, bound record: the Baseline itself is as it was)
            return {'state': 'USER', **out, **self._versions(record), 'formal': {'approved_at': formal['approved_at'], 'actor': formal['actor']}}
        if origin == 'USER_UPDATE' and not any(str(b.get('actor', '')).startswith('SiteProof自動作成') for b in record.get('baselines', [])):
            return {'state': 'USER', **out, **self._versions(record)}  # a person approved every profile's current version
        confirmed = self.root / ('real/baseline-confirmation.json' if real else 'baseline-confirmation.json')
        if confirmed.is_file():
            return {'state': 'CONFIRMED', **out, **self._versions(record), 'confirmed': json.loads(confirmed.read_text('utf-8')), 'targets': self._targets(record)}
        return {'state': 'AUTO', **out, **self._versions(record), 'targets': self._targets(record)}

    @staticmethod
    def _targets(record):
        """What a formal approval is bound to, for the screen to show and send back: {kind: candidate id, version, digest, image hash}."""
        return {b['kind']: {k: b.get(k) for k in ('candidate_id', 'version', 'candidate_digest', 'png_sha256')} for b in record.get('baselines', [])}

    @staticmethod
    def _versions(record):
        return {'versions': {b['kind']: b.get('version', 1) for b in record.get('baselines', [])}}

    def baseline_history_dirs(self):
        """The earlier registry versions kept by Baseline updates, newest first (runs compared with them are still shown)."""
        d = self.root / 'real' / 'registry-history'
        return sorted((p for p in d.iterdir() if (p / 'APPROVAL-RECORD.json').is_file()), key=lambda p: p.stat().st_mtime, reverse=True) if d.is_dir() else []

    def baseline_history(self):
        """Earlier registries kept by Baseline updates, oldest first: [{'name', 'versions', 'approved_at', 'actor'}]. Read-only."""
        d = self.root / 'real' / 'registry-history'
        out = []
        for p in sorted(d.iterdir()) if d.is_dir() else []:
            try:
                record = json.loads((p / 'APPROVAL-RECORD.json').read_text('utf-8'))
                out.append({'name': p.name, 'versions': self._versions(record)['versions'], 'approved_at': record.get('approved_at'), 'actor': record.get('actor')})
            except (OSError, ValueError):
                out.append({'name': p.name, 'versions': {}, 'approved_at': None, 'actor': None})
        return sorted(out, key=lambda h: h['approved_at'] or '')

    def confirm_baseline(self, now):
        state = self.baseline_state()
        if state['state'] != 'AUTO':
            raise SiteRefused('確認が必要な自動作成のBaselineはありません')
        record = {'confirmed_at': format_utc(now), 'actor': 'ローカル利用者（SiteProofアプリの画面で確認）', 'source_run': state['source_run']}
        (self.root / ('real/baseline-confirmation.json' if state['mode'] == 'REAL' else 'baseline-confirmation.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return record
