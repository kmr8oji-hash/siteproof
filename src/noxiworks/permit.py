"""Signed monitoring permits: the only thing that lets SiteProof capture a real site. Verification only -- this module never signs.

A permit is a JSON file signed by the USER with OpenSSH (`ssh-keygen -Y sign -n siteproof-monitoring-permit -f <USER key> permit.json`,
which writes permit.json.sig). It is verified with `ssh-keygen -Y verify` against a trust file in OpenSSH allowed_signers format
(`<principal> namespaces="siteproof-monitoring-permit" ssh-ed25519 AAAA...`) that the USER places at <data>/trust/allowed_signers.
No cryptography is implemented here: OpenSSH (Ed25519 SSHSIG, namespace-bound) does the signing and the verification. SiteProof
holds no private key and has no code path that runs `ssh-keygen -Y sign`, so the app cannot issue a permit.

The permit fixes, under the signature:
  site / target      site id, origin, the single host, target id, the page URL (top page `/` only: the harness and the broker accept
                     nothing else) -- and the SHA-256 of the site's own targets.json and capture_plan.json, so editing the URL in a
                     settings file without a new signature changes a pinned hash and is refused
  scope              valid_from / valid_until, max_runs, ownership check record (method + time), issued_by (= the trusted principal)
  ownership          well-known-file / dns-txt: NOT verifiable yet -- a method and a time are only a claim, so they never allow a
                     capture (VERIFIABLE_METHODS). CLOUDFLARE_ACCOUNT_CONTROL (workers.dev hosts only): the account ID hash,
                     the Worker name and the account's workers.dev subdomain -- the host must be exactly
                     <worker>.<subdomain>.workers.dev -- and the ID + SHA-256 of the evidence file <site>/real/ownership-evidence.json,
                     whose content must state the same values and the same check time. The account hash alone never passes.
                     DNS_TXT_CHALLENGE (any public host): the USER published the token issued for this site id and this exact host as a TXT
                     record of that host, the USER-run check found exactly that value, and the evidence file (same place, pinned by hash) says
                     so for at most 90 days. The record of another host, a parent domain or another site never passes; a withdrawn check
                     (real/ownership-revoked.json) ends it at once. 'dns-txt' / 'well-known-file' stay what they were: claims, never accepted.
  identity           the harness identity (pinned file hashes, image ID, browser bundle manifest): the `--expect` the harness checks
  baseline_policy    AUTO_INITIAL_THEN_COMPARE: the first stable capture under this permit may become the Baseline, and later runs
                     are compared with exactly that Baseline (derive_expect adds its pins); NONE: no Baseline is ever created
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import urlsplit

from src.aws_b.model import parse_utc

SCHEMA = 'siteproof.monitoring-permit.v1'
NAMESPACE = 'siteproof-monitoring-permit'
POLICIES = ('AUTO_INITIAL_THEN_COMPARE', 'NONE')
OWNERSHIP_METHODS = ('well-known-file', 'dns-txt', 'CLOUDFLARE_ACCOUNT_CONTROL', 'DNS_TXT_CHALLENGE')
VERIFIABLE_METHODS = ('CLOUDFLARE_ACCOUNT_CONTROL', 'DNS_TXT_CHALLENGE')  # the only ones whose evidence is really checked below; any other method is refused
OWNERSHIP_EVIDENCE = 'ownership-evidence.json'  # in <site>/real/, next to permit.json; placed by the USER, pinned by the permit
OWNERSHIP_REVOKED = 'ownership-revoked.json'  # in <site>/real/: written when a later check did not find the record any more
DNS_EVIDENCE_SCHEMA = 'siteproof.ownership-evidence.dns-txt-challenge.v1'
DNS_RECORD_PREFIX = '_siteproof-challenge.'
DNS_MAX_DAYS = 90
CF_EVIDENCE_SCHEMA = 'siteproof.ownership-evidence.cloudflare-account-control.v1'
DNS_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
MAX_EVIDENCE_BYTES = 64 * 1024
TARGET_FILES = ('targets.json', 'capture_plan.json')
MAX_PERMIT_BYTES = 64 * 1024


class PermitRefused(ValueError):
    pass


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ssh_keygen():
    """OpenSSH's ssh-keygen. The operating system's own copy first (Windows System32\\OpenSSH, /usr/bin), so a directory placed
    earlier on PATH cannot substitute a "verifier" that always succeeds; PATH (e.g. Git for Windows) only when there is none."""
    for builtin in (Path(r'C:\Windows\System32\OpenSSH\ssh-keygen.exe'), Path('/usr/bin/ssh-keygen')):
        if builtin.is_file():
            return str(builtin)
    return shutil.which('ssh-keygen')


def verify_signature(permit_file, trust_file):
    """-> the permit dict, only if permit.json.sig is a valid signature by the principal it names, per the trust file."""
    permit_file, trust_file = Path(permit_file), Path(trust_file)
    sig = permit_file.with_name(permit_file.name + '.sig')
    if not trust_file.is_file():
        raise PermitRefused('信頼する公開鍵（trust/allowed_signers）がありません')
    if not permit_file.is_file() or not sig.is_file():
        raise PermitRefused('署名付きの監視許可（real/permit.json と permit.json.sig）がありません')
    raw = permit_file.read_bytes()
    if len(raw) > MAX_PERMIT_BYTES:
        raise PermitRefused('監視許可が大きすぎます')
    try:
        permit = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise PermitRefused('監視許可がJSONとして読めません') from None
    principal = permit.get('issued_by') if isinstance(permit, dict) else None
    if not isinstance(principal, str) or not re.fullmatch(r'[A-Za-z0-9._@-]{1,64}', principal):
        raise PermitRefused('監視許可の発行者（issued_by）が不正です')
    tool = ssh_keygen()
    if tool is None:
        raise PermitRefused('署名を検証する ssh-keygen（OpenSSH）が見つかりません')
    # The exact bytes that were signed are fed on stdin; the namespace binds the signature to this purpose only.
    p = subprocess.run([tool, '-Y', 'verify', '-f', str(trust_file), '-I', principal, '-n', NAMESPACE, '-s', str(sig)],
                       input=raw, capture_output=True, timeout=30)
    if p.returncode != 0:
        raise PermitRefused('監視許可の署名が正しくありません（改変された・信頼していない鍵で署名された可能性があります）')
    return permit


def check_scope(permit, *, site_info, page_id, target_dir, now, used_runs):
    """Everything the signature covers must match this site and this moment. -> list of problems (empty = within the permit)."""
    problems = []
    if permit.get('schema') != SCHEMA:
        return ['監視許可の形式が違います']
    site, target = permit.get('site') or {}, permit.get('target') or {}
    host = urlsplit(site_info['url']).hostname
    if site.get('site_id') != site_info['site_id'] or site.get('origin') != site_info['origin'] or site.get('host') != host:
        problems.append('許可されたサイトが登録内容と一致しません')
    if target.get('target_id') != page_id or target.get('url') != site_info['url']:
        problems.append('許可されたページが登録内容と一致しません')
    if urlsplit(site_info['url']).path != '/':
        problems.append('撮影ハーネスが扱えるのはトップページ（/）だけです')
    pins = permit.get('target_files') or {}
    for name in TARGET_FILES:
        f = Path(target_dir) / name
        if not f.is_file() or pins.get(name) != sha(f):
            problems.append(f'対象設定 {name} が許可時の内容と一致しません')
    start, end = parse_utc(permit.get('valid_from') or ''), parse_utc(permit.get('valid_until') or '')
    if not (start and end and start <= now < end):
        problems.append('監視許可の有効期間外です')
    if type(permit.get('max_runs')) is not int or permit['max_runs'] < 1 or used_runs >= permit['max_runs']:
        problems.append(f'許可された撮影回数を使い切っています（{used_runs}回）')
    problems += ownership_problems(permit, host, target_dir, now)
    if permit.get('baseline_policy') not in POLICIES:
        problems.append('Baselineの扱い（baseline_policy）が不正です')
    identity = permit.get('identity') or {}
    if not identity.get('files') or not re.fullmatch(r'sha256:[0-9a-f]{64}', str(identity.get('image_id', ''))):
        problems.append('撮影構成（identity）が固定されていません')
    if not isinstance(permit.get('permit_id'), str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', permit['permit_id']):
        problems.append('監視許可のID（permit_id）が不正です')
    return problems


def ownership_problems(permit, host, target_dir, now):
    """The signed ownership record, for the app (check_scope) and the harness (before any Docker call). target_dir is the site folder
    (<site>/: the evidence is <site>/real/ownership-evidence.json). -> list of problems (all start with 所有権)."""
    own = permit.get('ownership') or {}
    if own.get('method') not in OWNERSHIP_METHODS or parse_utc(own.get('verified_at') or '') is None:
        return ['所有権の確認記録がありません']
    if own['method'] not in VERIFIABLE_METHODS:  # a recorded method + time with nothing to check it against proves nothing
        return [f"所有権の確認方法「{own['method']}」は、まだ自動照合に対応していません。実サイトの撮影は開始できません"]
    if own['method'] == 'DNS_TXT_CHALLENGE':
        site = permit.get('site')
        site_id = site.get('site_id') if isinstance(site, dict) else permit.get('site_id')  # the image permit / the HTTP grant
        return dns_ownership_problems(own, site_id, host, Path(target_dir) / 'real', now)
    return cloudflare_ownership_problems(own, host, Path(target_dir) / 'real' / OWNERSHIP_EVIDENCE, now)


def dns_ownership_problems(own, site_id, host, folder, now):
    """DNS_TXT_CHALLENGE: the signed record, the pinned evidence file and this moment must all agree on one site id, one exact host, one record
    name and one token, checked not longer ago than the evidence allows (at most 90 days). -> list of problems (all start with 所有権)."""
    dns, pin = own.get('dns'), own.get('evidence')
    if not (isinstance(dns, dict) and isinstance(pin, dict)):
        return ['所有権の確認記録（DNS）が不完全です']
    token, verified, until = str(dns.get('token_sha256', '')), parse_utc(own.get('verified_at') or ''), parse_utc(str(dns.get('valid_until', '')))
    if not (re.fullmatch(r'[0-9a-f]{64}', token) and isinstance(pin.get('evidence_id'), str) and re.fullmatch(r'dns-[A-Za-z0-9._-]{1,60}', pin['evidence_id'])
            and re.fullmatch(r'[0-9a-f]{64}', str(pin.get('sha256', '')))):
        return ['所有権の確認記録（DNS）が不完全です']
    if not isinstance(site_id, str) or not isinstance(host, str) or dns.get('site_id') != site_id or dns.get('host') != host or dns.get('record_name') != DNS_RECORD_PREFIX + host:
        return ['所有権の確認記録（DNS）が、このサイト・このホストのものではありません']
    if verified > now:
        return ['所有権の確認日時が未来です']
    if until is None or until <= verified or (until - verified).total_seconds() > DNS_MAX_DAYS * 86400 or now >= until:
        return ['所有権の確認（DNS）の有効期限が切れています。もう一度確認してください']
    evidence_file = folder / OWNERSHIP_EVIDENCE
    if not evidence_file.is_file():
        return ['所有権の確認の証拠ファイルがありません']
    raw = evidence_file.read_bytes()
    if len(raw) > MAX_EVIDENCE_BYTES or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        return ['所有権の確認の証拠ファイルが許可に固定された内容と一致しません']
    try:
        ev = json.loads(raw.decode('utf-8'))
        checks = ev['checks']
        issued, expires = parse_utc(str(ev.get('challenge_issued_at', ''))), parse_utc(str(ev.get('challenge_expires_at', '')))
        same = (ev.get('schema') == DNS_EVIDENCE_SCHEMA and ev.get('method') == 'DNS_TXT_CHALLENGE' and ev.get('evidence_id') == pin['evidence_id']
                and ev.get('site_id') == site_id and ev.get('host') == host and ev.get('record_name') == dns['record_name'] and ev.get('token_sha256') == token
                and parse_utc(str(ev.get('checked_at', ''))) == verified and parse_utc(str(ev.get('valid_until', ''))) == until
                and issued is not None and expires is not None and issued <= verified < expires
                and all(checks.get(k) is True for k in ('record_found', 'exact_value', 'all_answers_agree')))
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError):
        return ['所有権の確認の証拠ファイルを読み取れません']
    if not same:
        return ['所有権の確認の証拠の内容が許可の記録と一致しません']
    revoked = folder / OWNERSHIP_REVOKED
    if revoked.exists():  # present and unreadable counts as withdrawn
        try:
            withdrawn = json.loads(revoked.read_text('utf-8')).get('evidence_id')
        except (OSError, ValueError, AttributeError):
            withdrawn = pin['evidence_id']
        if withdrawn == pin['evidence_id']:
            return ['所有権の確認は取り消されています（後の確認で、DNSの記録が見つかりませんでした）']
    return []


def cloudflare_ownership_problems(own, host, evidence_file, now):
    """CLOUDFLARE_ACCOUNT_CONTROL: control of the Cloudflare account proves the host only where the host name itself names that account's
    Worker -- <worker>.<subdomain>.workers.dev (a workers.dev subdomain belongs to one account). A custom domain never passes here.
    The signed record must match the host exactly and the pinned evidence file byte for byte, and the evidence must state the same
    account / Worker / subdomain / host / check time. -> list of problems (all start with 所有権)."""
    cf, pin = own.get('cloudflare') or {}, own.get('evidence') or {}
    account, worker, sub = (str(cf.get(k, '')) for k in ('account_id_sha256', 'worker', 'workers_dev_subdomain'))
    if not (re.fullmatch(r'[0-9a-f]{64}', account) and re.fullmatch(DNS_LABEL, worker) and re.fullmatch(DNS_LABEL, sub)):
        return ['所有権の確認記録（Cloudflareのアカウント・Worker・サブドメイン）が不完全です']
    if host != f'{worker}.{sub}.workers.dev':
        return ['所有権の確認記録（Cloudflare）が対象ホストと一致しません（workers.devの <Worker>.<サブドメイン> だけが対象です）']
    verified = parse_utc(own['verified_at'])
    if verified > now:
        return ['所有権の確認日時が未来です']
    if not (isinstance(pin.get('evidence_id'), str) and re.fullmatch(r'[A-Za-z0-9._-]{1,64}', pin['evidence_id'])
            and re.fullmatch(r'[0-9a-f]{64}', str(pin.get('sha256', '')))):
        return ['所有権の確認の証拠（ID・SHA-256）が許可に固定されていません']
    if not evidence_file.is_file():
        return ['所有権の確認の証拠ファイルがありません']
    raw = evidence_file.read_bytes()
    if len(raw) > MAX_EVIDENCE_BYTES or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        return ['所有権の確認の証拠ファイルが許可に固定された内容と一致しません']
    try:
        ev = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return ['所有権の確認の証拠ファイルがJSONとして読めません']
    checks = ev.get('checks') if isinstance(ev, dict) else None
    if not (isinstance(checks, dict) and ev.get('schema') == CF_EVIDENCE_SCHEMA and ev.get('evidence_id') == pin['evidence_id']
            and ev.get('method') == 'CLOUDFLARE_ACCOUNT_CONTROL' and ev.get('account_id_sha256') == account and ev.get('worker') == worker
            and ev.get('workers_dev_subdomain') == sub and ev.get('host') == host and parse_utc(str(ev.get('checked_at', ''))) == verified
            and checks.get('worker_in_account') is True and checks.get('account_workers_dev_subdomain') == sub):
        return ['所有権の確認の証拠の内容が許可の記録と一致しません']
    return []


def derive_expect(permit, registry_pins=None):
    """The harness --expect for one run, derived from the signed identity only. With a Baseline (compare mode) its pins are added --
    allowed only when the permit's baseline_policy says so. Nothing else can be added or changed."""
    expect = json.loads(json.dumps(permit['identity']))
    expect.pop('baseline', None)
    if registry_pins is not None:
        if permit.get('baseline_policy') != 'AUTO_INITIAL_THEN_COMPARE':
            raise PermitRefused('この監視許可はBaselineとの比較を含みません')
        expect['baseline'] = registry_pins
    expect['permit_id'] = permit['permit_id']
    return expect


def check_expect(permit, expect, registry_pins=None):
    """Harness side: the --expect it was given must be exactly derive_expect(permit[, the registry it was given])."""
    return expect == derive_expect(permit, registry_pins)


# ---- the run ledger: one persistent count per permit, shared by the app and the harness
# The harness reserves a run (under an exclusive lock) after every permit check and BEFORE any container or network, so running the
# harness directly cannot exceed max_runs either; the app only reads the count. A reserved run stays counted whatever happens next
# (failure, crash): fail-closed. The ledger lives next to the trust file (<data>/trust/permit-ledger/<permit_id>.jsonl).
# Limit: anyone who can write these local files (or the trust file) can reset or forge the count; this guards the normal app and
# harness paths on a PC whose administrator is trusted, it is not protection against a local attacker.
LOCK_STALE_SECONDS = 900  # as site_monitor: a lock this old is left over from a crashed process
LOCK_WAIT_SECONDS = 15


def ledger_file(trust_file, permit_id):
    if not isinstance(permit_id, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', permit_id):
        raise PermitRefused('監視許可のID（permit_id）が不正です')
    return Path(trust_file).parent / 'permit-ledger' / (permit_id + '.jsonl')


def used_runs(trust_file, permit_id):
    f = ledger_file(trust_file, permit_id)
    return sum(1 for line in f.read_text('utf-8').splitlines() if line.strip()) if f.is_file() else 0


def _acquire(lock):
    """The same exclusive-create lock file as site_monitor.Monitor._lock, waiting briefly instead of failing at once."""
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > LOCK_STALE_SECONDS:
                    lock.unlink(missing_ok=True)  # left by a crashed holder
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() > deadline:
                raise PermitRefused('撮影回数の記録が別の処理で使用中です') from None
            time.sleep(0.05)


def reserve_run(trust_file, permit, run_ref, now_text):
    """Count one run against the permit, atomically; refused once max_runs is reached. -> runs used including this one."""
    f = ledger_file(trust_file, permit.get('permit_id'))
    f.parent.mkdir(parents=True, exist_ok=True)
    lock = f.with_suffix('.lock')
    _acquire(lock)
    try:
        used = used_runs(trust_file, permit['permit_id'])
        if type(permit.get('max_runs')) is not int or used >= permit['max_runs']:
            raise PermitRefused(f"許可された撮影回数を使い切っています（{used} / {permit.get('max_runs')}）")
        line = json.dumps({'run': str(run_ref), 'at': now_text,
                           'permit_sha256': hashlib.sha256(json.dumps(permit, sort_keys=True).encode()).hexdigest()})
        with open(f, 'a', encoding='utf-8') as out:
            out.write(line + '\n')
            out.flush()
            os.fsync(out.fileno())
        return used + 1
    finally:
        lock.unlink(missing_ok=True)
