"""Who may be checked over HTTP, when and how often: the signed HTTP grant, its ownership evidence and the request ledger. Verification only.

The grant (<site>/http-grant.json + .sig, schema siteproof.http-grant.v2) is signed by the USER with tools/http_grant.py and verified against
<data>/trust/allowed_signers (OpenSSH SSHSIG, src/noxiworks/permit.verify_signature). It fixes, under the signature: the site id, ONE host, port 443,
ONE path, GET, a period, the shortest interval between ANY two requests (manual ones included), the total number of requests, the purpose
(MONITOR, or LIMITED_TRIAL: at most 24 h and 20 requests) and the ownership record. It is not an image permit and an image permit is not one:
the schemas differ, the fields differ and each verifier refuses the other.

Ownership: the same verifiable evidence the image permit needs (permit.ownership_problems: CLOUDFLARE_ACCOUNT_CONTROL of a workers.dev host, the
evidence file pinned by hash under the signature), not older than OWNERSHIP_MAX_DAYS. A declaration alone, or a method nothing can verify, never
allows a request -- so a site on its own domain cannot be checked over HTTP yet, exactly like image capture.

The ledger (<data>/trust/http-ledger/<site id>.jsonl, one line per request, written and fsynced BEFORE the request under an OS lock) is where count
and frequency are enforced for the app, the scheduler and anything else that runs the probe process: max_requests per grant, min_interval_seconds
between any two requests to the site (also across a renewed grant). A reserved request stays counted whatever happens next. An unreadable line, a
different site in the file, or a clock that went back refuses (fail closed).
Limits: the PC's own clock and the local files are trusted; whoever can write them (or the trust file) can reset the count. This guards the normal
paths on a PC whose user is the site owner, it is not protection against a local attacker.
"""
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.aws_b.model import format_utc, parse_utc
from src.isolation.destination import AllowedDestination, DestinationPolicy, check_authority
from src.noxiworks import filelock
from src.noxiworks import permit as permits
from src.noxiworks import sites

GRANT_SCHEMA = 'siteproof.http-grant.v2'
GRANT_KEYS = {'schema', 'grant_id', 'issued_by', 'issued_at', 'site_id', 'host', 'port', 'path', 'method', 'purpose', 'valid_from', 'valid_until',
              'min_interval_seconds', 'max_requests', 'ownership'}
PURPOSES = {'MONITOR': {'max_days': 366, 'min_interval': 300, 'max_requests': 110_000},
            'LIMITED_TRIAL': {'max_days': 1, 'min_interval': 60, 'max_requests': 20}}
OWNERSHIP_MAX_DAYS = 90
GRANT_ID = re.compile(r'http-[A-Za-z0-9._-]{1,59}\Z')
PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}\Z", re.ASCII)
LEDGER_LOCK_WAIT = 5.0


class Refused(ValueError):
    """Nothing may be requested. `code`: GRANT_INVALID | GRANT_EXPIRED | GRANT_EXHAUSTED | RATE_LIMITED | LEDGER | TARGET."""

    def __init__(self, code, message, not_before=None):
        super().__init__(message)
        self.code, self.message, self.not_before = code, message, not_before


def target(info):
    """(host, path) of the registered page: the only thing that can ever be checked (never taken from a request)."""
    u = urlsplit(info['url'])
    return u.hostname, (u.path or '/')


def target_problems(info):
    from src.noxiworks.site_workflow import BLOCKED_HOSTS  # the same names the registration refuses (localhost, .local, .internal ...)
    host, path = target(info)
    decision = check_authority(DestinationPolicy((AllowedDestination(host, 443),)), host, 443)
    if not decision.allowed:
        return ['監視できないホストです（' + decision.reason + '）']
    if host.endswith(BLOCKED_HOSTS) or host in BLOCKED_HOSTS or '.' not in host:
        return ['監視できないホストです（内部向けの名前）']
    if not PATH_RE.fullmatch(path) or '..' in path:
        return ['監視できないパスです']
    return []


def trust_file(site_root):
    return sites.data_of(site_root) / 'trust' / 'allowed_signers'


def ledger_file(site_root):
    return trust_file(site_root).parent / 'http-ledger' / (Path(site_root).resolve().name + '.jsonl')


def read_grant(site_root):
    """-> (grant or None, why not). The returned dict is parsed from exactly the bytes whose signature was verified."""
    try:
        return permits.verify_signature(Path(site_root) / 'http-grant.json', trust_file(site_root)), None
    except permits.PermitRefused as exc:
        return None, 'HTTP監視の許可がありません：' + str(exc).replace('real/permit.json と permit.json.sig', 'http-grant.json と http-grant.json.sig').replace('監視許可', 'HTTP監視の許可')


def grant_problems(grant, info, site_root, now, interval=None):
    """Everything under the signature must match this site and this moment. -> [(code, message)]. `interval` is the monitor's own interval
    (None: a manual check, which only has to keep min_interval_seconds, enforced by the ledger)."""
    if not isinstance(grant, dict) or grant.get('schema') != GRANT_SCHEMA:
        return [('GRANT_INVALID', 'HTTP監視の許可の形式が違います（画像撮影の許可は使えません。古い形式の許可は tools/http_grant.py で署名し直してください）')]
    problems = []

    def bad(message, code='GRANT_INVALID'):
        problems.append((code, message))
    if set(grant) != GRANT_KEYS:
        bad('許可の項目が不正です（不足または余分な項目があります）')
    host, path = target(info)
    if grant.get('site_id') != info['site_id'] or grant.get('host') != host or grant.get('path') != path:
        bad('許可された対象が登録内容と一致しません')
    if grant.get('port') != 443 or type(grant.get('port')) is not int or grant.get('method') != 'GET':
        bad('許可できるのは HTTPS（443）への GET だけです')
    if not isinstance(grant.get('grant_id'), str) or not GRANT_ID.match(grant['grant_id']):
        bad('許可のIDが不正です')
    limits = PURPOSES.get(grant.get('purpose')) if isinstance(grant.get('purpose'), str) else None
    start, end, issued = (parse_utc(grant.get(k) if isinstance(grant.get(k), str) else '') for k in ('valid_from', 'valid_until', 'issued_at'))
    if limits is None:
        bad('許可の目的が不正です')
    elif not (start and end and issued):
        bad('許可の期間が不正です')
    else:
        if end <= start or end - start > timedelta(days=limits['max_days']):
            bad('許可の期間が長すぎる、または不正です')
        if not start <= now < end:
            bad('HTTP監視の許可が有効期間外です', 'GRANT_EXPIRED' if now >= end else 'GRANT_INVALID')
        step, most = grant.get('min_interval_seconds'), grant.get('max_requests')
        if type(step) is not int or not limits['min_interval'] <= step <= 86400:
            bad('許可された最短の間隔が不正です')
        elif interval is not None and step > interval:
            bad('許可された最短の間隔より短い間隔は使えません')
        if type(most) is not int or not 1 <= most <= limits['max_requests']:
            bad('許可された回数が不正です')
    return problems + [('GRANT_INVALID', m) for m in ownership_problems(grant, host, site_root, now)]


def ownership_problems(grant, host, site_root, now):
    """The same evidence check as the image permit, plus an age limit: an old check says nothing about who controls the host today.
    The evidence is the site's (it is about the host), also for a further page of it."""
    site_root = sites.site_root_of(site_root)
    own = grant.get('ownership')
    if not isinstance(own, dict):
        return ['所有権の確認記録がありません']
    try:
        problems = permits.ownership_problems(grant, host, site_root, now)
    except (AttributeError, TypeError, KeyError, OSError):
        return ['所有権の確認記録が不正です']
    verified = parse_utc(own.get('verified_at') if isinstance(own.get('verified_at'), str) else '')
    if not problems and (verified is None or now - verified > timedelta(days=OWNERSHIP_MAX_DAYS)):
        problems = [f'所有権の確認が古くなっています（{OWNERSHIP_MAX_DAYS}日以内の確認が必要です）。もう一度確認して署名してください']
    return problems


def entries(site_root):
    """Every reserved request of this site, oldest first. Refused (LEDGER) when anything in the file cannot be read as one."""
    f, site_id = ledger_file(site_root), Path(site_root).resolve().name
    if not f.is_file():
        return []
    out = []
    for line in f.read_text('utf-8').splitlines():
        try:
            e = json.loads(line)
            if e['site_id'] != site_id or parse_utc(e['at']) is None or not isinstance(e['grant_id'], str):
                raise ValueError('entry')
        except (ValueError, KeyError, TypeError):
            raise Refused('LEDGER', 'HTTP監視の回数の記録を読み取れません（trust/http-ledger）。安全のため通信しません') from None
        out.append(e)
    return out


def usage(site_root, grant):
    """{'used', 'remaining', 'last_at', 'not_before'} for the screen. used None = the ledger cannot be read."""
    try:
        done = entries(site_root)
    except Refused:
        return {'used': None, 'remaining': 0, 'last_at': None, 'not_before': None}
    used = sum(1 for e in done if e['grant_id'] == grant.get('grant_id'))
    last = done[-1]['at'] if done else None
    step, most = grant.get('min_interval_seconds'), grant.get('max_requests')
    return {'used': used, 'remaining': max(0, most - used) if type(most) is int else 0, 'last_at': last,
            'not_before': format_utc(parse_utc(last) + timedelta(seconds=step)) if last and type(step) is int else None}


def reserve(site_root, grant, now, trigger):
    """Count one request, atomically, before it is made. -> the number used including this one. Raises Refused."""
    f = ledger_file(site_root)
    f.parent.mkdir(parents=True, exist_ok=True)
    try:
        with filelock.held(f.with_suffix('.lock'), wait=LEDGER_LOCK_WAIT):
            used = _room(entries(site_root), grant, now)
            line = json.dumps({'site_id': Path(site_root).resolve().name, 'grant_id': grant['grant_id'], 'at': format_utc(now), 'trigger': trigger,
                               'grant_sha256': hashlib.sha256(json.dumps(grant, sort_keys=True).encode()).hexdigest()})
            raw = (line + '\n').encode('utf-8')
            with open(f, 'ab') as out:
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
            return used + 1
    except filelock.LockBusy:
        raise Refused('LEDGER', 'HTTP監視の回数の記録が別の処理で使用中です') from None


def _permitted(site_root, now, interval):
    site_root = Path(site_root).resolve()
    try:
        info = json.loads((site_root / 'site.json').read_text('utf-8'))
        mine = sites.unit_problem(site_root, info) is None
    except (OSError, ValueError, KeyError, TypeError):
        mine = False
    if not mine:
        raise Refused('TARGET', 'サイトの登録内容を確認できません')
    wrong = target_problems(info)
    if wrong:
        raise Refused('TARGET', '／'.join(wrong))
    grant, why = read_grant(site_root)
    if grant is None:
        raise Refused('GRANT_INVALID', why)
    problems = grant_problems(grant, info, site_root, now, interval)
    if problems:
        raise Refused(problems[0][0] if len(problems) == 1 else 'GRANT_INVALID', '／'.join(m for _, m in problems))
    return site_root, info, grant


def _room(done, grant, now):
    """Refused when this grant has no request left or the last request to this unit is too recent. -> the number used so far."""
    used = sum(1 for e in done if e['grant_id'] == grant['grant_id'])
    if used >= grant['max_requests']:
        raise Refused('GRANT_EXHAUSTED', f"許可された回数を使い切りました（{used} / {grant['max_requests']}回）")
    if done:
        allowed = parse_utc(done[-1]['at']) + timedelta(seconds=grant['min_interval_seconds'])
        if now < allowed:  # also when the clock went back
            raise Refused('RATE_LIMITED', f"前回の検査から{grant['min_interval_seconds']}秒以上あける必要があります（手動検査を含む）", format_utc(allowed))
    return used


def precheck(site_root, now, interval=None):
    """Would a request be refused right now? Raises Refused (nothing is reserved); the binding decision is authorize(), right before the request."""
    site_root, _, grant = _permitted(site_root, now, interval)
    _room(entries(site_root), grant, now)


def authorize(site_root, now, trigger='MANUAL', interval=None):
    """The whole decision for ONE request, taken fresh (never from a cache): target, signature, scope, period, ownership -- and the reservation.
    -> {'host', 'path', 'grant', 'used', 'reserved_at'}; raises Refused when nothing may be requested."""
    site_root, info, grant = _permitted(site_root, now, interval)
    used = reserve(site_root, grant, now, trigger)
    host, path = target(info)
    return {'host': host, 'path': path, 'grant': grant, 'used': used, 'reserved_at': format_utc(now)}
