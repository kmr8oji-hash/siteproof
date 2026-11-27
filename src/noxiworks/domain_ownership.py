"""Ownership of a general domain by DNS TXT challenge (method DNS_TXT_CHALLENGE): how the evidence that permit.dns_ownership_problems verifies comes into being.

issue() makes a one-time token for this site id and this exact host (valid 7 days) and the TXT record the USER must publish
(`_siteproof-challenge.<host>` = `siteproof-site=<site id>;token=<token>`). check() accepts it only when EVERY lookup it is given answers and contains exactly
that value (extra unrelated TXT values are fine; a `siteproof-site=` value of another site makes the answer ambiguous and is refused); only then it writes
<site>/real/ownership-evidence.json (without the token: its SHA-256 only), valid for at most 90 days, and consumes the challenge. recheck() looks again: a record
that every lookup definitively reports missing withdraws the evidence (real/ownership-revoked.json); a failed or disagreeing lookup never does.
Older files are moved to real/ownership-history/, never deleted. A site folder only: pages use their site's evidence.
Guarantees: pure and offline -- the lookups are injected (tools/dns_ownership.py holds the only real one, off by default); nothing is written on a refusal.
Not guaranteed: DNS itself (a resolver the USER trusts can be wrong or spoofed; the check asks the system resolver and up to three the USER names), and who
published the record: the USER vouches for it by running the check. This module never signs and grants nothing: the signed permit / grant pins the evidence.
"""
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit

from src.aws_b.model import format_utc, parse_utc
from src.noxiworks import http_authority, sites
from src.noxiworks import permit as permits

CHALLENGE_SCHEMA = 'siteproof.ownership-challenge.v1'
CHALLENGE_FILE = 'ownership-challenge.json'
HISTORY = 'ownership-history'
CHALLENGE_DAYS = 7
VALUE_PREFIX = 'siteproof-site='
MAX_ANSWERS = 50  # TXT strings read per lookup (more is refused: a record name that big is not the one we published)
MAX_KEPT = 20     # answers kept in the evidence, each cut to MAX_ANSWER_CHARS
MAX_ANSWER_CHARS = 300
METHODS = {'CLOUDFLARE_ACCOUNT_CONTROL': permits.CF_EVIDENCE_SCHEMA, 'DNS_TXT_CHALLENGE': permits.DNS_EVIDENCE_SCHEMA}


class OwnershipRefused(ValueError):
    pass


class LookupFailed(Exception):
    """A resolver did not give an answer. code: TIMEOUT | ERROR | NXDOMAIN (the name does not exist: a definite answer for recheck, a refusal for check)."""

    def __init__(self, code, message=''):
        super().__init__(message or code)
        self.code = code


def _read(path):
    try:
        value = json.loads(Path(path).read_text('utf-8'))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _write(path, body):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(tmp, path)


def _keep(path, history, name):
    """Move `path` into the history folder under a name nothing else has (never overwrites, never deletes)."""
    history.mkdir(parents=True, exist_ok=True)
    target, n = history / name, 1
    while target.exists():
        n += 1
        target = history / f'{Path(name).stem}-{n}{Path(name).suffix}'
    os.replace(path, target)
    return target


def _safe(value):
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,80}', value) else 'unnamed'


def _site(site_root):
    """-> (folder, site.json, host) of a SITE folder (a page folder is refused: pages use the evidence of their site)."""
    root = Path(site_root).resolve()
    info = _read(root / 'site.json')
    if info is None or not sites.SITE_ID.match(root.name) or info.get('site_id') != root.name or sites.site_root_of(root) != root:
        raise OwnershipRefused('サイトのフォルダではありません（ページのフォルダでは確認しません。所有権の確認はサイトに対して行います）')
    wrong = http_authority.target_problems(info)
    if wrong:
        raise OwnershipRefused('このホストの所有権は確認できません：' + '／'.join(wrong))
    return root, info, urlsplit(info['url']).hostname


def record_name(host):
    return permits.DNS_RECORD_PREFIX + host


def record_value(site_id, token):
    return f'{VALUE_PREFIX}{site_id};token={token}'


def _challenge(real):
    c = _read(real / CHALLENGE_FILE)
    return c if c and c.get('schema') == CHALLENGE_SCHEMA else None


def _sane(c, site_id, host):
    """The challenge file is this site's and this host's own, as issue() wrote it (a copied one is not)."""
    return (isinstance(c.get('token'), str) and re.fullmatch(r'[A-Za-z0-9_-]{20,128}', c['token']) is not None and c.get('site_id') == site_id and c.get('host') == host
            and c.get('record_name') == record_name(host) and c.get('record_value') == record_value(site_id, c['token'])
            and c.get('challenge_id') == f"dns-{site_id}-{str(c.get('issued_at', '')).replace('-', '').replace(':', '')}"
            and parse_utc(c.get('issued_at')) is not None and parse_utc(c.get('expires_at')) is not None)


def _live(real, site_id, host, now):
    c = _challenge(real)
    return c if c and _sane(c, site_id, host) and parse_utc(c['issued_at']) <= now < parse_utc(c['expires_at']) else None


def issue(site_root, now):
    """-> the challenge (a still valid one of this site and host is returned unchanged; an expired or foreign one is kept in the history and replaced)."""
    root, info, host = _site(site_root)
    real = root / 'real'
    live = _live(real, root.name, host, now)
    if live:
        return live
    if (real / CHALLENGE_FILE).exists():
        _keep(real / CHALLENGE_FILE, real / HISTORY, f"ownership-challenge-expired-{_safe((_challenge(real) or {}).get('challenge_id'))}.json")
    token = secrets.token_urlsafe(32)
    challenge = {'schema': CHALLENGE_SCHEMA, 'challenge_id': f"dns-{root.name}-{format_utc(now).replace('-', '').replace(':', '')}", 'site_id': root.name,
                 'host': host, 'record_name': record_name(host), 'token': token, 'record_value': record_value(root.name, token),
                 'issued_at': format_utc(now), 'expires_at': format_utc(now + timedelta(days=CHALLENGE_DAYS))}
    _write(real / CHALLENGE_FILE, challenge)
    return challenge


def _answers(name, lookup, record):
    """-> sorted TXT strings one lookup returned. Raises LookupFailed (also for an answer that is not a list of strings)."""
    got = lookup(record)
    if not isinstance(got, (list, tuple)) or not all(isinstance(a, str) for a in got) or len(got) > MAX_ANSWERS:
        raise LookupFailed('ERROR', f'{name}: 答えの形式が不正です')
    return sorted(got)


def _digest(answers):
    return hashlib.sha256(json.dumps(answers, ensure_ascii=False).encode('utf-8')).hexdigest()


def _foreign(answers, site_id):
    """TXT values that claim to be another site's SiteProof challenge."""
    return [a for a in answers if a.startswith(VALUE_PREFIX) and not a.startswith(f'{VALUE_PREFIX}{site_id};')]


def check(site_root, now, lookups):
    """The USER-run check. -> the evidence written. Raises OwnershipRefused (nothing is written) unless every lookup answered with exactly the issued value."""
    root, info, host = _site(site_root)
    real = root / 'real'
    c = _challenge(real)
    if c is None:
        raise OwnershipRefused('確認用の記録（チャレンジ）がありません。先に発行してください')
    if not _sane(c, root.name, host):
        raise OwnershipRefused('確認用の記録がこのサイト・このホストのものではありません。もう一度発行してください')
    if not parse_utc(c['issued_at']) <= now < parse_utc(c['expires_at']):
        raise OwnershipRefused('確認用の記録の有効期限（7日）が切れています。もう一度発行して、新しい値をDNSに登録してください')
    if not lookups:
        raise OwnershipRefused('DNSの問い合わせ先がありません')
    seen = []
    for name, lookup in lookups:
        try:
            answers = _answers(name, lookup, c['record_name'])
        except LookupFailed as exc:
            raise OwnershipRefused(f'{name}：DNSの問い合わせに失敗しました（{exc.code}）。記録を登録したか、反映を待ったか確認してください') from None
        if _foreign(answers, root.name):
            raise OwnershipRefused(f'{name}：他のサイトの確認用の値が同じ名前にあり、判断できません')
        if c['record_value'] not in answers:
            raise OwnershipRefused(f'{name}：{c["record_name"]} に、発行した値と完全に一致するTXTが見つかりません')
        seen.append({'resolver': str(name)[:80], 'answers': [a.replace(c['token'], '<token>')[:MAX_ANSWER_CHARS] for a in answers[:MAX_KEPT]],
                     'answers_sha256': _digest(answers)})
    evidence_id = c['challenge_id']
    evidence = {'schema': permits.DNS_EVIDENCE_SCHEMA, 'evidence_id': evidence_id, 'method': 'DNS_TXT_CHALLENGE', 'site_id': root.name, 'host': host,
                'record_name': c['record_name'], 'token_sha256': hashlib.sha256(c['token'].encode()).hexdigest(), 'checked_at': format_utc(now),
                'valid_until': format_utc(now + timedelta(days=permits.DNS_MAX_DAYS)), 'challenge_issued_at': c['issued_at'], 'challenge_expires_at': c['expires_at'],
                'checks': {'record_found': True, 'exact_value': True, 'all_answers_agree': True}, 'lookups': seen,
                'sources': ['DNS TXT lookups started by the USER (tools/dns_ownership.py); the token itself is not stored here']}
    current = real / permits.OWNERSHIP_EVIDENCE
    if current.exists():
        _keep(current, real / HISTORY, f"ownership-evidence-{_safe((_read(current) or {}).get('evidence_id'))}.json")
    _write(current, evidence)
    _keep(real / CHALLENGE_FILE, real / HISTORY, f'ownership-challenge-{evidence_id}.json')  # consumed: this token is never used again
    return evidence


def _token_of(real, evidence):
    """The token of an evidence file, from its consumed challenge in the history (found by SHA-256), or None."""
    for f in sorted((real / HISTORY).glob('ownership-challenge-*.json')) if (real / HISTORY).is_dir() else []:
        c = _read(f)
        if (c and c.get('schema') == CHALLENGE_SCHEMA and isinstance(c.get('token'), str) and c.get('site_id') == evidence.get('site_id')
                and hashlib.sha256(c['token'].encode()).hexdigest() == evidence.get('token_sha256') and c.get('challenge_id') == evidence.get('evidence_id')):
            return c
    return None


def recheck(site_root, now, lookups):
    """Look again at the record of the existing DNS evidence. -> {'status': OK | REVOKED | UNKNOWN | DISAGREE, 'detail': [...]}.
    Only a record that EVERY lookup definitively reports missing withdraws the evidence; a failed lookup never does; valid_until is never extended."""
    root, info, host = _site(site_root)
    real = root / 'real'
    ev = _read(real / permits.OWNERSHIP_EVIDENCE)
    if not ev or ev.get('schema') != permits.DNS_EVIDENCE_SCHEMA:
        raise OwnershipRefused('DNSの所有権確認の証拠がありません')
    if ev.get('site_id') != root.name or ev.get('host') != host or ev.get('record_name') != record_name(host):
        raise OwnershipRefused('証拠がこのサイト・このホストのものではありません')
    c = _token_of(real, ev)
    if c is None:
        raise OwnershipRefused('証拠に対応する確認用の記録が履歴にありません（再確認できません。もう一度発行してください）')
    if not lookups:
        raise OwnershipRefused('DNSの問い合わせ先がありません')
    detail = []
    for name, lookup in lookups:
        try:
            answers = _answers(name, lookup, ev['record_name'])
            found = 'ABSENT' if c['record_value'] not in answers else 'UNKNOWN' if _foreign(answers, root.name) else 'PRESENT'  # ambiguous is not "missing"
        except LookupFailed as exc:
            found = 'ABSENT' if exc.code == 'NXDOMAIN' else 'UNKNOWN'
        detail.append({'resolver': str(name)[:80], 'result': found})
    results = {d['result'] for d in detail}
    if results == {'PRESENT'}:
        return {'status': 'OK', 'detail': detail}
    if results == {'ABSENT'}:
        _write(real / permits.OWNERSHIP_REVOKED, {'evidence_id': ev['evidence_id'], 'at': format_utc(now), 'reason': 'record_missing_in_all_lookups',
                                                  'lookups': detail})
        return {'status': 'REVOKED', 'detail': detail}
    return {'status': 'DISAGREE' if results == {'PRESENT', 'ABSENT'} else 'UNKNOWN', 'detail': detail}


def _revoked(real, evidence_id):
    f = real / permits.OWNERSHIP_REVOKED
    if not f.exists():
        return False
    marker = _read(f)
    return marker is None or marker.get('evidence_id') == evidence_id  # present and unreadable counts as withdrawn (as permit.py)


def state(site_root, now):
    """What the screen shows. status VERIFIED only for evidence that is valid today; a challenge alone is never a confirmation."""
    root = Path(site_root).resolve()
    out = {'method': None, 'status': 'NONE', 'checked_at': None, 'valid_until': None, 'days_left': None, 'host': None, 'record_name': None,
           'record_value': None, 'expires_at': None, 'guidance': ''}
    try:
        _, info, host = _site(root)
    except OwnershipRefused as exc:
        return {**out, 'guidance': str(exc)}
    real = root / 'real'
    out['host'] = host
    ev = _read(real / permits.OWNERSHIP_EVIDENCE)
    if ev is not None and ev.get('schema') in METHODS.values():
        method = next(m for m, s in METHODS.items() if s == ev['schema'])
        checked = parse_utc(ev.get('checked_at'))
        until = parse_utc(ev.get('valid_until')) if method == 'DNS_TXT_CHALLENGE' else checked and checked + timedelta(days=permits.DNS_MAX_DAYS)
        mine = ev.get('host') == host and (method == 'CLOUDFLARE_ACCOUNT_CONTROL' or ev.get('site_id') == root.name)
        if checked and until and mine:
            out.update(method=method, checked_at=ev['checked_at'], valid_until=format_utc(until), days_left=round((until - now).total_seconds() / 86400, 1))
            if checked > now:
                out.update(status='NONE', guidance='確認日時が未来です。この証拠は使えません。')
            elif method == 'DNS_TXT_CHALLENGE' and _revoked(real, ev.get('evidence_id')):
                out.update(status='REVOKED', guidance='後の確認で、DNSの記録が見つかりませんでした。所有権の確認は取り消されています。もう一度確認してください。')
            elif until <= now:
                out.update(status='EXPIRED', guidance=f'所有権の確認は{permits.DNS_MAX_DAYS}日で期限切れになりました。もう一度確認してください。')
            else:
                out.update(status='VERIFIED', guidance=f'このホストの所有権を確認済みです（あと{out["days_left"]}日）。')
    live = _live(real, root.name, host, now)
    if live:
        out.update(record_name=live['record_name'], record_value=live['record_value'], expires_at=live['expires_at'])
        if out['status'] != 'VERIFIED':
            out.update(method='DNS_TXT_CHALLENGE', status='CHALLENGE', guidance=(
                f"DNSに、名前 {live['record_name']} のTXTレコードとして下の値を登録してください。登録しただけでは確認済みになりません。"
                '登録後に、利用者が別の操作（DNSの照会）で確認します。'))
    elif out['status'] == 'NONE' and (real / CHALLENGE_FILE).exists() and _challenge(real):
        out.update(method='DNS_TXT_CHALLENGE', status='EXPIRED', guidance='確認用の記録の有効期限（7日）が切れました。もう一度発行してください。')
    elif out['status'] == 'NONE' and not out['guidance']:
        out['guidance'] = 'まだ所有権を確認していません。「確認用の記録を発行」からDNS TXTレコードによる確認を始められます。'
    return out
