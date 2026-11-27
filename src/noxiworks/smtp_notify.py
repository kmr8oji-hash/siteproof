"""E-mail (SMTP) provider for SiteProof notices, behind a signed grant, a kill switch and a message ledger. Verification and sending only: this module never signs.

Layers, each of which must say yes before a byte leaves the PC:
  1. NOTIFY_EXTERNAL_ENABLED (False in the source): refused with ExternalDisabled before any name lookup, connection, credential read or ledger write.
  2. The grant <data>/notify/notify-grant.json + .sig (schema siteproof.notify-grant.v1): SSHSIG by the USER's own trusted key (permit.verify_signature, trust file
     <data>/trust/allowed_signers). It pins ONE server (host, port 465 TLS or 587 STARTTLS), the sender, 1..5 recipients, the name of the Windows credential, the
     period (<= 366 days) and the message limits. It is a different schema from the HTTP grant and the image permit: none of them is accepted for another.
     The caller verifies it freshly before EVERY send (verify_grant); only the screen may use cached_grant_view (<= 60 s old) and only to show it.
  3. The ledger <data>/trust/notify-ledger/<grant_id>.jsonl: every connection attempt is counted (fsync) BEFORE it is made; refused at the total or rolling
     24 h limit, at an unreadable line, or when the clock went back more than 5 minutes (fail closed). A DNS lookup is not a message and is not counted.
Transport: bounded name resolution (5 s), the whole answer set checked by src/isolation/destination.check_destination, ONE connection to the first approved
address (IPv4 first), the peer compared with it, then smtplib on that very socket (smtplib never resolves anything itself), TLS 1.2+, certificate and host name
checked against the granted host, STARTTLS mandatory for 587; nothing (no login, no mail) is sent before TLS is up. Overall deadline 30 s, enforced by a
watchdog that shuts the connection down (socket timeouts alone bound each read, not their sum): TEMPORARY 'TIMEOUT' before DATA, UNCERTAIN once DATA has started.
The credential (user, password) is read from the Windows Credential Manager only at send time, kept in memory only for that call, never written, logged or put into
an exception text; every failure is reduced to a fixed reason code.

Results: ACCEPTED (the server took the message for all recipients) / PARTIAL (some recipients refused; not resent) / REJECTED (5xx; not retried) / TEMPORARY
(4xx or a connection / DNS / TLS failure before DATA; retry allowed) / UNCERTAIN (failure once DATA had started: it may have been sent, so it is never resent) /
REFUSED (nothing was sent: grant, ledger, kill switch, credential, destination). ACCEPTED means the server accepted the message, never that anyone received it.
Limits: a local administrator can edit the ledger or the trust file; the isolation of the real transport at OS / network level is not claimed here.
"""
from collections import namedtuple
from datetime import timedelta
import email.policy
import email.utils
from email.message import EmailMessage
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time

from src.aws_b.model import format_utc, parse_utc
from src.isolation.destination import AllowedDestination, DestinationPolicy, check_authority, check_destination
from src.noxiworks import filelock, notifications
from src.noxiworks import permit as permits

NOTIFY_EXTERNAL_ENABLED = False  # the kill switch: no mail leaves this PC until it is turned on, deliberately, after the boundary is measured and the USER approved
GRANT_SCHEMA = 'siteproof.notify-grant.v1'
LOCAL_HOSTNAME = 'siteproof.local'  # what EHLO says: never the name of this PC
RESOLVE_TIMEOUT = 5
CONNECT_TIMEOUT = 10
DEADLINE_SECONDS = 30
LEDGER_WAIT_SECONDS = 15
CLOCK_BACK = timedelta(minutes=5)
MAX_GRANT_DAYS = 366
SECURITY = {465: 'TLS', 587: 'STARTTLS'}
_ID_RE = re.compile(r'notify-[A-Za-z0-9._-]{1,57}\Z')
_REF_RE = re.compile(r'SiteProof-SMTP-[A-Za-z0-9._-]{1,40}\Z')
_LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_ADDR_RE = re.compile(r'[A-Za-z0-9._+-]{1,64}@(?:' + _LABEL + r'\.)+' + _LABEL, re.ASCII)
_SAFE_RE = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
SendResult = namedtuple('SendResult', 'result reason')
FOOTER = ['', '--', 'このメールは、あなたのPC上で動くSiteProofアプリ（PC版）から送られました。',
          '※ 「送信受付」はメールサーバーが受け付けたという意味で、受信（メールボックスへの到着）を保証しません。迷惑メールのフォルダも確認してください。',
          '※ 送信できなかったときの再送は最大3回までです。結果が不明のときは、同じ通知が重なって届かないよう再送しません。']
DROP_LINES = ('SNS', '次回の監視実行で再送')  # lines of the AWS-B texts that describe SNS behaviour: wrong for this channel


class ExternalDisabled(RuntimeError):
    pass


class LedgerRefused(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class CredentialError(Exception):
    pass


# ---- the signed grant
def valid_address(value):
    if type(value) is not str or len(value) > 254 or not _ADDR_RE.fullmatch(value):
        return False
    local = value.split('@')[0]
    return not (local.startswith('.') or local.endswith('.') or '..' in local)


def host_problem(host, port):
    """-> None, or why this server may not be a destination (public DNS name, exact host and port, not an internal-looking name)."""
    from src.noxiworks.site_workflow import BLOCKED_HOSTS
    if type(host) is not str or type(port) is not int:
        return 'INVALID'
    decision = check_authority(DestinationPolicy((AllowedDestination(host, port),)), host, port)
    if not decision.allowed:
        return decision.reason
    if host != host.lower() or host.endswith(BLOCKED_HOSTS) or host in BLOCKED_HOSTS or '.' not in host:
        return 'INTERNAL_NAME'
    return None


def mask_address(value):
    local, _, domain = str(value).partition('@')
    return local[:1] + '***@' + domain


def shape_problems(grant):
    """Everything the signature does not decide by itself except the period. -> list of Japanese problems."""
    if not isinstance(grant, dict) or grant.get('schema') != GRANT_SCHEMA:
        return ['通知許可の形式が違います（HTTP監視・画像撮影の許可は使えません）']
    problems = []
    if not isinstance(grant.get('grant_id'), str) or not _ID_RE.fullmatch(grant['grant_id']):
        problems.append('通知許可のID（notify- で始まる英数字）が不正です')
    if parse_utc(grant.get('issued_at') or '') is None:
        problems.append('発行日時（issued_at）が不正です')
    smtp = grant.get('smtp')
    if not isinstance(smtp, dict):
        problems.append('メールサーバーの指定がありません')
    else:
        host, port, security = smtp.get('host'), smtp.get('port'), smtp.get('security')
        if type(port) is not int or port not in SECURITY:
            problems.append('メールサーバーのポートは 465（TLS）か 587（STARTTLS）だけです')
        elif security != SECURITY[port]:
            problems.append('ポートと暗号化方式が合っていません（465はTLS、587はSTARTTLS）')
        why = host_problem(host, port if type(port) is int else 0)
        if why:
            problems.append('メールサーバーのホストを使えません（' + why + '）')
    if not valid_address(grant.get('sender')):
        problems.append('送信元のメールアドレスが不正です')
    recipients = grant.get('recipients')
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 5 or not all(valid_address(r) for r in recipients) or len(set(recipients)) != len(recipients):
        problems.append('宛先は、正しいメールアドレス1〜5件（重複なし）で指定してください')
    if not isinstance(grant.get('credential_ref'), str) or not _REF_RE.fullmatch(grant['credential_ref']):
        problems.append('資格情報の名前（SiteProof-SMTP-…）が不正です')
    for name, high in (('max_messages_total', 10000), ('max_messages_per_day', 200)):
        if type(grant.get(name)) is not int or not 1 <= grant[name] <= high:
            problems.append(f'{name} は 1〜{high} の整数にしてください')
    start, end = parse_utc(grant.get('valid_from') or ''), parse_utc(grant.get('valid_until') or '')
    if not (start and end) or not timedelta(0) < end - start <= timedelta(days=MAX_GRANT_DAYS):
        problems.append('有効期間が不正です（最大366日）')
    return problems


def period_problems(grant, now):
    start, end = parse_utc(grant.get('valid_from') or ''), parse_utc(grant.get('valid_until') or '')
    return [] if start and end and start <= now < end else ['通知許可が有効期間外です']


def load_grant(data):
    """Signature and shape, verified now. -> (grant or None, problems). The period is not looked at here."""
    f, trust = Path(data) / 'notify' / 'notify-grant.json', Path(data) / 'trust' / 'allowed_signers'
    try:
        grant = permits.verify_signature(f, trust)
    except permits.PermitRefused as exc:
        why = str(exc).replace('real/permit.json と permit.json.sig', 'notify-grant.json と notify-grant.json.sig').replace('監視許可', '通知許可')  # permit.py's words, for this file
        return None, ['通知許可がありません：' + why]
    except (OSError, subprocess.SubprocessError) as exc:
        return None, ['通知許可を検証できません：' + type(exc).__name__]
    problems = shape_problems(grant)
    return (None, problems) if problems else (grant, [])


def verify_grant(data, now):
    """The check before EVERY send (never cached). -> (grant or None, problems)."""
    grant, problems = load_grant(data)
    if grant is None:
        return None, problems
    problems = period_problems(grant, now)
    return (None, problems) if problems else (grant, [])


_VIEW = {}  # (data, file stamps) -> (monotonic time, result): the screen asks every few seconds; ssh-keygen runs at most once a minute


def cached_grant_view(data, now, ttl=60):
    """FOR DISPLAY ONLY (<= ttl s old signature check; the period is always judged against `now`). -> (grant or None, problems)."""
    root = Path(data)
    stamp = tuple((f.stat().st_mtime_ns, f.stat().st_size) if f.is_file() else None
                  for f in (root / 'notify' / 'notify-grant.json', root / 'notify' / 'notify-grant.json.sig', root / 'trust' / 'allowed_signers'))
    key = (str(root), stamp)
    hit = _VIEW.get(key)
    if hit is None or time.monotonic() - hit[0] > ttl:
        if len(_VIEW) > 32:
            _VIEW.clear()
        hit = _VIEW[key] = (time.monotonic(), load_grant(data))
    grant, problems = hit[1]
    if grant is None:
        return None, list(problems)
    problems = period_problems(grant, now)
    return (None, problems) if problems else (grant, [])


# ---- the ledger
def ledger_file(data, grant_id):
    if not isinstance(grant_id, str) or not _ID_RE.fullmatch(grant_id):
        raise LedgerRefused('GRANT_ID_INVALID')
    return Path(data) / 'trust' / 'notify-ledger' / (grant_id + '.jsonl')


def _ledger_times(f):
    if not f.is_file():
        return []
    try:
        lines = f.read_bytes().decode('utf-8').split('\n')
    except UnicodeDecodeError:
        raise LedgerRefused('LEDGER_CORRUPT') from None
    if lines[-1] == '':  # the normal end: every line closed by a newline
        lines.pop()
    times = []
    for line in lines:  # a blank line or a torn last line is not parsable: refused, never repaired
        try:
            at = parse_utc(json.loads(line)['at'])
        except (ValueError, KeyError, TypeError):
            at = None
        if at is None:
            raise LedgerRefused('LEDGER_CORRUPT')
        times.append(at)
    return times


def ledger_usage(data, grant, now):
    """-> {'total', 'today', 'remaining_total', 'remaining_today'}; LedgerRefused when the ledger cannot be trusted."""
    times = _ledger_times(ledger_file(data, grant['grant_id']))
    today = sum(1 for t in times if t > now - timedelta(hours=24))
    return {'total': len(times), 'today': today, 'remaining_total': max(0, grant['max_messages_total'] - len(times)),
            'remaining_today': max(0, min(grant['max_messages_per_day'] - today, grant['max_messages_total'] - len(times)))}


def reserve(data, grant, now, ref):
    """Count one attempt BEFORE it is made, atomically (OS lock). -> the number of attempts counted including this one; LedgerRefused otherwise."""
    f = ledger_file(data, grant['grant_id'])
    f.parent.mkdir(parents=True, exist_ok=True)
    try:
        with filelock.held(f.with_suffix('.lock'), LEDGER_WAIT_SECONDS):
            times = _ledger_times(f)
            if times and now < times[-1] - CLOCK_BACK:
                raise LedgerRefused('CLOCK_WENT_BACK')
            if len(times) >= grant['max_messages_total']:
                raise LedgerRefused('LIMIT_TOTAL')
            if sum(1 for t in times if t > now - timedelta(hours=24)) >= grant['max_messages_per_day']:
                raise LedgerRefused('LIMIT_DAILY')
            notifications.append_jsonl(f, {'at': format_utc(now), 'ref': str(ref)[:64]}, sync=True)
            return len(times) + 1
    except filelock.LockBusy:
        raise LedgerRefused('LEDGER_BUSY') from None
    except OSError:
        raise LedgerRefused('LEDGER_UNWRITABLE') from None


# ---- the credential (Windows Credential Manager, generic credential; read only, never written, never logged)
def read_credential(ref):
    """-> (user, password). Only at send time. CredentialError (a fixed code, nothing from the store) when it cannot be read."""
    if not isinstance(ref, str) or not _REF_RE.fullmatch(ref):
        raise CredentialError('REF_INVALID')
    if sys.platform != 'win32':
        raise CredentialError('NOT_WINDOWS')
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD), ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
                    ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD), ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)),
                    ('Persist', wintypes.DWORD), ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p), ('TargetAlias', wintypes.LPWSTR),
                    ('UserName', wintypes.LPWSTR)]
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    advapi.CredReadW.restype = wintypes.BOOL
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    pointer = ctypes.POINTER(CREDENTIAL)()
    if not advapi.CredReadW(ref, 1, 0, ctypes.byref(pointer)):  # 1 = CRED_TYPE_GENERIC
        raise CredentialError('NOT_FOUND')
    try:
        cred = pointer.contents
        user = cred.UserName or ''
        blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize) if cred.CredentialBlobSize else b''
    finally:
        advapi.CredFree(pointer)
    try:
        password = blob.decode('utf-16-le') if len(blob) % 2 == 0 and b'\x00' in blob else blob.decode('utf-8')
    except UnicodeDecodeError:
        raise CredentialError('UNREADABLE') from None
    if not user or not password:
        raise CredentialError('INCOMPLETE')
    return user, password


# ---- the message
def clean_subject(text):
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(text or '')).strip()
    return (re.sub(r' {2,}', ' ', text) or '[SiteProof] 通知')[:150]


def mail_body(body):
    """The notice body without the AWS-B lines about SNS, plus the SiteProof footer."""
    lines = [x for x in str(body or '').split('\n') if not (x.startswith('※') and any(d in x for d in DROP_LINES))]  # only the note lines: a host named "sns" stays
    while lines and not lines[-1].strip():
        lines.pop()
    return '\n'.join(lines + FOOTER) + '\n'


def build_message(grant, *, notice_id, site_id, subject, body, now):
    """From / To exactly as granted; Message-ID stable for (notice, site) so a mail client can see a duplicate."""
    if not (_SAFE_RE.fullmatch(str(notice_id)) and _SAFE_RE.fullmatch(str(site_id))):
        raise ValueError('id')
    msg = EmailMessage()
    msg['From'] = grant['sender']
    msg['To'] = ', '.join(grant['recipients'])
    msg['Subject'] = clean_subject(subject)
    msg['Date'] = email.utils.format_datetime(now)
    msg['Message-ID'] = f'<{notice_id}.{site_id}@{LOCAL_HOSTNAME}>'
    msg.set_content(mail_body(body), charset='utf-8', cte='base64')
    return msg


# ---- the transport
def _bounded(fn, timeout, *args):
    box = {}

    def run():
        try:
            box['v'] = fn(*args)
        except BaseException as exc:  # handed to the caller, never lost
            box['e'] = exc
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError('resolve')
    if 'e' in box:
        raise box['e']
    return box['v']


def _system_resolver(host, port):
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def _connect(ip, port, timeout):
    if not ipaddress.ip_address(ip).is_global:  # second line of defence behind check_destination
        raise OSError('not a public address')
    return socket.create_connection((ip, port), timeout)


class _OneAuth:
    """Log in with ONE mechanism (PLAIN, else LOGIN; the session is already TLS). smtplib.login tries the next mechanism after a refusal: a server that hangs up
    after the first refusal (Gmail does) then looked like a lost connection -- TEMPORARY, retried, again and again against the account -- instead of the refused
    login it is (SMTPAuthenticationError -> AUTH_FAILED, final). Seen in the real acceptance test of 2026-11-27."""

    def login(self, user, password, *, initial_response_ok=True):
        self.ehlo_or_helo_if_needed()
        if not self.has_extn('auth'):
            raise smtplib.SMTPNotSupportedError('AUTH')
        offered = self.esmtp_features['auth'].upper().split()
        method = next((m for m in ('PLAIN', 'LOGIN') if m in offered), None)
        if method is None:
            raise smtplib.SMTPNotSupportedError('AUTH')
        self.user, self.password = user, password
        return self.auth(method, getattr(self, 'auth_' + method.lower()), initial_response_ok=initial_response_ok)


class _Pinned(_OneAuth, smtplib.SMTP):
    """smtplib on a socket that was already connected to the approved address: it never resolves or connects by itself."""

    def __init__(self, sock, host, port, local_hostname, timeout):
        self._pre = sock
        super().__init__(host, port, local_hostname, timeout)

    def _get_socket(self, host, port, timeout):
        sock, self._pre = self._pre, None
        if sock is None:
            raise OSError('socket already used')
        return sock


class _PinnedSSL(_OneAuth, smtplib.SMTP_SSL):
    def __init__(self, sock, host, port, local_hostname, timeout, context):
        self._pre = sock
        super().__init__(host, port, local_hostname, timeout=timeout, context=context)

    def _get_socket(self, host, port, timeout):
        sock, self._pre = self._pre, None
        if sock is None:
            raise OSError('socket already used')
        return self.context.wrap_socket(sock, server_hostname=self._host)  # self._host is the granted host name


def _make_smtp(security, host, port, sock, context, local_hostname, timeout):
    if security == 'TLS':
        return _PinnedSSL(sock, host, port, local_hostname, timeout, context)
    return _Pinned(sock, host, port, local_hostname, timeout)


def _by_code(code, tag):
    """A definite server reply -> SendResult. 4xx may be retried, everything else is final."""
    if 400 <= code < 500:
        return SendResult('TEMPORARY', f'{tag}_4XX')
    if 500 <= code < 600:
        return SendResult('REJECTED', f'{tag}_5XX')
    return SendResult('TEMPORARY', f'{tag}_UNEXPECTED')


def _failure(exc):
    """An exception before DATA -> SendResult. Fixed codes only: never the exception text (a server reply may quote a credential)."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return SendResult('TEMPORARY', 'TLS_CERT_INVALID')
    if isinstance(exc, ssl.SSLError):
        return SendResult('TEMPORARY', 'TLS_FAILED')
    if isinstance(exc, TimeoutError):
        return SendResult('TEMPORARY', 'TIMEOUT')
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return SendResult('TEMPORARY', 'DISCONNECTED')
    if isinstance(exc, smtplib.SMTPResponseException):
        return _by_code(exc.smtp_code, 'SMTP')
    if isinstance(exc, smtplib.SMTPException):
        return SendResult('TEMPORARY', 'SMTP_ERROR')
    if isinstance(exc, OSError):
        return SendResult('TEMPORARY', 'NETWORK_ERROR')
    return SendResult('TEMPORARY', 'INTERNAL_ERROR')


class _Watchdog:
    """The hard end of a session: socket timeouts bound each read, a drip-feeding server could stretch their sum. At the deadline the connection is shut down
    (the CURRENT socket: smtp.sock once TLS wrapped it, the raw one and a dup of it otherwise -- wrap_socket detaches the original), so whatever read is
    waiting fails at once. `fired` tells the session that this was the deadline."""

    def __init__(self, seconds, sock):
        self.sock, self.smtp, self.fired = sock, None, threading.Event()
        try:
            self.dup = sock.dup()  # shares the connection with the socket that TLS will take over
        except Exception:
            self.dup = None
        self.timer = threading.Timer(seconds, self.stop)
        self.timer.daemon = True
        self.timer.start()

    def stop(self):
        self.fired.set()
        for target in (getattr(self.smtp, 'sock', None), self.dup, self.sock):
            try:
                target.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    def cancel(self):
        self.timer.cancel()
        try:
            self.dup.close()
        except Exception:
            pass


class SmtpProvider:
    def __init__(self, resolver=None, connector=None, credentials=None, smtp_factory=None, clock=time.monotonic):
        """All four are injectable for tests / rehearsals; the defaults are the real ones (still behind the kill switch)."""
        self.resolver, self.connector = resolver or _system_resolver, connector or _connect
        self.credentials, self.smtp_factory, self.clock = credentials or read_credential, smtp_factory or _make_smtp, clock

    def can_send(self):
        return NOTIFY_EXTERNAL_ENABLED is True

    def send(self, grant, data, message, now):
        """`grant` was verified by the caller just now (verify_grant). -> SendResult; raises ExternalDisabled while the kill switch is off."""
        if NOTIFY_EXTERNAL_ENABLED is not True:
            raise ExternalDisabled('メール通知の外部通信は無効です')
        cfg = grant.get('smtp') or {}
        host, port, security = cfg.get('host'), cfg.get('port'), cfg.get('security')
        if SECURITY.get(port) != security:
            return SendResult('REFUSED', 'PORT_SECURITY_MISMATCH')
        if host_problem(host, port):
            return SendResult('REFUSED', 'HOST_NOT_ALLOWED')
        try:
            user, password = self.credentials(grant['credential_ref'])
            if not (isinstance(user, str) and isinstance(password, str) and user and password):
                raise CredentialError('INCOMPLETE')
        except Exception:  # whatever the store said stays out of every record
            return SendResult('REFUSED', 'CREDENTIAL_UNAVAILABLE')
        try:
            answers = _bounded(self.resolver, RESOLVE_TIMEOUT, host, port)
        except TimeoutError:
            return SendResult('TEMPORARY', 'DNS_TIMEOUT')
        except Exception:
            return SendResult('TEMPORARY', 'DNS_FAILED')
        decision = check_destination(DestinationPolicy((AllowedDestination(host, port),)), host, port, list(answers) if isinstance(answers, (list, tuple)) else [])
        if not decision.allowed:
            return SendResult('REFUSED', 'DESTINATION_' + decision.reason)
        ip = sorted(decision.addresses, key=lambda a: ipaddress.ip_address(a).version)[0]
        try:
            reserve(data, grant, now, str(message['Message-ID']))
        except LedgerRefused as exc:
            return SendResult('REFUSED', exc.reason)
        deadline = self.clock() + DEADLINE_SECONDS
        try:
            sock = self.connector(ip, port, min(CONNECT_TIMEOUT, DEADLINE_SECONDS))
        except TimeoutError:
            return SendResult('TEMPORARY', 'CONNECT_TIMEOUT')
        except Exception:
            return SendResult('TEMPORARY', 'CONNECT_FAILED')
        try:
            try:
                peer = sock.getpeername()
                same = ipaddress.ip_address(peer[0]) == ipaddress.ip_address(ip) and peer[1] == port
            except Exception:
                same = False
            if not same:
                return SendResult('REFUSED', 'PEER_MISMATCH')
            watchdog = _Watchdog(max(0.0, deadline - self.clock()), sock)
            try:
                return self._session(grant, user, password, message, sock, host, port, security, deadline, watchdog)
            finally:
                watchdog.cancel()
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _session(self, grant, user, password, message, sock, host, port, security, deadline, watchdog):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        timeout = max(1, deadline - self.clock())

        def failure(exc):  # before DATA: whatever the exception looks like after the watchdog cut the connection, it was the deadline
            return SendResult('TEMPORARY', 'TIMEOUT') if watchdog.fired.is_set() else _failure(exc)

        def arm(smtp):
            if self.clock() > deadline:
                raise TimeoutError('deadline')
            try:
                smtp.sock.settimeout(max(0.5, deadline - self.clock()))
            except Exception:
                pass
        smtp = None
        try:
            smtp = self.smtp_factory(security, host, port, sock, context, LOCAL_HOSTNAME, timeout)
            watchdog.smtp = smtp
            try:
                if security == 'STARTTLS':
                    arm(smtp)
                    smtp.ehlo(LOCAL_HOSTNAME)
                    if not smtp.has_extn('starttls'):
                        return SendResult('REFUSED', 'STARTTLS_NOT_OFFERED')  # never log in or send in the clear
                    code = smtp.starttls(context=context)[0]
                    if code != 220:
                        return SendResult('REFUSED', 'STARTTLS_FAILED')
                    smtp.ehlo(LOCAL_HOSTNAME)
                arm(smtp)
                try:
                    smtp.login(user, password)
                except smtplib.SMTPAuthenticationError as exc:
                    return SendResult('TEMPORARY', 'AUTH_TEMPORARY') if 400 <= exc.smtp_code < 500 else SendResult('REFUSED', 'AUTH_FAILED')
                except smtplib.SMTPNotSupportedError:
                    return SendResult('REFUSED', 'AUTH_NOT_SUPPORTED')
                arm(smtp)
                code = smtp.mail(grant['sender'])[0]
                if code != 250:
                    return _by_code(code, 'MAIL')
                accepted, refused = 0, []
                for recipient in grant['recipients']:
                    arm(smtp)
                    code = smtp.rcpt(recipient)[0]
                    if code in (250, 251):
                        accepted += 1
                    else:
                        refused.append(code)
                if not accepted:
                    return SendResult('TEMPORARY', 'RCPT_4XX') if any(400 <= c < 500 for c in refused) else SendResult('REJECTED', 'RCPT_5XX')
            except Exception as exc:
                return failure(exc)
            try:
                arm(smtp)
            except Exception as exc:
                return failure(exc)
            try:  # from here on the message may be on its way: nothing is sent again whatever happens
                code = smtp.data(message.as_bytes(policy=email.policy.SMTP))[0]
            except smtplib.SMTPDataError as exc:
                return _by_code(exc.smtp_code, 'DATA')  # the server refused DATA itself: nothing was transmitted
            except Exception:
                return SendResult('UNCERTAIN', 'DATA_INTERRUPTED')
            if 200 <= code < 300:
                return SendResult('PARTIAL', 'SOME_RECIPIENTS_REFUSED') if refused else SendResult('ACCEPTED', 'SMTP_%d' % code)
            return _by_code(code, 'DATA') if 400 <= code < 600 else SendResult('UNCERTAIN', 'DATA_REPLY_UNKNOWN')
        except Exception as exc:  # construction: greeting, TLS handshake
            return failure(exc)
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass
                try:
                    smtp.close()
                except Exception:
                    pass


class MockSmtpProvider:
    """Rehearsals / tests: scripted results, messages recorded in a local file. Proves the hand-over only: nothing leaves the PC, nothing is ever received."""

    def __init__(self, path=None, script=()):
        self.path, self.script, self.calls = Path(path) if path else None, list(script), []

    def can_send(self):
        return True

    def send(self, grant, data, message, now):
        try:
            if data is not None:
                reserve(data, grant, now, str(message['Message-ID']))
        except LedgerRefused as exc:
            return SendResult('REFUSED', exc.reason)
        record = {'message_id': message['Message-ID'], 'from': message['From'], 'to': message['To'], 'subject': message['Subject'], 'body': message.get_content()}
        self.calls.append(record)
        if self.path:
            notifications.append_jsonl(self.path, record)
        item = self.script.pop(0) if self.script else 'ACCEPTED'
        if isinstance(item, BaseException):
            raise item
        return item if isinstance(item, SendResult) else SendResult(item, 'MOCK')
