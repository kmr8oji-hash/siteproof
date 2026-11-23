"""Browser-side request audit: what the page's own browser context says failed to load.

A CONNECT proxy cannot see inside an allowed tunnel, so a TLS certificate error or an HTTP error on a
sub-resource is invisible to it. The browser knows. Playwright reports every request of the page's context
(never the browser's own background traffic, which uses a different route), so this collector listens there.

Trust: the report comes from the untrusted producer. It is used only to push a verdict DOWN to UNKNOWN; its
absence, malformation or incompleteness also means UNKNOWN, and "nothing failed" never raises a verdict or
vouches for the rendering. The trusted side re-validates the whole shape and recomputes every derived field.

Privacy: only scheme, host, port, resource type, an error token and a count are kept. Never a path, query,
header, cookie or credential. The collector holds no permission over what the page may connect to.

Uncaught page script errors (`weberror`) are counted by error class name only (`TypeError`), never the message or stack.
Audits recorded before this field existed simply lack it: that reads as "not recorded", never as zero errors.
"""
import re
import threading
from urllib.parse import urlsplit


SCHEMA = 'siteproof.browser-audit.v1'
SOURCE = 'BROWSER_SELF_REPORT'
MAX_ENTRIES = 64
TLS_CLASS, LOAD_CLASS = 'TLS_VALIDATION_FAILED', 'RESOURCE_LOAD_FAILED'
_ERROR = re.compile(r'(?:net::)?(ERR_[A-Z0-9_]{1,60})')
_HOST = re.compile(r'[a-z0-9.\-]{1,253}\Z')
_TYPE = re.compile(r'[a-z]{1,24}\Z')
_SCRIPT_ERROR = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}\Z')
SCRIPT_CLASS = 'PAGE_SCRIPT_ERROR'
_TLS_PREFIXES = ('ERR_CERT_', 'ERR_SSL_', 'ERR_BAD_SSL_', 'ERR_CONNECTION_REFUSED_SSL', 'ERR_SECURITY')


def classify(error):
    """Error token -> verdict class. Certificate / TLS errors are their own class; everything else is a load failure."""
    return TLS_CLASS if type(error) is str and error.startswith(_TLS_PREFIXES) else LOAD_CLASS


def error_token(text):
    found = _ERROR.search(text) if type(text) is str else None
    return found.group(1) if found else 'ERR_UNKNOWN'


def _origin(url):
    """scheme, hostname, port only. Anything unparsable is recorded without a host rather than guessed."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
        scheme = parts.scheme if parts.scheme in ('http', 'https') else 'other'
        port = parts.port or {'http': 80, 'https': 443}.get(scheme)
    except (ValueError, AttributeError, TypeError):
        return 'other', None, None
    return scheme, (host if _HOST.match(host) else None), port


def _resource_type(request):
    value = getattr(request, 'resource_type', None)
    return value if type(value) is str and _TYPE.match(value) else 'unknown'


class RequestAuditCollector:
    """Attach before the first navigation; call `summary(final=True)` while the context is still open."""

    def __init__(self):
        self._lock = threading.Lock()
        self.monitor = 'NOT_ATTACHED'
        self.requests = self.finished = 0
        self._pending = set()
        self._failures, self._http_errors, self._script_errors = {}, {}, {}
        self.dropped = self.handler_errors = 0
        self.finalized = False

    def attach(self, context):
        try:
            context.on('request', self._guard(self._on_request))
            context.on('requestfinished', self._guard(self._on_finished))
            context.on('requestfailed', self._guard(self._on_failed))
            context.on('response', self._guard(self._on_response))
            context.on('weberror', self._guard(self._on_script_error))
        except Exception:
            self.monitor = 'FAILED'
            return False
        self.monitor = 'ATTACHED'
        return True

    def _guard(self, handler):
        def run(item):
            try:
                handler(item)
            except Exception:
                with self._lock:
                    self.handler_errors += 1  # A missed event makes the audit incomplete, never silently smaller.
        return run

    def _on_request(self, request):
        with self._lock:
            self.requests += 1
            self._pending.add(id(request))

    def _on_finished(self, request):
        with self._lock:
            self.finished += 1
            self._pending.discard(id(request))

    def _on_failed(self, request):
        scheme, host, port = _origin(getattr(request, 'url', ''))
        error = error_token(getattr(request, 'failure', None))
        key = (_resource_type(request), scheme, host, port, error, bool(request.is_navigation_request()))
        with self._lock:
            self._pending.discard(id(request))
            self._add(self._failures, key)

    def _on_response(self, response):
        status = response.status
        if type(status) is int and status >= 400:
            scheme, host, port = _origin(getattr(response, 'url', ''))
            with self._lock:
                self._add(self._http_errors, (_resource_type(response.request), scheme, host, port, status))

    def _on_script_error(self, web_error):
        name = getattr(getattr(web_error, 'error', None), 'name', None)
        with self._lock:
            self._add(self._script_errors, name if type(name) is str and _SCRIPT_ERROR.match(name) else 'Error')

    def _add(self, table, key):
        if key in table or len(table) < MAX_ENTRIES:
            table[key] = table.get(key, 0) + 1
        else:
            self.dropped += 1

    def summary(self, final=False):
        with self._lock:
            if final:
                self.finalized = True
            failures = [{'resource_type': t, 'scheme': s, 'host': h, 'port': p, 'error': e, 'class': classify(e),
                         'navigation': n, 'count': c} for (t, s, h, p, e, n), c in sorted(self._failures.items(), key=str)]
            errors = [{'resource_type': t, 'scheme': s, 'host': h, 'port': p, 'status': st, 'count': c}
                      for (t, s, h, p, st), c in sorted(self._http_errors.items(), key=str)]
            scripts = [{'name': n, 'count': c} for n, c in sorted(self._script_errors.items())]
            report = {'schema': SCHEMA, 'source': SOURCE, 'monitor': self.monitor, 'finalized': self.finalized,
                      'requests': self.requests, 'finished': self.finished, 'pending': len(self._pending),
                      'dropped': self.dropped, 'handler_errors': self.handler_errors,
                      'failed': sum(f['count'] for f in failures), 'http_errors': sum(e['count'] for e in errors),
                      'failures': failures, 'http_error_entries': errors,
                      'script_errors': sum(s['count'] for s in scripts), 'script_error_entries': scripts}
        report['complete'] = _complete(report)
        return report


def _complete(report):
    return (report['monitor'] == 'ATTACHED' and report['finalized'] is True and report['requests'] >= 1
            and report['dropped'] == 0 and report['handler_errors'] == 0 and report['pending'] == 0)


def unavailable(reason):
    """Explicit marker: the producer could not (or did not) deliver an audit. Never an empty one."""
    return {'schema': SCHEMA, 'source': 'UNAVAILABLE', 'reason': reason}


def check_browser_audit(report):
    """Strict re-validation on the trusted side. Returns a rebuilt, sanitized dict, or None if anything is off.

    Nothing is trusted: counts, the class of every failure and `complete` are recomputed from the entries.
    """
    try:
        if type(report) is not dict or report.get('schema') != SCHEMA or report.get('source') != SOURCE:
            return None
        ints = {k: report[k] for k in ('requests', 'finished', 'pending', 'dropped', 'handler_errors')}
        if (any(type(v) is not int or v < 0 or v > 10**7 for v in ints.values()) or report.get('monitor') not in ('ATTACHED', 'FAILED', 'NOT_ATTACHED')
                or type(report.get('finalized')) is not bool):
            return None
        failures, errors = report['failures'], report['http_error_entries']
        if type(failures) is not list or type(errors) is not list or len(failures) > MAX_ENTRIES or len(errors) > MAX_ENTRIES:
            return None
        clean_failures, clean_errors = [], []
        for f in failures:
            error = f['error']
            if (type(f) is not dict or type(f['count']) is not int or not 0 < f['count'] <= 10**7 or not _ERROR.fullmatch(error)
                    or not _TYPE.match(f['resource_type']) or f['scheme'] not in ('http', 'https', 'other')
                    or not (f['host'] is None or _HOST.match(f['host'])) or not (f['port'] is None or 0 < f['port'] < 65536)
                    or type(f['navigation']) is not bool):
                return None
            clean_failures.append({k: f[k] for k in ('resource_type', 'scheme', 'host', 'port', 'error', 'navigation', 'count')}
                                  | {'class': classify(error)})
        for e in errors:
            if (type(e) is not dict or type(e['count']) is not int or not 0 < e['count'] <= 10**7
                    or type(e['status']) is not int or not 400 <= e['status'] <= 599 or not _TYPE.match(e['resource_type'])
                    or e['scheme'] not in ('http', 'https', 'other') or not (e['host'] is None or _HOST.match(e['host']))
                    or not (e['port'] is None or 0 < e['port'] < 65536)):
                return None
            clean_errors.append({k: e[k] for k in ('resource_type', 'scheme', 'host', 'port', 'status', 'count')})
        clean = {'schema': SCHEMA, 'source': SOURCE, 'monitor': report['monitor'], 'finalized': report['finalized'], **ints,
                 'failed': sum(f['count'] for f in clean_failures), 'http_errors': sum(e['count'] for e in clean_errors),
                 'failures': clean_failures, 'http_error_entries': clean_errors}
        if 'script_error_entries' in report or 'script_errors' in report:  # absent in audits recorded before the field existed
            scripts = report['script_error_entries']
            if type(scripts) is not list or len(scripts) > MAX_ENTRIES:
                return None
            clean_scripts = []
            for s in scripts:
                if (type(s) is not dict or type(s['count']) is not int or not 0 < s['count'] <= 10**7
                        or type(s['name']) is not str or not _SCRIPT_ERROR.match(s['name'])):
                    return None
                clean_scripts.append({'name': s['name'], 'count': s['count']})
            clean.update(script_errors=sum(s['count'] for s in clean_scripts), script_error_entries=clean_scripts)
        clean['complete'] = _complete(clean)
        return clean
    except (KeyError, TypeError, AttributeError, re.error):
        return None


def audit_problems(audit, prefix=''):
    """Verdict reasons from a (validated) browser audit. Anything unusable is a reason, never a pass."""
    if audit is None:
        return [prefix + 'BROWSER_AUDIT_UNAVAILABLE']
    if type(audit) is dict and audit.get('source') == 'UNAVAILABLE':
        return [prefix + 'BROWSER_AUDIT_UNAVAILABLE']
    clean = check_browser_audit(audit)  # Every field below is recomputed, none is taken from the stored dict.
    if clean is None:
        return [prefix + 'BROWSER_AUDIT_INVALID']
    problems = []
    if not clean['complete']:
        problems.append(prefix + 'BROWSER_AUDIT_INCOMPLETE')
    if any(f['class'] == TLS_CLASS for f in clean['failures']):
        problems.append(prefix + TLS_CLASS)
    if any(f['class'] == LOAD_CLASS for f in clean['failures']) or clean['http_errors']:
        problems.append(prefix + LOAD_CLASS)
    if clean.get('script_errors'):
        problems.append(prefix + SCRIPT_CLASS)
    return problems
