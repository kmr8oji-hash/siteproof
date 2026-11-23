"""Bounded, privacy-minimal ledger of CONNECT attempts seen by the trusted proxy.

Only the proxy can observe this: the browser's own reports are never used. A CONNECT
proxy sees host:port, not URLs or resource types, so a record carries the validated
hostname, port, decision and a fixed reason code only. Query strings, paths, credentials
and cookies never reach this module, and an unvalidated authority is recorded with no host.

Every attempt is kept as an ordered record (sequence + monotonic time); nothing is dropped
for being "uninteresting". A window is split by one trusted fact only: a page subresource
cannot be requested before the page's own document, so records ordered before the first
ALLOWed connection to the job's own target authority are the "prelude" (browser start and
sandbox self-check). Prelude records are retained and reported separately, never ignored by
host name. Anything at or after that connection counts as the job. If the bound is exceeded
or a record fails, the window is incomplete rather than silently shortened. Absence of a
ledger is not "0 blocked".
"""
import re
import threading
import time


SCHEMA = 'siteproof.network-audit.v2'
SOURCE = 'TRUSTED_CONNECT_PROXY'
MAX_RECORDS = 2048
MAX_TIMELINE = 256
DECISIONS = ('ALLOW', 'BLOCK', 'FAILED', 'IDLE')
_REASON = re.compile(r'[A-Z0-9_]{1,48}\Z')
_HOST = re.compile(r'[a-z0-9.-]{1,253}\Z')


def _aggregate(records):
    counts = {}
    for _, _, host, port, decision, reason in records:
        key = (host, port, decision, reason)
        counts[key] = counts.get(key, 0) + 1
    entries = [{'host': h, 'port': p, 'decision': d, 'reason': r, 'count': n}
               for (h, p, d, r), n in sorted(counts.items(), key=lambda i: tuple(map(str, i[0])))]
    totals = {d: sum(e['count'] for e in entries if e['decision'] == d) for d in DECISIONS}
    return entries, totals


class ConnectLedger:
    def __init__(self, max_records=MAX_RECORDS):
        if type(max_records) is not int or max_records <= 0:
            raise ValueError('positive record bound required')
        self.max_records = max_records
        self._lock = threading.Lock()
        self._records = []
        self._seq = 0
        self._in_flight = 0
        self._dropped = 0
        self._lost = 0

    def begin(self):
        with self._lock:
            self._in_flight += 1

    def record(self, host, port, decision, reason, *, began=True):
        """Exactly one call per CONNECT attempt. Never raises into the proxy."""
        try:
            if decision not in DECISIONS:
                raise ValueError(decision)
            if not (type(reason) is str and _REASON.match(reason)):
                reason = 'UNKNOWN'
            if not (type(host) is str and _HOST.match(host)):
                host = None
            if not (type(port) is int and 0 < port < 65536):
                port = None
            with self._lock:
                if began:
                    self._in_flight = max(0, self._in_flight - 1)
                if len(self._records) < self.max_records:
                    self._seq += 1
                    self._records.append((self._seq, time.monotonic(), host, port, decision, reason))
                else:
                    self._dropped += 1
        except Exception:
            with self._lock:
                self._lost += 1

    def mark(self):
        with self._lock:
            return (self._seq, self._dropped, self._lost)

    def window(self, mark, anchor=None):
        """Audit for everything recorded since `mark` (taken before the capture).

        `anchor` is the job's own (host, port), from the trusted job intent. Top-level counts and
        entries cover the job (from the anchor's first ALLOW on); `prelude` covers what came
        before it. Without an anchor connection nothing is split off: all of it counts as the job.
        """
        seq0, dropped0, lost0 = mark
        with self._lock:
            records = [r for r in self._records if r[0] > seq0]
            dropped, lost, in_flight = self._dropped - dropped0, self._lost - lost0, self._in_flight
        boundary = None
        if anchor is not None:
            boundary = next((r[0] for r in records if r[4] == 'ALLOW' and (r[2], r[3]) == tuple(anchor)), None)
        before = [r for r in records if boundary is not None and r[0] < boundary]
        job = [r for r in records if not (boundary is not None and r[0] < boundary)]
        entries, total = _aggregate(job)
        pre_entries, pre_total = _aggregate(before)
        return {'schema': SCHEMA, 'source': SOURCE, 'resource_types': 'NOT_OBSERVABLE',
                'complete': dropped == 0 and lost == 0 and in_flight == 0,
                'allowed': total['ALLOW'], 'blocked': total['BLOCK'], 'failed': total['FAILED'], 'idle': total['IDLE'],
                'dropped': dropped + lost, 'in_flight': in_flight, 'entries': entries,
                'anchor': {'host': anchor[0] if anchor else None, 'port': anchor[1] if anchor else None,
                           'seen': boundary is not None},
                'prelude': {'allowed': pre_total['ALLOW'], 'blocked': pre_total['BLOCK'], 'failed': pre_total['FAILED'],
                            'idle': pre_total['IDLE'], 'entries': pre_entries},
                # Ordered, bounded, host/port/decision/reason only; seconds are relative to the first record.
                't0_monotonic': round(records[0][1], 3) if records else None,
                'timeline': [[r[0], round(r[1] - records[0][1], 3), r[2], r[3], r[4], r[5]]
                             for r in records[:MAX_TIMELINE]]}


def unavailable(reason):
    """Explicit marker when no trusted ledger exists. Never reads as an empty audit."""
    return {'schema': SCHEMA, 'source': 'UNAVAILABLE', 'resource_types': 'NOT_OBSERVABLE',
            'complete': False, 'reason': reason, 'entries': []}
