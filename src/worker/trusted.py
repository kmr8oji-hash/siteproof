"""Trusted pipe supervisor and S1 handoff. No browser observations are attested.

Deadlines bound waiting on a source, not arbitrary Python/OS calls. A blocked reader
or close can outlive the wait: cleanup=False must be reported and the isolated
launcher must kill its process group. No detached work is reported as success.
"""
import queue
import threading
import time

from src.core.model import JobStatus
from src.core.rules import is_terminal
from src.isolation.frames import FrameLimits


class WireBudget:
    """One shared IPC byte ceiling for all page/profile children of a batch."""
    def __init__(self, limit):
        self.remaining = limit
        self.lock = threading.Lock()

    def charge(self, count):
        with self.lock:
            if count > self.remaining:
                raise OSError('JOB_OUTPUT_LIMIT')
            self.remaining -= count


class DeadlineSource:
    def __init__(self, source, seconds, cancel=None, on_cancel=None, budget=None):
        self.source, self.cancel = source, cancel
        self.on_cancel = on_cancel
        self.budget = budget
        self.deadline = time.monotonic() + seconds
        self.requests, self.answers = queue.Queue(1), queue.Queue(1)
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._reader, daemon=True,
                                       name='siteproof-evidence-reader')
        self.thread.start()

    def _reader(self):
        try:
            while True:
                size = self.requests.get()
                if size is None:
                    return
                try:
                    value = self.source.read(size)
                    if type(value) is not bytes or len(value) > size:
                        raise OSError('INVALID_SOURCE')
                    result = (True, value)
                except Exception:
                    result = (False, b'')
                self.answers.put(result)
        finally:
            self.stopped.set()

    def read(self, size):
        if self.cancel is not None and self.cancel.is_set():
            if self.on_cancel:
                self.on_cancel()
            raise OSError('CANCELLED')
        if size <= 0:
            return b''
        self.requests.put_nowait(size)
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            if self.cancel is not None and self.cancel.is_set():
                if self.on_cancel:
                    self.on_cancel()
                raise OSError('CANCELLED')
            try:
                ok, value = self.answers.get(timeout=min(.02, remaining))
                if not ok:
                    raise OSError('SOURCE_FAILED')
                if self.budget is not None:
                    self.budget.charge(len(value))
                return value
            except queue.Empty:
                continue

    def close(self, seconds):
        # Close itself can block too. Preserve that uncertainty in the return value.
        result = []
        def close_source():
            try:
                self.source.close()
                result.append(True)
            except Exception:
                pass
        closer = threading.Thread(target=close_source, daemon=True,
                                  name='siteproof-evidence-close')
        closer.start()
        try:
            self.requests.put_nowait(None)
        except queue.Full:
            pass
        deadline = time.monotonic() + seconds
        closer.join(max(0, deadline - time.monotonic()))
        self.thread.join(max(0, deadline - time.monotonic()))
        return bool(result) and not closer.is_alive() and not self.thread.is_alive()


class TrustedWorker:
    def __init__(self, bridge, *, frame_limits=None, cleanup_seconds=1):
        self.bridge = bridge
        self.frame_limits = frame_limits or FrameLimits()
        if type(cleanup_seconds) not in (int, float) or not 0 < cleanup_seconds <= 60:
            raise ValueError('bounded cleanup required')
        self.cleanup_seconds = cleanup_seconds

    def ingest(self, job_id, attempt_id, source, *, cancel=None, seconds=None, byte_budget=None):
        """Channel contains bytes only; no browser-specified paths/DB/identities."""
        repo = self.bridge.finalizer.repo
        bounded = DeadlineSource(source, min(seconds, self.frame_limits.timeout_seconds)
                                 if seconds is not None else self.frame_limits.timeout_seconds,
                                 cancel, lambda: repo.cancel(job_id), byte_budget)
        result, cleanup = None, False
        try:
            if cancel is not None and cancel.is_set():
                repo.cancel(job_id)
            else:
                result = self.bridge.finalize(job_id, attempt_id, bounded,
                                              limits=self.frame_limits)
        finally:
            cleanup = bounded.close(self.cleanup_seconds)
        return result, cleanup

    def fail(self, job_id, attempt, reason):
        repo = self.bridge.finalizer.repo
        job = repo.get_job(job_id)
        if is_terminal(job.status):
            return job
        status = JobStatus.TIMED_OUT if reason.endswith('_TIMEOUT') else JobStatus.FAILED_EXECUTION
        return repo.transition(job_id, job.version, status, reason, expected_attempt=attempt)
