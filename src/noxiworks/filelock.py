"""One exclusive lock between processes AND threads, held by the operating system (msvcrt.locking / fcntl.flock) on one byte of a file.

Unlike an O_EXCL marker file there is nothing to go stale: the OS releases it when the holder closes the file or dies, so no process ever has
to guess whether a lock is left over (and two processes can never both "take over" the same one). The file itself stays on disk and means
nothing by existing. Used for what must never run twice at once: an HTTP check, a settings change, a mail dispatch, a real capture.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import time

if os.name == 'nt':
    import msvcrt
else:
    import fcntl

POLL_SECONDS = 0.02


class LockBusy(Exception):
    pass


def _try(fd):
    try:
        if os.name == 'nt':
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _release(fd):
    try:
        if os.name == 'nt':
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


@contextmanager
def held(path, wait=0.0):
    """Hold the lock for the block; LockBusy when another holder keeps it longer than `wait` seconds."""
    fd = os.open(Path(path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_BINARY', 0), 0o600)
    deadline = time.monotonic() + wait
    while not _try(fd):
        if time.monotonic() >= deadline:
            os.close(fd)
            raise LockBusy(str(path))
        time.sleep(POLL_SECONDS)
    try:
        yield
    finally:
        _release(fd)


def is_held(path):
    """Is someone holding it right now? (For display only: it may change at once.)"""
    if not Path(path).is_file():
        return False
    try:
        with held(path):
            return False
    except (LockBusy, OSError):
        return True
