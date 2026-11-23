"""Kill only Popen children owned by each fixture; never a service/browser.

Checkpoints are injected in the child around REAL SQLite operations. The parent
kills that process, then reopens the preserved DB in a separate process. These
are process-termination tests, not power-loss/disk-durability attestations.
"""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from src.profile_context.sqlite_store import SQLiteContextStore
from src.profile_context.start_gate import request_simulated_start
from tests.profile_context.test_model import make_bundle


def _publish(path, payload):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _worker(root, operation, checkpoint, marker, go=None, bundle="first"):
    root = Path(root)
    store = SQLiteContextStore.open(root / "ledger.sqlite", root)
    entry = (make_bundle() if bundle == "first" else
             make_bundle(attempt="attempt-2", epoch=2, nonce="nonce-2", context_id="context-2"))

    def pause(name):
        if checkpoint == name:
            _publish(marker, {"checkpoint": name, "pid": os.getpid()})
            # Termination, not a cooperative Python exception/rollback.
            while True:
                time.sleep(0.05)

    real_connect, real_read = store._connect, store.read

    class ObservedConnection:
        def __init__(self, conn):
            self.conn = conn

        def __getattr__(self, name):
            return getattr(self.conn, name)

        def execute(self, statement, *args):
            result = self.conn.execute(statement, *args)
            if statement.startswith("INSERT INTO specs"):
                pause("register_after_spec")
            elif statement.startswith("INSERT INTO contexts"):
                pause("register_after_context")
            elif statement.startswith("INSERT INTO starts"):
                pause("reserve_after_insert")
            return result

        def commit(self):
            pause(operation + "_before_commit")
            self.conn.commit()
            pause(operation + "_after_commit")

    def connect(readonly, **kwargs):
        conn = real_connect(readonly, **kwargs)
        return conn if readonly else ObservedConnection(conn)

    def read(cid):
        pause(operation + "_before_readback")
        result = real_read(cid)
        pause(operation + "_after_readback")
        return result

    store._connect, store.read = connect, read
    if go:
        _publish(marker, {"checkpoint": "ready", "pid": os.getpid()})
        deadline = time.monotonic() + 15
        while not Path(go).exists():
            if time.monotonic() > deadline:
                raise TimeoutError("parent barrier was not released")
            time.sleep(0.01)
    if operation == "register":
        result = {"created": store.register(entry.spec, entry.context).created}
    elif checkpoint.startswith("reserve_"):
        # Isolate reservation checkpoints from the gate's idempotent register.
        result = {"status": "AUTHORIZED_SIMULATION",
                  "decision_id": store.reserve_simulated_start(entry.spec, entry.context)}
    else:
        decision = request_simulated_start(store, entry.spec, entry.context)
        result = {"status": decision.status.value, "reason": decision.reason,
                  "decision_id": decision.decision_id}
        pause("gate_after_decision")
    print(json.dumps(result), flush=True)


class ProcessCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-batch03-crash-A-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "ledger.sqlite"
        self.store = SQLiteContextStore.create(self.db, self.root)
        self.entry = make_bundle()
        self.children = []
        self.addCleanup(self._reap_children)

    def _reap_children(self):
        # Only process handles returned by this fixture's Popen are targeted.
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def spawn(self, operation, checkpoint="none", *, name="one", go=None, bundle="first"):
        marker = self.root / (name + ".json")
        args = [sys.executable, "-B", "-m", "tests.profile_context.test_process_crash",
                "--worker", str(self.root), operation, checkpoint, str(marker),
                str(go) if go else "-", bundle]
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        return child, marker

    def wait_checkpoint(self, child, marker, checkpoint):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if marker.exists():
                try:
                    data = json.loads(marker.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    pass  # A partially written signal never counts as ready.
                else:
                    self.assertEqual(data, {"checkpoint": checkpoint, "pid": child.pid})
                    self.assertIsNone(child.poll(), "child exited instead of waiting")
                    return
            if child.poll() is not None:
                self.fail(f"child exited before checkpoint: {child.communicate()!r}")
            time.sleep(0.01)
        self.fail("owned child did not reach deterministic checkpoint")

    def finish(self, child):
        stdout, stderr = child.communicate(timeout=20)
        self.assertEqual(child.returncode, 0, stderr)
        self.assertEqual(stderr, "")
        return json.loads(stdout)

    def restart(self, operation, *, name="restart", bundle="first"):
        child, _ = self.spawn(operation, name=name, bundle=bundle)
        return self.finish(child)

    def terminate_at(self, operation, checkpoint):
        child, marker = self.spawn(operation, checkpoint)
        self.wait_checkpoint(child, marker, checkpoint)
        child.kill()
        stdout, _ = child.communicate(timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(stdout, "", "no authorization reply before killed checkpoint")

    def rows(self, table):
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            return conn.execute("SELECT count(*) FROM " + table).fetchone()[0]

    def registration_crash(self, checkpoint, committed):
        self.terminate_at("register", checkpoint)
        outcome = self.restart("register")
        self.assertEqual(outcome["created"], not committed)
        self.assertEqual((self.rows("specs"), self.rows("contexts"), self.rows("starts")), (1, 1, 0))
        self.assertFalse(self.restart("register", name="duplicate")["created"])
        self.assertEqual(self.restart("reserve", name="start")["status"], "AUTHORIZED_SIMULATION")

    def reservation_crash(self, checkpoint, committed):
        self.store.register(self.entry.spec, self.entry.context)
        self.terminate_at("reserve", checkpoint)
        outcome = self.restart("reserve")
        self.assertEqual(outcome["status"], "UNKNOWN" if committed else "AUTHORIZED_SIMULATION")
        if committed:
            self.assertEqual(outcome["reason"], "START_ALREADY_RESERVED")
            self.assertIsNone(outcome["decision_id"])
        self.assertEqual(self.rows("starts"), 1)
        again = self.restart("reserve", name="duplicate")
        self.assertEqual(again["reason"], "START_ALREADY_RESERVED")

    def test_kill_during_registration_rolls_back_partial_spec(self):
        self.registration_crash("register_after_spec", False)

    def test_kill_after_context_insert_rolls_back_whole_registration(self):
        self.registration_crash("register_after_context", False)

    def test_kill_immediately_before_registration_commit(self):
        self.registration_crash("register_before_commit", False)

    def test_kill_immediately_after_registration_commit(self):
        self.registration_crash("register_after_commit", True)

    def test_kill_before_registration_readback(self):
        self.registration_crash("register_before_readback", True)

    def test_kill_after_registration_readback(self):
        self.registration_crash("register_after_readback", True)

    def test_kill_after_reservation_insert(self):
        self.reservation_crash("reserve_after_insert", False)

    def test_kill_immediately_before_reservation_commit(self):
        self.reservation_crash("reserve_before_commit", False)

    def test_kill_immediately_after_reservation_commit(self):
        self.reservation_crash("reserve_after_commit", True)

    def test_kill_before_reservation_readback(self):
        self.reservation_crash("reserve_before_readback", True)

    def test_kill_after_reservation_readback(self):
        self.reservation_crash("reserve_after_readback", True)

    def test_kill_after_gate_decision_before_response(self):
        self.reservation_crash("gate_after_decision", True)

    def test_restart_preserves_old_epoch_rejection_and_new_attempt(self):
        self.assertEqual(self.restart("reserve")["status"], "AUTHORIZED_SIMULATION")
        self.assertEqual(self.restart("reserve", name="new", bundle="second")["status"], "AUTHORIZED_SIMULATION")
        self.assertEqual(self.restart("reserve", name="old")["reason"], "STALE_EPOCH")
        self.assertEqual(self.rows("starts"), 2)

    def test_restart_preserves_nonce_and_attempt_uniqueness(self):
        self.restart("register")
        reopened = SQLiteContextStore.open(self.db, self.root)
        from src.profile_context.sqlite_store import StoreError, StoreReason
        for nonce, attempt in (("nonce-1", "attempt-2"), ("nonce-2", "attempt-1")):
            entry = make_bundle(attempt=attempt, epoch=2, nonce=nonce, context_id="other")
            with self.subTest(nonce=nonce), self.assertRaises(StoreError) as caught:
                reopened.register(entry.spec, entry.context)
            self.assertIs(caught.exception.reason, StoreReason.CONFLICT)
        self.assertEqual(self.rows("contexts"), 1)

    def concurrent(self, operation):
        go = self.root / "go"
        a, ma = self.spawn(operation, name="a", go=go)
        b, mb = self.spawn(operation, name="b", go=go)
        self.wait_checkpoint(a, ma, "ready")
        self.wait_checkpoint(b, mb, "ready")
        go.write_text("release owned children", encoding="utf-8")
        return self.finish(a), self.finish(b)

    def test_two_process_exact_registration_is_idempotent(self):
        results = self.concurrent("register")
        self.assertEqual(sorted(r["created"] for r in results), [False, True])
        self.assertEqual(self.rows("contexts"), 1)

    def test_two_process_reservation_grants_exactly_once(self):
        self.store.register(self.entry.spec, self.entry.context)
        results = self.concurrent("reserve")
        self.assertEqual(sorted(r["status"] for r in results), ["AUTHORIZED_SIMULATION", "UNKNOWN"])
        self.assertEqual(self.rows("starts"), 1)
        self.assertEqual(self.restart("reserve", name="after-race")["reason"], "START_ALREADY_RESERVED")


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--worker":
    _worker(*sys.argv[2:6], go=None if sys.argv[6] == "-" else sys.argv[6], bundle=sys.argv[7])
