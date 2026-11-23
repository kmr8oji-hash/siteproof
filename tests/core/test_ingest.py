import dataclasses
import unittest

from src.core.errors import FrameRejected, StreamIncomplete
from src.core.frames import CheckType, FrameKind, StreamSummary, Termination
from src.core.ingest import IngestLimits, verify_frame, verify_stream
from src.core.model import AttemptRef, JobIntent, JobSnapshot
from src.core.synthetic import make_frame, make_summary

K = FrameKind


def snapshot(checks=(CheckType.HTTP, CheckType.CAPTURE)):
    return JobSnapshot("job-1", JobIntent("https://example.invalid/", "page-1", "desktop",
                                          checks, "base-1"), "2026-01-01T00:00:00+00:00")


ATT = AttemptRef("job-1", "att-1", 3)


def frame(seq=0, kind=K.HTTP_RECORD, **kw):
    args = dict(job_id="job-1", attempt_id="att-1", lease_epoch=3, seq=seq, kind=kind,
                page_id="page-1", profile_id="desktop")
    args.update(kw)
    return make_frame(**args)


class FrameVerificationTests(unittest.TestCase):
    def reject(self, f, code, snap=None):
        with self.assertRaises(FrameRejected) as cm:
            verify_frame(f, snap or snapshot(), ATT)
        self.assertEqual(cm.exception.code, code)

    def test_valid_frame_passes(self):
        verify_frame(frame(), snapshot(), ATT)
        verify_frame(frame(1, K.SCREENSHOT_PNG), snapshot(), ATT)

    def test_each_mismatch_is_rejected(self):
        base = frame()
        r = dataclasses.replace
        self.reject(r(base, schema_version="siteproof.bridge.v9"), "SCHEMA_VERSION")
        self.reject(r(base, provenance="trusted"), "PROVENANCE")
        self.reject(r(base, job_id="job-2"), "JOB_MISMATCH")
        self.reject(r(base, attempt_id="att-9"), "ATTEMPT_MISMATCH")
        self.reject(r(base, lease_epoch=2), "LEASE_EPOCH_MISMATCH")
        self.reject(r(base, check_type=CheckType.LOAD), "KIND_CHECK_MISMATCH")
        self.reject(r(base, page_id="page-2"), "PAGE_MISMATCH")
        self.reject(r(base, profile_id="mobile"), "PROFILE_MISMATCH")
        self.reject(r(base, byte_length=base.byte_length + 1), "LENGTH_MISMATCH")
        self.reject(r(base, sha256="0" * 64), "HASH_MISMATCH")
        self.reject(r(base, payload=bytearray(base.payload)), "TYPE_ERROR")
        self.reject(r(base, seq=True), "TYPE_ERROR")

    def test_check_not_in_required_checks_is_rejected(self):
        self.reject(frame(kind=K.LOAD_RECORD), "CHECK_NOT_REQUIRED")

    def test_png_signature_is_checked(self):
        self.reject(frame(kind=K.SCREENSHOT_PNG, payload=b"not a png"), "PNG_SIGNATURE")

    def test_frame_size_limit(self):
        with self.assertRaises(FrameRejected) as cm:
            verify_frame(frame(payload=b"x" * 11), snapshot(), ATT, IngestLimits(max_frame_bytes=10))
        self.assertEqual(cm.exception.code, "OVERSIZE")


class StreamVerificationTests(unittest.TestCase):
    def frames(self):
        return [frame(0, K.HTTP_RECORD), frame(1, K.CAPTURE_RECORD), frame(2, K.SCREENSHOT_PNG)]

    def test_clean_stream_passes(self):
        fs = self.frames()
        self.assertEqual(len(verify_stream(fs, make_summary(fs), snapshot(), ATT)), 3)

    def test_non_clean_terminations_are_never_accepted(self):
        fs = self.frames()
        for t in (Termination.TRUNCATED, Termination.TIMEOUT, Termination.OVERSIZE,
                  Termination.PROTOCOL_ERROR):
            with self.assertRaises(StreamIncomplete) as cm:
                verify_stream(fs, make_summary(fs, t), snapshot(), ATT)
            self.assertEqual(cm.exception.termination, t.value)

    def test_count_and_total_mismatch(self):
        fs = self.frames()
        good = make_summary(fs)
        with self.assertRaises(StreamIncomplete) as cm:
            verify_stream(fs[:2], good, snapshot(), ATT)
        self.assertEqual(cm.exception.code, "FRAME_COUNT_MISMATCH")
        with self.assertRaises(StreamIncomplete) as cm:
            verify_stream(fs, StreamSummary(Termination.CLEAN, 3, good.total_payload_bytes + 1),
                          snapshot(), ATT)
        self.assertEqual(cm.exception.code, "TOTAL_BYTES_MISMATCH")

    def test_duplicate_check_kind_slot_is_rejected(self):
        a, b = frame(0, K.HTTP_RECORD), frame(1, K.HTTP_RECORD, payload=b"other")
        with self.assertRaises(FrameRejected) as cm:
            verify_stream([a, b], make_summary([a, b]), snapshot(), ATT)
        self.assertEqual(cm.exception.code, "DUPLICATE_FRAME")

    def test_one_bad_frame_poisons_the_stream(self):
        fs = self.frames()
        fs[1] = dataclasses.replace(fs[1], sha256="f" * 64)
        with self.assertRaises(FrameRejected) as cm:
            verify_stream(fs, make_summary(fs), snapshot(), ATT)
        self.assertEqual(cm.exception.code, "HASH_MISMATCH")


class SummaryValidationTests(unittest.TestCase):
    """PF-02: summary counts must be real non-negative ints, even when they compare equal."""

    def check(self, summary, frames):
        with self.assertRaises(StreamIncomplete) as cm:
            verify_stream(frames, summary, snapshot(), ATT)
        self.assertEqual(cm.exception.code, "SUMMARY_INVALID", summary)

    def test_bool_and_float_counts_that_equal_the_real_values_are_rejected(self):
        one = [frame(0)]
        total = one[0].byte_length
        self.check(StreamSummary(Termination.CLEAN, True, total), one)      # True == 1
        self.check(StreamSummary(Termination.CLEAN, 1.0, total), one)       # 1.0 == 1
        self.check(StreamSummary(Termination.CLEAN, 1, float(total)), one)
        self.check(StreamSummary(Termination.CLEAN, 1, True), [frame(0, payload=b"x")])
        self.check(StreamSummary(Termination.CLEAN, False, 0), [])          # False == 0
        self.check(StreamSummary(Termination.CLEAN, 0, False), [])

    def test_negative_non_numeric_and_missing_counts_are_rejected(self):
        one = [frame(0)]
        total = one[0].byte_length
        self.check(StreamSummary(Termination.CLEAN, -1, total), one)
        self.check(StreamSummary(Termination.CLEAN, 1, -total), one)
        self.check(StreamSummary(Termination.CLEAN, "1", total), one)
        self.check(StreamSummary(Termination.CLEAN, 1, str(total)), one)
        self.check(StreamSummary(Termination.CLEAN, None, total), one)
        self.check(StreamSummary(Termination.CLEAN, 1, None), one)

    def test_invalid_counts_are_rejected_before_the_termination_is_interpreted(self):
        self.check(StreamSummary(Termination.TIMEOUT, True, 0), [])

    def test_summary_that_is_not_a_summary_is_rejected(self):
        self.check(object(), [frame(0)])
        self.check(StreamSummary("CLEAN", 1, frame(0).byte_length), [frame(0)])

    def test_valid_zero_and_exact_counts_are_still_accepted(self):
        self.assertEqual(verify_stream([], StreamSummary(Termination.CLEAN, 0, 0),
                                       snapshot(), ATT), ())
        fs = [frame(0), frame(1, K.CAPTURE_RECORD)]
        self.assertEqual(len(verify_stream(fs, make_summary(fs), snapshot(), ATT)), 2)


class SeqContiguityTests(unittest.TestCase):
    """INT-02: seq must be exactly 0,1,2,... even when count and byte totals agree."""

    def verify(self, seqs, kinds=(K.HTTP_RECORD, K.CAPTURE_RECORD, K.SCREENSHOT_PNG)):
        fs = [frame(sq, kinds[i]) for i, sq in enumerate(seqs)]
        return verify_stream(fs, make_summary(fs), snapshot(), ATT)

    def assert_rejected(self, seqs, code="SEQ_NOT_CONTIGUOUS"):
        with self.assertRaises(FrameRejected) as cm:
            self.verify(seqs)
        self.assertEqual(cm.exception.code, code, seqs)

    def test_non_zero_start_is_rejected(self):
        self.assert_rejected([5])
        self.assert_rejected([1, 2, 3])

    def test_gap_duplicate_and_reorder_are_rejected(self):
        self.assert_rejected([0, 2])
        self.assert_rejected([0, 1, 3])
        self.assert_rejected([0, 0])
        self.assert_rejected([0, 1, 1])
        self.assert_rejected([1, 0])
        self.assert_rejected([2, 1, 0])

    def test_negative_and_bad_types_are_rejected(self):
        self.assert_rejected([-1], "TYPE_ERROR")
        fs = [dataclasses.replace(frame(0), seq=True)]
        with self.assertRaises(FrameRejected) as cm:
            verify_stream(fs, make_summary(fs), snapshot(), ATT)
        self.assertEqual(cm.exception.code, "TYPE_ERROR")
        fs = [dataclasses.replace(frame(0), seq=0.0)]
        with self.assertRaises(FrameRejected) as cm:
            verify_stream(fs, make_summary(fs), snapshot(), ATT)
        self.assertEqual(cm.exception.code, "TYPE_ERROR")

    def test_contiguous_streams_are_accepted(self):
        self.assertEqual(len(self.verify([0])), 1)
        self.assertEqual(len(self.verify([0, 1, 2])), 3)


if __name__ == "__main__":
    unittest.main()
