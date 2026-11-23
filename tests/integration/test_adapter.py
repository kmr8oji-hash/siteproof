"""INT-07 nominal conversion, derived from isolation/INTERFACE.md and core/ingest.py."""

from dataclasses import fields, replace
import io
import unittest

from src.bridge import AdapterError, EvidenceBridge, adapt_stream
from src.core.frames import CheckType, FrameKind, Termination
from src.isolation import frames as s0
from tests.integration.fixtures import complete, stream


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.result = s0.FrameReader(io.BytesIO(stream(complete())),
                                     s0.TrustedContext("job-1", "attempt-1", 1)).read()

    def test_every_frame_and_summary_field_preserved(self):
        converted = adapt_stream(self.result)
        self.assertEqual(len(fields(s0.VerifiedFrame)), 13)
        self.assertEqual(len(fields(s0.StreamSummary)), 3)
        for original, mapped in zip(self.result.frames, converted.frames, strict=True):
            for field in fields(original):
                self.assertEqual(getattr(mapped, field.name), getattr(original, field.name))
            self.assertIs(type(mapped.kind), FrameKind)
            self.assertIs(type(mapped.check_type), CheckType)
            self.assertIs(mapped.payload, original.payload)
        self.assertIs(type(converted.summary.termination), Termination)
        for field in fields(self.result.summary):
            self.assertEqual(getattr(converted.summary, field.name),
                             getattr(self.result.summary, field.name))

    def test_all_terminations_and_incorrect_counts_preserved(self):
        for termination in Termination:
            with self.subTest(termination=termination):
                summary = s0.StreamSummary(termination.value, -7, 1234567)
                mapped = adapt_stream(replace(self.result, summary=summary)).summary
                self.assertIs(mapped.termination, termination)
                self.assertEqual((mapped.frame_count, mapped.total_payload_bytes), (-7, 1234567))

    def test_incorrect_evidence_is_never_repaired(self):
        changes = dict(schema_version="wrong", job_id="other", attempt_id="old", lease_epoch=0,
                       seq=99, page_id="other-page", profile_id="other-profile",
                       check_type="CAPTURE", byte_length=-1, sha256="bad", payload=b"changed",
                       provenance="wrong")
        original = replace(self.result.frames[0], **changes)
        mapped = adapt_stream(replace(self.result, frames=(original,))).frames[0]
        for key, value in changes.items():
            self.assertEqual(getattr(mapped, key), value)

    def test_frame_order_and_duplicates_not_changed(self):
        frames = (self.result.frames[2], self.result.frames[0], self.result.frames[0])
        mapped = adapt_stream(replace(self.result, frames=frames)).frames
        self.assertEqual([f.seq for f in mapped], [2, 0, 0])

    def test_incompatible_frame_fields_rejected(self):
        bad = dict(schema_version=1, job_id=None, attempt_id=1, lease_epoch=True, seq=False,
                   kind="END", page_id=[], profile_id={}, check_type="OTHER", byte_length=True,
                   sha256=b"hash", payload=bytearray(b"x"), provenance=None)
        for key, value in bad.items():
            with self.subTest(field=key), self.assertRaises(AdapterError):
                frame = replace(self.result.frames[0], **{key: value})
                adapt_stream(replace(self.result, frames=(frame,)))

    def test_incompatible_wrapper_and_summary_rejected(self):
        bad = [None, {}, replace(self.result, frames=list(self.result.frames)),
               replace(self.result, frames=({},)), replace(self.result, summary=None),
               replace(self.result, reason=None)]
        for changes in (dict(termination="OTHER"), dict(termination=None),
                        dict(termination=Termination.CLEAN), dict(frame_count=True),
                        dict(frame_count=1.0), dict(total_payload_bytes=False)):
            bad.append(replace(self.result, summary=replace(self.result.summary, **changes)))
        for value in bad:
            with self.subTest(value=value), self.assertRaises(AdapterError):
                adapt_stream(value)

    def test_bridge_requires_real_finalizer(self):
        with self.assertRaises(AdapterError):
            EvidenceBridge(object())
