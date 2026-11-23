"""Batch 02 S0 boundary tests only: no S1, adapter, files or network."""

import binascii
from dataclasses import replace
import hashlib
import io
import json
import struct
import unittest
import zlib

from src.isolation.frames import (
    CONTRACT_VERSION, PROVENANCE, FrameLimits, FrameReader, TrustedContext,
)
from wire_fixtures import end, header, packet, png_1x1


def record_bytes(record_type, observation):
    # Deliberately noncanonical formatting and UTF-8: transport must preserve it.
    doc = {"observation": observation, "record_type": record_type,
           "schema_version": "siteproof.record.v0.1"}
    return ("\n" + json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def data_frame(seq, kind, payload, **claims):
    return packet(header(seq, kind, len(payload), **claims), payload)


class ConnectionBoundaryTests(unittest.TestCase):
    def setUp(self):
        # A synthetic canonical-context shape, not an imported S1 AttemptRef.
        self.context = TrustedContext("job-001", "attempt-001", 1)
        self.http = record_bytes("HTTP", {
            "state": "OBSERVED", "status_code": 200, "reason_code": "HTTP_200"})
        self.capture = record_bytes("CAPTURE", {
            "capture_state": "SUCCEEDED", "comparison_state": "BASELINE_PENDING",
            "reason_code": "BASELINE_NOT_SET"})
        self.image = png_1x1()

    def read(self, data, limits=None):
        return FrameReader(io.BytesIO(data), self.context, limits).read()

    def capture_prefix(self):
        return (data_frame(0, "CAPTURE_RECORD", self.capture)
                + data_frame(1, "SCREENSHOT_PNG", self.image))

    def assert_summary(self, result, termination, payloads):
        self.assertEqual(result.summary.termination, termination, result.reason)
        self.assertEqual(result.summary.frame_count, len(payloads))
        self.assertEqual(result.summary.total_payload_bytes, sum(map(len, payloads)))
        self.assertEqual([f.payload for f in result.frames], list(payloads))

    def test_connection_context_and_contiguous_data_summary(self):
        load = record_bytes("LOAD", {"state": "SUCCEEDED", "reason_code": "LOAD_OK"})
        kinds = ("HTTP_RECORD", "LOAD_RECORD", "CAPTURE_RECORD", "SCREENSHOT_PNG")
        payloads = (self.http, load, self.capture, self.image)
        wire = b"".join(data_frame(i, kind, payload)
                        for i, (kind, payload) in enumerate(zip(kinds, payloads))) + end(4)
        for epoch in (1, 7, 99):
            with self.subTest(epoch=epoch):
                context = TrustedContext("job-001", "attempt-001", epoch)
                out = FrameReader(io.BytesIO(wire), context).read()
                self.assert_summary(out, "CLEAN", payloads)
                self.assertEqual([f.seq for f in out.frames], [0, 1, 2, 3])
                self.assertEqual([f.kind for f in out.frames], list(kinds))
                self.assertEqual([f.check_type for f in out.frames],
                                 ["HTTP", "LOAD", "CAPTURE", "CAPTURE"])
                self.assertEqual(out.reason, "COMPLETE_END")
                for f in out.frames:
                    self.assertEqual((f.job_id, f.attempt_id, f.lease_epoch),
                                     (context.job_id, context.attempt_id, epoch))
                    self.assertEqual((f.page_id, f.profile_id), ("page-1", "profile-1"))
                    self.assertEqual(f.schema_version, CONTRACT_VERSION)
                    self.assertEqual(f.provenance, PROVENANCE)
                    self.assertEqual((f.byte_length, f.sha256),
                                     (len(f.payload), hashlib.sha256(f.payload).hexdigest()))

    def test_general_utf8_ids_and_epoch_zero_are_not_narrowed(self):
        context = TrustedContext("一般ジョブ", "試行 / fixture", 0)
        wire = data_frame(0, "HTTP_RECORD", self.http,
                          page_id="ページ", profile_id="設定") + end(1)
        out = FrameReader(io.BytesIO(wire), context).read()
        self.assert_summary(out, "CLEAN", [self.http])
        f = out.frames[0]
        self.assertEqual((f.job_id, f.attempt_id, f.lease_epoch),
                         (context.job_id, context.attempt_id, 0))
        self.assertEqual((f.page_id, f.profile_id), ("ページ", "設定"))

    def test_http_load_capture_record_json_bytes_are_not_changed(self):
        cases = [("HTTP", {"state": "OBSERVED", "status_code": status,
                           "reason_code": f"HTTP_{status}"})
                 for status in (100, 199, 200, 299, 300, 399, 400, 599)]
        cases += [("HTTP", {"state": state, "reason_code": "未観測"})
                  for state in ("UNKNOWN", "SKIPPED")]
        cases += [("LOAD", {"state": state, "reason_code": "LOAD_FIXTURE"})
                  for state in ("SUCCEEDED", "FAILED", "UNKNOWN", "SKIPPED")]
        cases += [("CAPTURE", {"capture_state": state,
                              "comparison_state": "NOT_EVALUATED",
                              "reason_code": "COMPARISON_NOT_RUN"})
                  for state in ("SUCCEEDED", "FAILED", "UNKNOWN", "SKIPPED")]
        for record_type, observation in cases:
            with self.subTest(record_type=record_type, observation=observation):
                payload = record_bytes(record_type, observation)
                out = self.read(data_frame(0, f"{record_type}_RECORD", payload) + end(1))
                self.assert_summary(out, "CLEAN", [payload])
                self.assertIs(type(out.frames[0].payload), bytes)
                self.assertEqual(out.frames[0].sha256, hashlib.sha256(payload).hexdigest())
                self.assertEqual(out.frames[0].byte_length, len(payload))

    def test_first_capture_keeps_pending_record_and_real_image(self):
        out = self.read(self.capture_prefix() + end(2))
        self.assert_summary(out, "CLEAN", [self.capture, self.image])
        self.assertEqual(json.loads(out.frames[0].payload)["observation"], {
            "capture_state": "SUCCEEDED", "comparison_state": "BASELINE_PENDING",
            "reason_code": "BASELINE_NOT_SET"})

    def test_existing_baseline_does_not_invent_a_comparison(self):
        payload = record_bytes("CAPTURE", {
            "capture_state": "SUCCEEDED", "comparison_state": "NOT_EVALUATED",
            "reason_code": "COMPARISON_NOT_RUN"})
        out = self.read(data_frame(0, "CAPTURE_RECORD", payload)
                        + data_frame(1, "SCREENSHOT_PNG", self.image) + end(2))
        self.assert_summary(out, "CLEAN", [payload, self.image])
        # No baseline or quality decision is inferred by S0 from these bytes.
        self.assertEqual(json.loads(out.frames[0].payload)["observation"]["comparison_state"],
                         "NOT_EVALUATED")

    def test_application_invalid_records_are_still_opaque_to_s0(self):
        payloads = [b"not JSON", b"\xff\x00", record_bytes("HTTP", {
            "state": "OBSERVED", "status_code": True, "reason_code": "BAD_STATUS"}),
            record_bytes("HTTP", {"state": "UNKNOWN", "status_code": 200,
                                  "reason_code": "FORBIDDEN_STATUS"}),
            record_bytes("LOAD", {"state": "SUCCEEDED", "reason_code": ""})]
        for payload in payloads:
            with self.subTest(payload=payload):
                out = self.read(data_frame(0, "HTTP_RECORD", payload) + end(1))
                self.assert_summary(out, "CLEAN", [payload])
        # S1, not S0, must reject these application-contract violations.

    def test_clean_transport_does_not_prove_required_capture_image_exists(self):
        out = self.read(data_frame(0, "CAPTURE_RECORD", self.capture) + end(1))
        self.assert_summary(out, "CLEAN", [self.capture])
        # This is deliberately insufficient evidence for S1 to adopt capture success.

    def test_start_gap_duplicate_and_reverse_sequences_retain_only_valid_prefix(self):
        for seqs, accepted in (((1,), 0), ((0, 2), 1), ((0, 0), 1), ((0, 1, 0), 2)):
            with self.subTest(seqs=seqs):
                wire = b"".join(data_frame(seq, "HTTP_RECORD", self.http) for seq in seqs)
                out = self.read(wire + end(len(seqs)))
                self.assert_summary(out, "PROTOCOL_ERROR", [self.http] * accepted)
                self.assertEqual(out.reason, "INVALID_SEQUENCE")

    def test_missing_end_retains_record_and_image_but_never_clean(self):
        out = self.read(self.capture_prefix())
        self.assert_summary(out, "TRUNCATED", [self.capture, self.image])
        self.assertEqual(out.reason, "UNEXPECTED_EOF")

    def test_incomplete_end_is_truncated_even_after_complete_payloads(self):
        ending = end(2)
        for cut in (1, 3, 4, len(ending) - 1):
            with self.subTest(cut=cut):
                out = self.read(self.capture_prefix() + ending[:cut])
                self.assert_summary(out, "TRUNCATED", [self.capture, self.image])

    def test_clean_requires_an_actual_eof_read_after_end(self):
        class ObservedEOF(io.BytesIO):
            eof_observed = False

            def read(self, size=-1):
                part = super().read(size)
                if part == b"":
                    self.eof_observed = True
                    self.eof_request_size = size
                return part

        source = ObservedEOF(self.capture_prefix() + end(2))
        out = FrameReader(source, self.context).read()
        self.assert_summary(out, "CLEAN", [self.capture, self.image])
        self.assertTrue(source.eof_observed)
        self.assertEqual(source.eof_request_size, 1)

    def test_end_without_available_eof_is_not_assumed_clean(self):
        class NoEOF(io.BytesIO):
            def read(self, size=-1):
                if self.tell() == len(self.getvalue()):
                    if self.return_none:
                        return None  # nonblocking "not ready" is not EOF
                    raise TimeoutError("synthetic EOF never arrived")
                return super().read(size)

        for return_none, termination in ((False, "TIMEOUT"), (True, "PROTOCOL_ERROR")):
            with self.subTest(return_none=return_none):
                source = NoEOF(self.capture_prefix() + end(2))
                source.return_none = return_none
                out = FrameReader(source, self.context).read()
                self.assert_summary(out, termination, [self.capture, self.image])

    def test_trailing_bytes_after_nonempty_stream_end_are_rejected(self):
        for suffix in (b"x", b"\x00", b"\n", end(2), data_frame(2, "HTTP_RECORD", self.http)):
            with self.subTest(suffix=suffix[:20]):
                out = self.read(self.capture_prefix() + end(2) + suffix)
                self.assert_summary(out, "PROTOCOL_ERROR", [self.capture, self.image])
                self.assertEqual(out.reason, "TRAILING_DATA")

    def test_browser_header_cannot_claim_even_matching_connection_context(self):
        for key, value in (("job_id", self.context.job_id),
                           ("attempt_id", self.context.attempt_id),
                           ("lease_epoch", self.context.lease_epoch)):
            with self.subTest(key=key):
                out = self.read(data_frame(0, "HTTP_RECORD", self.http, **{key: value}) + end(1))
                self.assert_summary(out, "PROTOCOL_ERROR", [])
                self.assertEqual(out.reason, "UNTRUSTED_CONTEXT_CLAIM")

    def test_payload_claimed_context_cannot_replace_trusted_metadata(self):
        payload = record_bytes("HTTP", {
            "state": "OBSERVED", "status_code": 200, "reason_code": "HTTP_200",
            "job_id": "forged-job", "attempt_id": "forged-attempt", "lease_epoch": 999})
        out = self.read(data_frame(0, "HTTP_RECORD", payload) + end(1))
        self.assert_summary(out, "CLEAN", [payload])
        f = out.frames[0]
        self.assertEqual((f.job_id, f.attempt_id, f.lease_epoch),
                         (self.context.job_id, self.context.attempt_id, self.context.lease_epoch))

    def test_reusable_png_has_valid_chunks_crc_and_decodable_1x1_scanline(self):
        payload = self.image
        self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")
        offset, chunks = 8, []
        while offset < len(payload):
            length = int.from_bytes(payload[offset:offset + 4], "big")
            kind = payload[offset + 4:offset + 8]
            data = payload[offset + 8:offset + 8 + length]
            crc = int.from_bytes(payload[offset + 8 + length:offset + 12 + length], "big")
            self.assertEqual(len(data), length)
            self.assertEqual(crc, binascii.crc32(kind + data) & 0xffffffff)
            chunks.append((kind, data))
            offset += 12 + length
        self.assertEqual(offset, len(payload))
        self.assertEqual([kind for kind, _ in chunks], [b"IHDR", b"IDAT", b"IEND"])
        self.assertEqual(struct.unpack(">IIBBBBB", chunks[0][1]), (1, 1, 8, 2, 0, 0, 0))
        self.assertEqual(zlib.decompress(chunks[1][1]), b"\x00\xff\x00\x00")
        self.assertEqual(chunks[2][1], b"")
        out = self.read(data_frame(0, "SCREENSHOT_PNG", payload) + end(1))
        self.assert_summary(out, "CLEAN", [payload])

    def test_corrupt_crc_and_structure_do_not_admit_image_after_record(self):
        bad_crc = self.image[:29] + bytes([self.image[29] ^ 1]) + self.image[30:]
        duplicate_ihdr = self.image[:33] + self.image[8:]
        for image in (bad_crc, self.image[:-12], duplicate_ihdr,
                      b"\x89PNG\r\n\x1a\nsynthetic-png-body"):
            with self.subTest(image=image):
                out = self.read(data_frame(0, "CAPTURE_RECORD", self.capture)
                                + data_frame(1, "SCREENSHOT_PNG", image) + end(2))
                self.assert_summary(out, "PROTOCOL_ERROR", [self.capture])
                self.assertEqual(out.reason, "INVALID_PNG")

    def test_record_and_png_limits_reject_before_payload_is_read(self):
        for kind, payload, field in (("HTTP_RECORD", self.http, "max_record_bytes"),
                                     ("SCREENSHOT_PNG", self.image, "max_png_bytes")):
            with self.subTest(kind=kind):
                source = io.BytesIO(data_frame(0, kind, payload) + end(1))
                limits = replace(FrameLimits(), **{field: len(payload) - 1})
                out = FrameReader(source, self.context, limits).read()
                self.assert_summary(out, "OVERSIZE", [])
                self.assertEqual(out.reason, "FRAME_PAYLOAD_LIMIT")
                self.assertEqual(source.tell(), len(packet(header(0, kind, len(payload)))))

    def test_connection_stream_quota_boundary_excludes_rejected_image(self):
        total = len(self.capture) + len(self.image)
        wire = self.capture_prefix() + end(2)
        out = self.read(wire, replace(FrameLimits(), max_stream_payload_bytes=total))
        self.assert_summary(out, "CLEAN", [self.capture, self.image])
        source = io.BytesIO(wire)
        out = FrameReader(source, self.context,
                          replace(FrameLimits(), max_stream_payload_bytes=total - 1)).read()
        self.assert_summary(out, "OVERSIZE", [self.capture])
        self.assertEqual(out.reason, "STREAM_PAYLOAD_LIMIT")
        self.assertEqual(source.tell(), len(data_frame(0, "CAPTURE_RECORD", self.capture))
                         + len(packet(header(1, "SCREENSHOT_PNG", len(self.image)))))


if __name__ == "__main__":
    unittest.main()
