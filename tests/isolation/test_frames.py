"""Memory-only stream tests with reusable generated fixtures, not browser output."""

from dataclasses import asdict, replace
import hashlib
import io
import struct
import unittest

from src.isolation.frames import (
    CONTRACT_VERSION, PROVENANCE, FrameLimits, FrameReader, TrustedContext,
)
from wire_fixtures import end, header, packet, png, png_chunk, raw_header


class RecordingSource(io.BytesIO):
    def __init__(self, value, fragment=None):
        super().__init__(value)
        self.requests = []
        self.fragment = fragment

    def read(self, size=-1):
        if size < 0:
            raise AssertionError("unbounded read")
        self.requests.append(size)
        return super().read(min(size, self.fragment) if self.fragment else size)


class FrameTests(unittest.TestCase):
    def setUp(self):
        self.context = TrustedContext("trusted-job", "trusted-attempt", 7)

    def read(self, value, limits=None, **kwargs):
        return FrameReader(io.BytesIO(value), self.context, limits, **kwargs).read()

    def assertTermination(self, result, expected, count=0, total=0):
        self.assertEqual(result.summary.termination, expected, result.reason)
        self.assertEqual(result.summary.frame_count, count)
        self.assertEqual(result.summary.total_payload_bytes, total)
        self.assertEqual(len(result.frames), count)

    def test_verified_frame_exact_contract_hash_and_actual_length(self):
        payload = b"\x00\xffsynthetic HTTP observation"
        result = self.read(packet(header(length=len(payload)), payload) + end())
        self.assertTermination(result, "CLEAN", 1, len(payload))
        self.assertEqual(asdict(result.frames[0]), dict(
            schema_version=CONTRACT_VERSION, job_id="trusted-job", attempt_id="trusted-attempt",
            lease_epoch=7, seq=0, kind="HTTP_RECORD", page_id="page-1", profile_id="profile-1",
            check_type="HTTP", byte_length=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
            payload=payload, provenance=PROVENANCE,
        ))
        self.assertRegex(result.frames[0].sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(set(asdict(result.summary)),
                         {"termination", "frame_count", "total_payload_bytes"})

    def test_kind_to_check_type_mapping(self):
        for kind, check in (("HTTP_RECORD", "HTTP"), ("LOAD_RECORD", "LOAD"),
                            ("CAPTURE_RECORD", "CAPTURE"), ("SCREENSHOT_PNG", "CAPTURE")):
            with self.subTest(kind=kind):
                payload = png() if kind == "SCREENSHOT_PNG" else b"abc"
                result = self.read(packet(header(kind=kind, length=len(payload)), payload) + end())
                self.assertTermination(result, "CLEAN", 1, len(payload))
                self.assertEqual(result.frames[0].check_type, check)

    def test_end_only_empty_stream_is_clean(self):
        self.assertTermination(self.read(end(0)), "CLEAN")

    def test_multiple_frames_and_zero_length_record(self):
        value = packet(header(length=0)) + packet(header(1, "LOAD_RECORD", 3), b"abc") + end(2)
        result = self.read(value)
        self.assertTermination(result, "CLEAN", 2, 3)
        self.assertEqual([frame.seq for frame in result.frames], [0, 1])

    def test_truncation_at_every_byte_of_valid_stream(self):
        value = packet(header(), b"abc") + end()
        for cut in range(len(value)):
            with self.subTest(cut=cut):
                result = self.read(value[:cut])
                self.assertEqual(result.summary.termination, "TRUNCATED")
                expected_count = int(cut >= len(packet(header(), b"abc")))
                self.assertEqual(result.summary.frame_count, expected_count)
                self.assertEqual(result.summary.total_payload_bytes, 3 * expected_count)

    def test_missing_end_retains_only_verified_prefix(self):
        result = self.read(packet(header(), b"abc"))
        self.assertTermination(result, "TRUNCATED", 1, 3)

    def test_wrong_sequence_duplicate_and_gap(self):
        for seq in (-1, 1, 9, True, "0", 0.0):
            with self.subTest(seq=seq):
                self.assertTermination(self.read(packet(header(seq), b"abc") + end()),
                                       "PROTOCOL_ERROR")
        for seq in (0, 2):
            with self.subTest(second_seq=seq):
                result = self.read(packet(header(), b"abc") +
                                   packet(header(seq), b"def") + end(2))
                self.assertTermination(result, "PROTOCOL_ERROR", 1, 3)

    def test_invalid_magic_version_and_kind(self):
        fixtures = ({"magic": "WRONG"}, {"magic": None}, {"version": "v0.2"},
                    {"version": 1}, {"kind": "UNKNOWN"}, {"kind": "http_record"},
                    {"kind": None}, {"kind": []}, {"kind": 1})
        for changes in fixtures:
            with self.subTest(changes=changes):
                self.assertTermination(self.read(packet(header(**changes), b"abc") + end()),
                                       "PROTOCOL_ERROR")

    def test_browser_cannot_supply_trusted_context_even_if_matching(self):
        for key, value in (("job_id", "trusted-job"), ("attempt_id", "trusted-attempt"),
                           ("lease_epoch", 7)):
            with self.subTest(key=key):
                result = self.read(packet(header(**{key: value}), b"abc") + end())
                self.assertTermination(result, "PROTOCOL_ERROR")
                self.assertEqual(result.reason, "UNTRUSTED_CONTEXT_CLAIM")

    def test_context_is_always_assigned_from_trusted_side(self):
        context = TrustedContext("another-job", "another-attempt", 99)
        result = FrameReader(io.BytesIO(packet(header(), b"abc") + end()), context).read()
        self.assertEqual((result.frames[0].job_id, result.frames[0].attempt_id,
                          result.frames[0].lease_epoch), ("another-job", "another-attempt", 99))

    def test_invalid_context_rejected(self):
        for args in (("", "a", 0), ("j", None, 0), ("j", "a", True),
                     ("j", "a", -1), ("j", "a", "1"), ("j", "\ud800", 0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                TrustedContext(*args)
        with self.assertRaises(ValueError):
            FrameReader(io.BytesIO(), None)

    def test_missing_and_additional_header_fields_rejected(self):
        for key in header():
            with self.subTest(missing=key):
                value = header()
                del value[key]
                self.assertTermination(self.read(packet(value)), "PROTOCOL_ERROR")
        for key in ("check_type", "sha256", "schema_version", "Attempt_ID", "payload"):
            with self.subTest(extra=key):
                self.assertTermination(self.read(packet(header(**{key: "forged"}))),
                                       "PROTOCOL_ERROR")

    def test_json_utf8_duplicates_and_types(self):
        raw_valid = raw_header(header())
        fixtures = (b"", b"\xff", b"{", b"[]", b"null", b"true", b'"string"',
                    raw_valid[:-1] + b',"seq":0}', raw_valid[:-1] + b',"x":NaN}',
                    raw_valid[:-1] + b',"x":Infinity}', b"[" * 2000 + b"]" * 2000)
        for raw in fixtures:
            with self.subTest(raw=raw[:50]):
                result = self.read(len(raw).to_bytes(4, "big") + raw)
                self.assertTermination(result, "PROTOCOL_ERROR")

    def test_identifiers_must_be_nonempty_valid_unicode_strings(self):
        for key in ("page_id", "profile_id"):
            for value in (None, [], {}, 1, True, "", " ", "a\x00b", "a\x7fb", "\ud800"):
                with self.subTest(key=key, value=value):
                    self.assertTermination(self.read(packet(header(**{key: value}), b"abc")),
                                           "PROTOCOL_ERROR")
        result = self.read(packet(header(page_id="ページ", profile_id="設定"), b"abc") + end())
        self.assertTermination(result, "CLEAN", 1, 3)

    def test_declared_length_strict_integer_and_nonnegative(self):
        for value in (-1, True, "3", 3.0, None, [], {}):
            with self.subTest(value=value):
                self.assertTermination(self.read(packet(header(length=value), b"abc")),
                                       "PROTOCOL_ERROR")

    def test_length_overclaim_truncates(self):
        self.assertTermination(self.read(packet(header(length=4), b"abc")), "TRUNCATED")

    def test_length_underclaim_cannot_complete_cleanly(self):
        result = self.read(packet(header(length=2), b"abc") + end())
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assertEqual(result.summary.total_payload_bytes, 2)

    def test_header_limit_exact_and_one_over_before_body_read(self):
        limit = FrameLimits().max_header_bytes
        raw = raw_header(header())
        padded = raw + b" " * (limit - len(raw))
        result = self.read(limit.to_bytes(4, "big") + padded + b"abc" + end())
        self.assertTermination(result, "CLEAN", 1, 3)
        for length in (limit + 1, 0xffffffff):
            with self.subTest(length=length):
                source = RecordingSource(length.to_bytes(4, "big"))
                result = FrameReader(source, self.context).read()
                self.assertTermination(result, "OVERSIZE")
                self.assertEqual(source.requests, [4])

    def test_record_limit_exact_and_one_over_before_payload_read(self):
        limit = FrameLimits().max_record_bytes
        payload = b"x" * limit
        result = self.read(packet(header(length=limit), payload) + end())
        self.assertTermination(result, "CLEAN", 1, limit)
        source = RecordingSource(packet(header(length=limit + 1)))
        result = FrameReader(source, self.context).read()
        self.assertTermination(result, "OVERSIZE")
        self.assertEqual(source.requests, [4, len(raw_header(header(length=limit + 1)))])

    def test_png_limit_exact_and_one_over(self):
        limit = FrameLimits().max_png_bytes
        padding_size = limit - len(png()) - 12
        payload = png(extra=png_chunk(b"teXt", b"x" * padding_size))
        self.assertEqual(len(payload), limit)
        result = self.read(packet(header(kind="SCREENSHOT_PNG", length=limit), payload) + end())
        self.assertTermination(result, "CLEAN", 1, limit)
        source = RecordingSource(packet(header(kind="SCREENSHOT_PNG", length=limit + 1)))
        result = FrameReader(source, self.context).read()
        self.assertTermination(result, "OVERSIZE")
        self.assertEqual(len(source.requests), 2)

    def test_stream_payload_exact_and_one_over(self):
        limits = replace(FrameLimits(), max_stream_payload_bytes=6)
        prefix = packet(header(), b"abc") + packet(header(1), b"def")
        self.assertTermination(self.read(prefix + end(2), limits), "CLEAN", 2, 6)
        source = RecordingSource(prefix + packet(header(2, length=1), b"g") + end(3))
        result = FrameReader(source, self.context, limits).read()
        self.assertTermination(result, "OVERSIZE", 2, 6)
        self.assertEqual(result.reason, "STREAM_PAYLOAD_LIMIT")
        self.assertEqual(source.tell(), len(prefix + packet(header(2, length=1))))

    def test_frame_count_64_exact_then_65_rejected_before_payload(self):
        prefix = b"".join(packet(header(i, length=1), b"x") for i in range(64))
        self.assertTermination(self.read(prefix + end(64)), "CLEAN", 64, 64)
        source = RecordingSource(prefix + packet(header(64, length=1), b"x") + end(65))
        result = FrameReader(source, self.context).read()
        self.assertTermination(result, "OVERSIZE", 64, 64)
        self.assertEqual(result.reason, "FRAME_COUNT_LIMIT")
        self.assertEqual(source.tell(), len(prefix + packet(header(64, length=1))))

    def test_defaults_match_batch_candidates(self):
        limits = FrameLimits()
        self.assertEqual((limits.max_header_bytes, limits.max_record_bytes,
                          limits.max_png_bytes, limits.max_stream_payload_bytes,
                          limits.max_data_frames), (4096, 2 << 20, 8 << 20, 32 << 20, 64))

    def test_end_must_be_complete_empty_and_correct_sequence(self):
        for changes in ({"declared_length": 1}, {"page_id": "p"}, {"profile_id": "p"},
                        {"page_id": None}, {"profile_id": 0}, {"seq": 2},
                        {"declared_length": False}, {"attempt_id": "forged"}):
            with self.subTest(changes=changes):
                value = header(1, "END", 0, page_id="", profile_id="")
                value.update(changes)
                self.assertTermination(self.read(packet(header(), b"abc") + packet(value)),
                                       "PROTOCOL_ERROR", 1, 3)

    def test_end_rejects_all_trailing_bytes_and_second_end(self):
        for suffix in (b"\x00", b" ", b"\n", end(1), packet(header(1), b"abc")):
            with self.subTest(suffix=suffix[:10]):
                self.assertTermination(self.read(end(0) + suffix), "PROTOCOL_ERROR")

    def test_short_reads_are_supported_and_requests_are_bounded(self):
        payload = b"x" * 100_000
        value = packet(header(length=len(payload)), payload) + end()
        for fragment in (None, 1, 17):
            with self.subTest(fragment=fragment):
                source = RecordingSource(value, fragment)
                result = FrameReader(source, self.context).read()
                self.assertTermination(result, "CLEAN", 1, len(payload))
                self.assertLessEqual(max(source.requests), 64 * 1024)

    def test_non_binary_or_oversized_read_result_rejected(self):
        class BrokenSource:
            def __init__(self, value):
                self.value = value

            def read(self, size):
                return self.value

        for value in (None, "abcd", bytearray(b"abcd"), b"x" * 5):
            with self.subTest(value=value):
                result = FrameReader(BrokenSource(value), self.context).read()
                self.assertTermination(result, "PROTOCOL_ERROR")

    def test_source_timeout_and_io_error_have_summary(self):
        class BrokenSource:
            def __init__(self, error):
                self.error = error

            def read(self, size):
                raise self.error

        for error, termination in ((TimeoutError(), "TIMEOUT"), (OSError(), "PROTOCOL_ERROR"),
                                   (ValueError(), "PROTOCOL_ERROR")):
            with self.subTest(error=type(error).__name__):
                result = FrameReader(BrokenSource(error), self.context).read()
                self.assertTermination(result, termination)

    def test_deadline_exact_boundary_and_verified_prefix(self):
        class AdvancingSource(io.BytesIO):
            def read(self, size):
                part = super().read(size)
                clock[0] += 1
                return part

        for timeout, count, total in ((3, 0, 0), (4, 1, 3)):
            with self.subTest(timeout=timeout):
                clock = [0]
                result = FrameReader(AdvancingSource(packet(header(), b"abc") + end()),
                                     self.context, replace(FrameLimits(), timeout_seconds=timeout),
                                     clock=lambda: clock[0]).read()
                self.assertTermination(result, "TIMEOUT", count, total)
        clock = [0]
        self.assertTermination(self.read(end(0), clock=lambda: clock[0]), "CLEAN")

    def test_invalid_and_regressing_clock(self):
        for value in (float("nan"), float("inf"), None, True, 10 ** 1000):
            with self.subTest(value=value):
                self.assertTermination(self.read(end(0), clock=lambda: value), "PROTOCOL_ERROR")
        clock = iter((1, 0))
        self.assertTermination(self.read(end(0), clock=lambda: next(clock)), "PROTOCOL_ERROR")

    def test_reader_single_use(self):
        reader = FrameReader(io.BytesIO(end(0)), self.context)
        reader.read()
        with self.assertRaises(RuntimeError):
            reader.read()

    def test_limits_configuration_strict(self):
        for field in ("max_header_bytes", "max_record_bytes", "max_png_bytes",
                      "max_stream_payload_bytes", "max_data_frames", "max_png_pixels"):
            for value in (0, -1, True, 1.0, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    replace(FrameLimits(), **{field: value})
        for value in (0, -1, True, float("nan"), float("inf"), None, 10 ** 1000):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                replace(FrameLimits(), timeout_seconds=value)

    def test_png_bad_signature_crc_truncation_and_missing_iend(self):
        valid = png()
        fixtures = (b"not png", valid[:7], valid[:-1], valid[:-12], valid + b"x",
                    valid[:29] + bytes([valid[29] ^ 1]) + valid[30:])
        for payload in fixtures:
            with self.subTest(length=len(payload)):
                result = self.read(packet(header(kind="SCREENSHOT_PNG", length=len(payload)),
                                          payload) + end())
                self.assertTermination(result, "PROTOCOL_ERROR")

    def test_png_bad_ihdr_and_pixel_limit(self):
        fixtures = (png(width=0), png(height=0), png(width=0x80000000),
                    png(depth=4, color=2), png(color=5), png(width=100, height=100))
        limits = replace(FrameLimits(), max_png_pixels=9999)
        for payload in fixtures:
            with self.subTest(length=len(payload)):
                result = self.read(packet(header(kind="SCREENSHOT_PNG", length=len(payload)),
                                          payload) + end(), limits)
                self.assertTermination(result, "PROTOCOL_ERROR")
        payload = png(width=3, height=3)
        result = self.read(packet(header(kind="SCREENSHOT_PNG", length=len(payload)), payload) + end(),
                           replace(FrameLimits(), max_png_pixels=9))
        self.assertTermination(result, "CLEAN", 1, len(payload))

    def test_png_chunk_order_lengths_and_unknown_critical_chunks(self):
        signature = b"\x89PNG\r\n\x1a\n"
        ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        idat, iend = png_chunk(b"IDAT", b"x"), png_chunk(b"IEND", b"")
        fixtures = (signature + idat + ihdr + iend,
                    signature + ihdr + ihdr + idat + iend,
                    signature + ihdr + iend,
                    signature + ihdr + png_chunk(b"IDAT", b"") + iend,
                    signature + ihdr + idat + png_chunk(b"teXt", b"k\x00v") + idat + iend,
                    signature + ihdr + png_chunk(b"ABCD", b"") + idat + iend,
                    signature + ihdr + png_chunk(b"abcd", b"") + idat + iend,
                    signature + ihdr + png_chunk(b"a1Cd", b"") + idat + iend,
                    signature + ihdr + idat + png_chunk(b"IEND", b"x"),
                    signature + ihdr + b"\xff\xff\xff\xffIDAT" + b"x" * 4)
        for payload in fixtures:
            with self.subTest(payload=payload[-20:]):
                self.assertTermination(self.read(packet(header(kind="SCREENSHOT_PNG",
                                                               length=len(payload)), payload) + end()),
                                       "PROTOCOL_ERROR")

    def test_png_palette_constraints(self):
        signature = b"\x89PNG\r\n\x1a\n"
        indexed = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 1, 3, 0, 0, 0))
        palette = png_chunk(b"PLTE", b"\x00\x00\x00")
        idat, iend = png_chunk(b"IDAT", b"x"), png_chunk(b"IEND", b"")
        for middle in (b"", png_chunk(b"PLTE", b"x"), palette + palette,
                       png_chunk(b"PLTE", b"x" * 9)):
            with self.subTest(middle=middle):
                payload = signature + indexed + middle + idat + iend
                self.assertTermination(self.read(packet(header(kind="SCREENSHOT_PNG",
                                                               length=len(payload)), payload) + end()),
                                       "PROTOCOL_ERROR")
        payload = signature + indexed + palette + idat + iend
        self.assertTermination(self.read(packet(header(kind="SCREENSHOT_PNG", length=len(payload)),
                                               payload) + end()), "CLEAN", 1, len(payload))

    def test_png_complete_decode_is_deliberately_not_claimed(self):
        # Correct container/CRC but deliberately invalid compressed image data.
        # This test records the boundary of the structural validator's promise.
        payload = png(idat=b"not a deflate stream")
        self.assertTermination(self.read(packet(header(kind="SCREENSHOT_PNG", length=len(payload)),
                                               payload) + end()), "CLEAN", 1, len(payload))
