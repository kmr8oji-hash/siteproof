import json
import unittest

from src.core.errors import RecordInvalid
from src.core.frames import CheckType, FrameKind
from src.core.model import CheckOutcome, CheckReport, JobIntent, JobSnapshot
from src.core.records import (RECORD_SCHEMA_VERSION, derive_report, derive_reports,
                              parse_record, validate_skips)
from src.core.synthetic import (capture_record, http_record, load_record, make_frame,
                                record_bytes)

HTTP, LOAD, CAPTURE = CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE
K = FrameKind
O = CheckOutcome


def snap(baseline="base-1", checks=(HTTP, LOAD, CAPTURE)):
    return JobSnapshot("job-1", JobIntent("https://example.invalid/", "page-1", "desktop",
                                          checks, baseline), "2026-01-01T00:00:00+00:00")


def report(kind, payload, snapshot=None):
    return derive_report(parse_record(kind, payload), snapshot or snap())


def code_of(fn, *args):
    with unittest.TestCase().assertRaises(RecordInvalid) as cm:
        fn(*args)
    return cm.exception.code


class ParserRejectsMalformedInput(unittest.TestCase):
    def test_not_utf8_not_json_not_object(self):
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, b"\xff\xfe{}"), "RECORD_NOT_UTF8")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, b"\xef\xbb\xbf" + http_record()),
                         "RECORD_NOT_JSON")  # BOM
        for bad in (b"", b"{", b"not json", b"{'a':1}"):
            self.assertEqual(code_of(parse_record, K.HTTP_RECORD, bad), "RECORD_NOT_JSON", bad)
        for bad in (b"[]", b"null", b"1", b'"x"', b"true"):
            self.assertEqual(code_of(parse_record, K.HTTP_RECORD, bad), "RECORD_NOT_OBJECT", bad)
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, b"[" * 100000), "RECORD_NOT_JSON")

    def test_duplicate_keys_and_nonfinite_numbers(self):
        dup = (b'{"schema_version":"siteproof.record.v0.1","record_type":"HTTP",'
               b'"record_type":"LOAD","observation":{"state":"SKIPPED","reason_code":"X"}}')
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, dup), "RECORD_DUPLICATE_KEY")
        nested = (b'{"schema_version":"siteproof.record.v0.1","record_type":"HTTP",'
                  b'"observation":{"state":"OBSERVED","status_code":200,"status_code":404,'
                  b'"reason_code":"X"}}')
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, nested), "RECORD_DUPLICATE_KEY")
        for tok in (b"NaN", b"Infinity", b"-Infinity"):
            doc = (b'{"schema_version":"siteproof.record.v0.1","record_type":"HTTP","observation":'
                   b'{"state":"OBSERVED","status_code":' + tok + b',"reason_code":"X"}}')
            self.assertEqual(code_of(parse_record, K.HTTP_RECORD, doc),
                             "RECORD_NONFINITE_NUMBER", tok)

    def test_schema_and_type_errors(self):
        good = json.loads(http_record())
        def variant(**kw):
            d = json.loads(json.dumps(good))
            d.update(kw)
            return json.dumps(d).encode()
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD,
                                 variant(schema_version="siteproof.record.v9")),
                         "RECORD_SCHEMA_VERSION")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, variant(record_type="DNS")),
                         "RECORD_TYPE_UNKNOWN")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, variant(record_type=7)),
                         "RECORD_TYPE_UNKNOWN")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, variant(record_type="LOAD")),
                         "RECORD_TYPE_MISMATCH")  # kind HTTP_RECORD vs record_type LOAD
        self.assertEqual(code_of(parse_record, K.LOAD_RECORD, http_record()),
                         "RECORD_TYPE_MISMATCH")
        self.assertEqual(code_of(parse_record, K.CAPTURE_RECORD, load_record()),
                         "RECORD_TYPE_MISMATCH")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, variant(extra=1)),
                         "RECORD_FIELD_UNEXPECTED")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, variant(observation=[])),
                         "RECORD_FIELD_TYPE")
        d = dict(good)
        d.pop("observation")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD, json.dumps(d).encode()),
                         "RECORD_FIELD_MISSING")
        self.assertEqual(code_of(parse_record, K.SCREENSHOT_PNG, http_record()),
                         "RECORD_KIND_NOT_A_RECORD")

    def test_http_status_code_rules(self):
        for bad in (True, False, 99, 600, 0, -200, 200.5, 200.0, "200", None, [200]):
            payload = record_bytes("HTTP", {"state": "OBSERVED", "status_code": bad,
                                            "reason_code": "X"})
            self.assertEqual(code_of(parse_record, K.HTTP_RECORD, payload),
                             "RECORD_STATUS_CODE_INVALID", repr(bad))
        # status_code missing on OBSERVED / present on UNKNOWN or SKIPPED
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD,
                                 record_bytes("HTTP", {"state": "OBSERVED", "reason_code": "X"})),
                         "RECORD_FIELD_MISSING")
        for st in ("UNKNOWN", "SKIPPED"):
            self.assertEqual(code_of(parse_record, K.HTTP_RECORD, record_bytes(
                "HTTP", {"state": st, "status_code": 200, "reason_code": "X"})),
                "RECORD_FIELD_UNEXPECTED")
        self.assertEqual(code_of(parse_record, K.HTTP_RECORD,
                                 record_bytes("HTTP", {"state": "MAYBE", "reason_code": "X"})),
                         "RECORD_STATE_INVALID")

    def test_reason_code_is_mandatory_and_clean(self):
        for bad in ("", "   ", " X", "X ", "a\nb", "x" * 129, None, 5):
            payload = record_bytes("LOAD", {"state": "SUCCEEDED", "reason_code": bad})
            self.assertEqual(code_of(parse_record, K.LOAD_RECORD, payload),
                             "RECORD_REASON_INVALID", repr(bad))
        self.assertEqual(code_of(parse_record, K.LOAD_RECORD,
                                 record_bytes("LOAD", {"state": "SUCCEEDED"})),
                         "RECORD_FIELD_MISSING")

    def test_load_and_capture_states(self):
        self.assertEqual(code_of(parse_record, K.LOAD_RECORD, load_record(state="OK")),
                         "RECORD_STATE_INVALID")
        self.assertEqual(code_of(parse_record, K.CAPTURE_RECORD,
                                 capture_record(capture_state="DONE")), "RECORD_STATE_INVALID")
        self.assertEqual(code_of(parse_record, K.CAPTURE_RECORD,
                                 capture_record(comparison_state="MATCH")),
                         "RECORD_COMPARISON_STATE_INVALID")
        self.assertEqual(code_of(parse_record, K.CAPTURE_RECORD,
                                 record_bytes("CAPTURE", {"capture_state": "SUCCEEDED",
                                                          "reason_code": "X"})),
                         "RECORD_FIELD_MISSING")


class OutcomeDerivation(unittest.TestCase):
    def test_http_status_classes(self):
        for sc, outcome in ((200, O.PASS), (204, O.PASS), (299, O.PASS), (400, O.FAIL),
                            (404, O.FAIL), (500, O.FAIL), (599, O.FAIL)):
            rep = report(K.HTTP_RECORD, http_record(sc))
            self.assertEqual(rep.outcome, outcome, sc)
        for sc in (100, 199, 301, 302, 399):
            rep = report(K.HTTP_RECORD, http_record(sc))
            self.assertEqual(rep.outcome, O.UNKNOWN, sc)  # a 3xx is never an automatic PASS
            self.assertEqual(rep.reason_code, f"HTTP_{sc}_UNRESOLVED")

    def test_http_unobserved_states(self):
        self.assertEqual(report(K.HTTP_RECORD, http_record(state="UNKNOWN", reason="TIMEOUT")),
                         CheckReport(HTTP, O.UNKNOWN, "TIMEOUT"))
        self.assertEqual(report(K.HTTP_RECORD, http_record(state="SKIPPED", reason="R")),
                         CheckReport(HTTP, O.SKIPPED, "R"))

    def test_load_states(self):
        for st, oc in (("SUCCEEDED", O.PASS), ("FAILED", O.FAIL), ("UNKNOWN", O.UNKNOWN),
                       ("SKIPPED", O.SKIPPED)):
            self.assertEqual(report(K.LOAD_RECORD, load_record(st, "WHY")),
                             CheckReport(LOAD, oc, "WHY"))

    def test_first_capture_without_baseline_is_unknown_baseline_pending(self):
        rep = report(K.CAPTURE_RECORD, capture_record(), snap(baseline=None))
        self.assertEqual(rep, CheckReport(CAPTURE, O.UNKNOWN, "BASELINE_PENDING"))

    def test_capture_with_baseline_but_no_comparison_is_unknown_comparison_not_run(self):
        rep = report(K.CAPTURE_RECORD, capture_record(comparison_state="NOT_EVALUATED",
                                                      reason="COMPARISON_NOT_RUN"))
        self.assertEqual(rep, CheckReport(CAPTURE, O.UNKNOWN, "COMPARISON_NOT_RUN"))

    def test_capture_record_cannot_claim_a_comparison_result(self):
        # the only comparison states are BASELINE_PENDING / NOT_EVALUATED; anything else is invalid
        for cs in ("MATCH", "CHANGED", "PASS", "DIFFERENT"):
            self.assertEqual(code_of(parse_record, K.CAPTURE_RECORD,
                                     capture_record(comparison_state=cs)),
                             "RECORD_COMPARISON_STATE_INVALID")

    def test_capture_baseline_state_must_agree_with_job(self):
        self.assertEqual(code_of(report, K.CAPTURE_RECORD, capture_record(), snap("base-1")),
                         "RECORD_BASELINE_STATE_MISMATCH")  # claims pending, baseline exists
        self.assertEqual(code_of(report, K.CAPTURE_RECORD,
                                 capture_record(comparison_state="NOT_EVALUATED",
                                                reason="COMPARISON_NOT_RUN"), snap(None)),
                         "RECORD_BASELINE_STATE_MISMATCH")
        self.assertEqual(code_of(report, K.CAPTURE_RECORD,
                                 capture_record(reason="SOMETHING_ELSE"), snap(None)),
                         "RECORD_REASON_MISMATCH")

    def test_explicit_capture_failure_states(self):
        for st, oc in (("FAILED", O.FAIL), ("UNKNOWN", O.UNKNOWN), ("SKIPPED", O.SKIPPED)):
            rep = report(K.CAPTURE_RECORD, capture_record(st, "NOT_EVALUATED", "WHY"))
            self.assertEqual(rep, CheckReport(CAPTURE, oc, "WHY"))
        self.assertEqual(code_of(report, K.CAPTURE_RECORD,
                                 capture_record("FAILED", "BASELINE_PENDING", "WHY")),
                         "RECORD_COMPARISON_STATE_INVALID")
        for reserved in ("BASELINE_NOT_SET", "COMPARISON_NOT_RUN", "BASELINE_PENDING"):
            self.assertEqual(code_of(report, K.CAPTURE_RECORD,
                                     capture_record("FAILED", "NOT_EVALUATED", reserved)),
                             "RECORD_REASON_RESERVED")


def frame(seq, kind, payload=None):
    return make_frame(job_id="job-1", attempt_id="att-1", lease_epoch=1, seq=seq, kind=kind,
                      page_id="page-1", profile_id="desktop", payload=payload)


class SkipJustification(unittest.TestCase):
    def reports(self, http, load=None, capture=None):
        out = {HTTP: http}
        if load:
            out[LOAD] = load
        if capture:
            out[CAPTURE] = capture
        return out

    def test_skipped_after_confirmed_http_failure_is_allowed(self):
        validate_skips(self.reports(
            CheckReport(HTTP, O.FAIL, "HTTP_STATUS_OBSERVED"),
            CheckReport(LOAD, O.SKIPPED, "UPSTREAM_HTTP_FAILED"),
            CheckReport(CAPTURE, O.SKIPPED, "UPSTREAM_HTTP_FAILED")))

    def test_skipped_after_http_success_is_rejected(self):
        for http in (O.PASS, O.UNKNOWN, O.SKIPPED):
            with self.assertRaises(RecordInvalid, msg=http.value) as cm:
                validate_skips(self.reports(CheckReport(HTTP, http, "X"),
                                            CheckReport(LOAD, O.SKIPPED, "UPSTREAM_HTTP_FAILED")))
            self.assertEqual(cm.exception.code, "SKIP_NOT_JUSTIFIED")

    def test_arbitrary_skip_reason_and_http_skip_are_rejected(self):
        with self.assertRaises(RecordInvalid):
            validate_skips(self.reports(CheckReport(HTTP, O.FAIL, "X"),
                                        CheckReport(LOAD, O.SKIPPED, "BROWSER_SAID_SO")))
        with self.assertRaises(RecordInvalid):
            validate_skips(self.reports(CheckReport(HTTP, O.SKIPPED, "UPSTREAM_HTTP_FAILED")))
        with self.assertRaises(RecordInvalid):  # no HTTP check at all to justify it
            validate_skips({LOAD: CheckReport(LOAD, O.SKIPPED, "UPSTREAM_HTTP_FAILED")})

    def test_derive_reports_end_to_end_404_with_explicit_skips(self):
        fs = [frame(0, K.HTTP_RECORD, http_record(404)),
              frame(1, K.LOAD_RECORD, load_record("SKIPPED", "UPSTREAM_HTTP_FAILED")),
              frame(2, K.CAPTURE_RECORD,
                    capture_record("SKIPPED", "NOT_EVALUATED", "UPSTREAM_HTTP_FAILED"))]
        reps = derive_reports(fs, snap())
        self.assertEqual(reps[HTTP].outcome, O.FAIL)
        self.assertEqual(reps[LOAD], CheckReport(LOAD, O.SKIPPED, "UPSTREAM_HTTP_FAILED"))
        self.assertEqual(reps[CAPTURE].outcome, O.SKIPPED)

    def test_derive_reports_rejects_skip_after_http_200(self):
        fs = [frame(0, K.HTTP_RECORD, http_record(200)),
              frame(1, K.LOAD_RECORD, load_record("SKIPPED", "UPSTREAM_HTTP_FAILED"))]
        with self.assertRaises(RecordInvalid):
            derive_reports(fs, snap(checks=(HTTP, LOAD)))

    def test_missing_record_is_simply_absent_not_skipped(self):
        fs = [frame(0, K.HTTP_RECORD, http_record(200))]
        self.assertEqual(set(derive_reports(fs, snap())), {HTTP})

    def test_frame_envelope_and_record_identity_must_agree(self):
        # frame says LOAD_RECORD but carries an HTTP record
        fs = [frame(0, K.LOAD_RECORD, http_record(200))]
        with self.assertRaises(RecordInvalid) as cm:
            derive_reports(fs, snap())
        self.assertEqual(cm.exception.code, "RECORD_TYPE_MISMATCH")

    def test_schema_constant(self):
        self.assertEqual(RECORD_SCHEMA_VERSION, "siteproof.record.v0.1")


if __name__ == "__main__":
    unittest.main()
