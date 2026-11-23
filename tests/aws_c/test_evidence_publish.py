"""AWS-C evidence: write-once S3 publication, read-back, tamper detection, signing wiring.

The export under test is produced by the EXISTING Repository / EvidenceFinalizer /
ArtifactStore, and verified by the EXISTING plan_recovery. S3 and KMS are offline fakes;
real conditional-write, checksum and signature behaviour is LIVE-unverified.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.aws_c.evidence import (RUN_MANIFEST_NAME, SIGNATURE_NAME, collect, publish_run,
                                verify_local)
from src.aws_c.s3_publisher import S3Publisher
from src.aws_c.signer import KmsSigner, UnsignedSigner, verify_with_kms
from tests.aws_c.support import RUN_ID, make_export
from tests.aws_fakes import FakeClientError, FakeKms, FakeS3

BUCKET, PREFIX = "evidence-bucket", "runs/%s/" % RUN_ID
AT = "2026-12-01T02:30:00Z"


class Publisher(unittest.TestCase):
    def setUp(self):
        self.s3 = FakeS3()
        self.pub = S3Publisher(self.s3, BUCKET, PREFIX)

    def test_publish_stores_bytes_with_checksum_and_reads_back(self):
        result = self.pub.publish("s1/a.bin", b"hello")
        self.assertEqual((result.status, result.sha256, result.byte_length),
                         ("PUBLISHED", hashlib.sha256(b"hello").hexdigest(), 5))
        self.assertEqual(self.s3.objects[(BUCKET, PREFIX + "s1/a.bin")]["Body"], b"hello")

    def test_second_publish_of_same_bytes_is_idempotent(self):
        self.pub.publish("a", b"x")
        self.assertEqual(self.pub.publish("a", b"x").status, "EXISTS_IDENTICAL")

    def test_existing_object_is_never_overwritten(self):
        self.pub.publish("a", b"original")
        result = self.pub.publish("a", b"replacement")
        self.assertEqual((result.status, result.ok), ("CONFLICT", False))
        self.assertEqual(self.s3.objects[(BUCKET, PREFIX + "a")]["Body"], b"original")

    def test_every_put_is_conditional(self):
        strict = FakeS3(require_if_none_match=True)
        self.assertTrue(S3Publisher(strict, BUCKET, PREFIX).publish("a", b"x").ok)
        with self.assertRaises(FakeClientError):
            strict.put_object(Bucket=BUCKET, Key=PREFIX + "b", Body=b"y")   # unconditional

    def test_corrupted_storage_is_detected_on_read_back(self):
        original = self.s3.put_object

        def corrupting(**request):
            response = original(**request)
            self.s3.objects[(request["Bucket"], request["Key"])]["Body"] = b"tampered"
            return response
        self.s3.put_object = corrupting
        self.assertEqual(self.pub.publish("a", b"expected").status, "READBACK_MISMATCH")

    def test_checksum_attribute_mismatch_is_detected(self):
        original = self.s3.put_object

        def wrong_checksum(**request):
            response = original(**request)
            self.s3.objects[(request["Bucket"], request["Key"])]["ChecksumSHA256"] = "AAAA"
            return response
        self.s3.put_object = wrong_checksum
        self.assertFalse(self.pub.publish("a", b"expected").ok)

    def test_lost_acknowledgement_is_resolved_from_stored_object(self):
        self.s3.faults.fail("put_object", TimeoutError(), mode="after")
        self.assertEqual(self.pub.publish("a", b"x").status, "PUBLISHED")

    def test_failed_put_is_uncertain_not_published(self):
        self.s3.faults.fail("put_object", FakeClientError("SlowDown"), mode="before")
        result = self.pub.publish("a", b"x")
        self.assertEqual((result.status, result.ok), ("UNCERTAIN", False))
        self.assertNotIn((BUCKET, PREFIX + "a"), self.s3.objects)

    def test_read_back_failure_is_uncertain(self):
        self.s3.faults.fail("get_object_attributes", TimeoutError())
        self.assertEqual(self.pub.publish("a", b"x").status, "UNCERTAIN")

    def test_names_cannot_escape_the_run_prefix(self):
        for bad in ("../other/a", "/abs", "a//b", "a\\b", "", "a b", "run/../../x", "é"):
            result = self.pub.publish(bad, b"x")
            self.assertEqual(result.status, "REJECTED", bad)
        self.assertEqual(self.s3.objects, {})
        for prefix in ("runs/x", "../", "/runs/", ""):
            with self.assertRaises(ValueError):
                S3Publisher(self.s3, BUCKET, prefix)

    def test_publisher_has_no_delete_or_overwrite_call(self):
        import inspect
        import src.aws_c.s3_publisher as module
        source = inspect.getsource(module)
        for forbidden in ("delete_object", "copy_object", "put_object_acl", "IfMatch="):
            self.assertNotIn(forbidden, source)
        self.assertEqual(source.count("put_object("), 1)


class ExportCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="siteproof-awsc-test-")
        self.addCleanup(self._tmp.cleanup)
        self.export = Path(self._tmp.name) / "s1"
        self.jobs = make_export(self.export)
        self.s3 = FakeS3()
        self.pub = S3Publisher(self.s3, BUCKET, PREFIX)

    def publish(self, signer=None, verification=None, **kw):
        verification = verification or verify_local(self.export / "siteproof.sqlite", self.export)
        return publish_run(self.pub, signer or UnsignedSigner(), pilot_run_id=RUN_ID,
                           export_root=self.export, verification=verification,
                           created_at=AT, **kw)

    def stored(self, name):
        return self.s3.objects[(BUCKET, PREFIX + name)]["Body"]


class LocalVerification(ExportCase):
    def test_existing_planner_accepts_an_untouched_export(self):
        self.assertEqual(verify_local(self.export / "siteproof.sqlite", self.export),
                         {"status": "CONSISTENT", "findings": []})

    def test_tampered_screenshot_is_inconsistent(self):
        png = next(self.export.rglob("*.png"))
        png.write_bytes(png.read_bytes() + b"x")
        result = verify_local(self.export / "siteproof.sqlite", self.export)
        self.assertEqual(result["status"], "INCONSISTENT")
        self.assertEqual(result["findings"][0]["code"], "EVIDENCE_INCONSISTENT")

    def test_tampered_manifest_is_inconsistent(self):
        manifest = next(self.export.rglob("manifest.json"))
        manifest.write_text(manifest.read_text("utf-8").replace("UNKNOWN", "PASS"), "utf-8")
        self.assertEqual(verify_local(self.export / "siteproof.sqlite", self.export)["status"],
                         "INCONSISTENT")

    def test_missing_artifact_and_stray_file_are_inconsistent(self):
        next(self.export.rglob("*.png")).unlink()
        self.assertEqual(verify_local(self.export / "siteproof.sqlite", self.export)["status"],
                         "INCONSISTENT")
        other = Path(self._tmp.name) / "s2"
        make_export(other)
        (other / "injected.bin").write_bytes(b"x")
        result = verify_local(other / "siteproof.sqlite", other)
        self.assertEqual([f["code"] for f in result["findings"]], ["ORPHAN_FILE"])

    def test_missing_database_is_unverified_not_consistent(self):
        result = verify_local(self.export / "missing.sqlite", self.export)
        self.assertIn(result["status"], ("UNVERIFIED", "INCONSISTENT"))
        self.assertNotEqual(result["status"], "CONSISTENT")

    def test_verification_does_not_modify_the_export(self):
        before = {p: p.read_bytes() for p in self.export.rglob("*") if p.is_file()}
        verify_local(self.export / "siteproof.sqlite", self.export)
        after = {p: p.read_bytes() for p in self.export.rglob("*") if p.is_file()}
        self.assertEqual(before, after)


class RunPublication(ExportCase):
    def test_all_files_then_manifest_then_signature(self):
        summary = self.publish(extra={"validation-result.json": b"{}"})
        self.assertTrue(summary["committed"])
        self.assertEqual(summary["failed_objects"], [])
        document = json.loads(self.stored(RUN_MANIFEST_NAME))
        local = {"s1/" + name: path.read_bytes() for name, path in collect(self.export)[0]}
        listed = {o["name"]: o for o in document["objects"]}
        self.assertEqual(set(listed), set(local) | {"run/validation-result.json"})
        for name, data in local.items():
            self.assertEqual(listed[name]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(self.stored(name), data)                # bytes unchanged
        puts = [k for (_, k) in self.s3.objects]
        self.assertEqual(puts[-2:], [PREFIX + RUN_MANIFEST_NAME, PREFIX + SIGNATURE_NAME])

    def test_manifest_keeps_quality_unknown_and_profile_unattested(self):
        self.publish()
        claims = json.loads(self.stored(RUN_MANIFEST_NAME))["claims"]
        self.assertEqual(claims, {"quality": "UNKNOWN", "profile_trust": "PROFILE_UNATTESTED",
                                  "target_scope": "CONTROLLED_FIXTURE_ONLY"})

    def test_existing_manifest_json_files_are_published_byte_identical(self):
        self.publish()
        for manifest in self.export.rglob("manifest.json"):
            name = "s1/" + manifest.relative_to(self.export).as_posix()
            self.assertEqual(self.stored(name), manifest.read_bytes())

    def test_inconsistent_export_is_preserved_but_not_committed(self):
        png = next(self.export.rglob("*.png"))
        png.write_bytes(b"tampered")
        summary = self.publish()
        self.assertFalse(summary["committed"])
        self.assertTrue(summary["all_objects_published"])            # failure is evidence too
        document = json.loads(self.stored(RUN_MANIFEST_NAME))
        self.assertEqual(document["local_verification"]["status"], "INCONSISTENT")

    def test_one_failed_object_blocks_commit_and_is_named(self):
        self.s3.faults.fail("put_object", FakeClientError("SlowDown"), skip=2)
        summary = self.publish()
        self.assertFalse(summary["committed"])
        self.assertEqual(len(summary["failed_objects"]), 1)
        document = json.loads(self.stored(RUN_MANIFEST_NAME))
        self.assertFalse(document["all_objects_published"])

    def test_rerun_is_idempotent_and_never_replaces_objects(self):
        first = self.publish()
        bodies = {k: v["Body"] for k, v in self.s3.objects.items()}
        second = self.publish()
        self.assertTrue(first["committed"] and second["committed"])
        self.assertEqual(second["manifest_status"], "EXISTS_IDENTICAL")
        self.assertEqual(bodies, {k: v["Body"] for k, v in self.s3.objects.items()})

    def test_rerun_after_local_change_conflicts_instead_of_overwriting(self):
        self.publish()
        png = next(self.export.rglob("*.png"))
        original = png.read_bytes()
        png.write_bytes(b"changed after publication")
        summary = self.publish()
        self.assertFalse(summary["committed"])
        name = "s1/" + png.relative_to(self.export).as_posix()
        self.assertIn(name, summary["failed_objects"])
        self.assertEqual(self.stored(name), original)
        self.assertEqual(summary["manifest_status"], "CONFLICT")

    def test_empty_or_missing_export_is_not_committed(self):
        empty = Path(self._tmp.name) / "none"
        summary = publish_run(self.pub, UnsignedSigner(), pilot_run_id=RUN_ID,
                              export_root=empty, verification={"status": "CONSISTENT"},
                              created_at=AT)
        self.assertFalse(summary["committed"])
        self.assertEqual(summary["problems"], ["EXPORT_ROOT_MISSING"])

    def test_symbolic_links_are_refused(self):
        target = Path(self._tmp.name) / "outside.txt"
        target.write_text("secret", "utf-8")
        link = self.export / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted on this host")
        files, problems = collect(self.export)
        self.assertNotIn("link.txt", [name for name, _ in files])
        self.assertEqual(problems, ["LINK_REFUSED:link.txt"])


class Signing(ExportCase):
    def test_unsigned_is_reported_as_unsigned(self):
        summary = self.publish()
        envelope = json.loads(self.stored(SIGNATURE_NAME))
        self.assertEqual((summary["signature_status"], envelope["status"]),
                         ("UNSIGNED", "UNSIGNED"))
        self.assertNotIn("signature_b64", envelope)

    def test_kms_signature_covers_exact_manifest_bytes(self):
        kms = FakeKms()
        summary = self.publish(signer=KmsSigner(kms, "alias/siteproof-evidence"))
        manifest = self.stored(RUN_MANIFEST_NAME)
        envelope = json.loads(self.stored(SIGNATURE_NAME))
        self.assertEqual(summary["signature_status"], "SIGNED")
        self.assertEqual(envelope["signed_sha256"], hashlib.sha256(manifest).hexdigest())
        self.assertEqual(kms.sign_calls[0]["MessageType"], "DIGEST")
        self.assertEqual(kms.sign_calls[0]["SigningAlgorithm"], "ECDSA_SHA_256")
        self.assertEqual(verify_with_kms(kms, envelope, manifest), "VALID")
        self.assertEqual(verify_with_kms(kms, envelope, manifest + b" "), "INVALID")
        forged = dict(envelope, signature_b64="AAAA")
        self.assertEqual(verify_with_kms(kms, forged, manifest), "INVALID")
        self.assertEqual(verify_with_kms(FakeKms(b"other-key"), envelope, manifest), "INVALID")

    def test_sign_failure_is_recorded_and_evidence_still_committed(self):
        kms = FakeKms()
        kms.faults.fail("sign", FakeClientError("AccessDeniedException"))
        summary = self.publish(signer=KmsSigner(kms, "key-1"))
        self.assertEqual(summary["signature_status"], "SIGN_FAILED")
        self.assertTrue(summary["committed"])        # integrity holds; authenticity does not
        envelope = json.loads(self.stored(SIGNATURE_NAME))
        self.assertEqual(verify_with_kms(kms, envelope, self.stored(RUN_MANIFEST_NAME)),
                         "UNSIGNED")

    def test_verifier_states(self):
        kms = FakeKms()
        self.assertEqual(verify_with_kms(kms, {"schema": "x"}, b"m"), "UNVERIFIABLE")
        self.assertEqual(verify_with_kms(kms, None, b"m"), "UNVERIFIABLE")
        envelope = KmsSigner(kms, "key-1").sign(b"m")
        kms.faults.fail("verify", TimeoutError())
        self.assertEqual(verify_with_kms(kms, envelope, b"m"), "UNVERIFIABLE")

    def test_signature_does_not_change_claims(self):
        self.publish(signer=KmsSigner(FakeKms(), "key-1"))
        claims = json.loads(self.stored(RUN_MANIFEST_NAME))["claims"]
        self.assertEqual((claims["quality"], claims["profile_trust"]),
                         ("UNKNOWN", "PROFILE_UNATTESTED"))


if __name__ == "__main__":
    unittest.main()
