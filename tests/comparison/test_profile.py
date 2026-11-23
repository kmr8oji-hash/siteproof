"""Pure profile fingerprint tests; no I/O."""

import unittest

from src.comparison.profile import (
    CaptureProfile,
    ComparisonProfile,
    ProfileError,
    ProfileKind,
    check_profile_compatibility,
)

CAPTURE = {
    "viewport_width": 1280,
    "viewport_height": 720,
    "device_scale_factor": 1,
    "color_scheme": "light",
    "locale": "en-US",
    "timezone": "UTC",
    "user_agent": "ua/1",
    "reduced_motion": True,
    "full_page": False,
}
FP = "a" * 64
COMPARISON = {
    "capture_fingerprint": FP,
    "method": "pixel",
    "method_version": "1",
    "threshold_policy": "strict",
}


def cap(pid="p1", **over):
    return CaptureProfile(pid, {**CAPTURE, **over})


class ProfileTests(unittest.TestCase):
    def test_fingerprint_is_stable_sha256_and_order_independent(self):
        a = cap()
        b = CaptureProfile("p1", dict(reversed(list(CAPTURE.items()))))
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertRegex(a.fingerprint, r"^[0-9a-f]{64}$")

    def test_profile_id_does_not_affect_fingerprint_or_grant_compat(self):
        self.assertEqual(cap("a").fingerprint, cap("b").fingerprint)
        self.assertTrue(check_profile_compatibility(cap("a"), cap("b")).compatible)
        self.assertFalse(check_profile_compatibility(cap("same"), cap("same", locale="ja-JP")).compatible)

    def test_any_attribute_change_changes_fingerprint(self):
        base = cap().fingerprint
        for k, v in (("viewport_width", 1281), ("color_scheme", "dark"), ("reduced_motion", False),
                     ("user_agent", "ua/2"), ("full_page", True)):
            self.assertNotEqual(base, cap(**{k: v}).fingerprint, k)

    def test_kinds_are_distinct(self):
        comp = ComparisonProfile("c", COMPARISON)
        self.assertNotEqual(comp.kind, cap().kind)
        res = check_profile_compatibility(cap(), comp)
        self.assertFalse(res.compatible)
        self.assertEqual(res.reason, "KIND_MISMATCH")

    def test_comparison_profile_fingerprint_depends_on_capture_fingerprint(self):
        other = ComparisonProfile("c", {**COMPARISON, "capture_fingerprint": "b" * 64})
        self.assertNotEqual(ComparisonProfile("c", COMPARISON).fingerprint, other.fingerprint)

    def test_missing_attribute_rejected(self):
        d = dict(CAPTURE)
        del d["locale"]
        with self.assertRaises(ProfileError):
            CaptureProfile("p", d)

    def test_unknown_attribute_rejected(self):
        with self.assertRaises(ProfileError):
            CaptureProfile("p", {**CAPTURE, "extra": "x"})

    def test_wrong_types_rejected(self):
        for k, v in (("viewport_width", "1280"), ("viewport_width", 1280.0), ("viewport_width", True),
                     ("viewport_width", 0), ("reduced_motion", 1), ("locale", ""),
                     ("locale", " en"), ("locale", None), ("user_agent", "a\nb")):
            with self.assertRaises(ProfileError, msg=(k, v)):
                cap(**{k: v})

    def test_comparison_profile_requires_valid_capture_fingerprint(self):
        for bad in ("A" * 64, "a" * 63, None, 5):
            with self.assertRaises(ProfileError):
                ComparisonProfile("c", {**COMPARISON, "capture_fingerprint": bad})

    def test_bad_profile_id_and_non_mapping(self):
        for pid in ("", None, 3, "x\t"):
            with self.assertRaises(ProfileError):
                CaptureProfile(pid, CAPTURE)
        with self.assertRaises(ProfileError):
            CaptureProfile("p", [("a", 1)])

    def test_attributes_are_immutable_and_decoupled_from_input(self):
        src = dict(CAPTURE)
        p = CaptureProfile("p", src)
        fp = p.fingerprint
        src["locale"] = "xx"
        with self.assertRaises(TypeError):
            p.attributes["locale"] = "xx"
        with self.assertRaises(Exception):
            p.profile_id = "q"
        self.assertEqual(p.fingerprint, fp)

    def test_non_profile_objects_incompatible(self):
        self.assertEqual(check_profile_compatibility(cap(), CAPTURE).reason, "NOT_A_PROFILE")
        self.assertFalse(check_profile_compatibility(None, None).compatible)


def _corrupt_profiles():
    """Profiles whose internal state was damaged after construction (all must fail closed)."""
    from types import MappingProxyType

    out = {}
    good = dict(CAPTURE)

    def mk(**over):
        return CaptureProfile("p", {**good, **over})

    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({}))
    out["empty attributes"] = p
    p = mk(); object.__setattr__(p, "attributes", None)
    out["attributes None"] = p
    p = mk(); object.__setattr__(p, "attributes", dict(good))
    out["plain dict container"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, "extra": "x"}))
    out["unknown attribute"] = p
    d = dict(good); del d["locale"]
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType(d))
    out["missing attribute"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, "viewport_width": "1280"}))
    out["str instead of int"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, "viewport_width": True}))
    out["bool instead of int"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, "reduced_motion": 1}))
    out["int instead of bool"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, "locale": None}))
    out["None value"] = p
    p = mk(); object.__setattr__(p, "attributes", MappingProxyType({**good, 5: "x"}))
    out["non-str key"] = p
    p = mk(); object.__delattr__(p, "attributes")
    out["attributes deleted"] = p
    p = mk(); object.__delattr__(p, "profile_id")
    out["profile_id deleted"] = p
    p = mk(); object.__setattr__(p, "profile_id", None)
    out["profile_id None"] = p
    p = mk(); object.__setattr__(p, "profile_id", " bad")
    out["profile_id unclean"] = p
    p = mk(); object.__setattr__(p, "KIND", ProfileKind.COMPARISON)
    out["instance KIND shadow"] = p
    p = mk(); object.__setattr__(p, "extra", 1)
    out["extra instance field"] = p
    c = ComparisonProfile("c", COMPARISON)
    object.__setattr__(c, "attributes", MappingProxyType({**COMPARISON, "capture_fingerprint": "A" * 64}))
    out["comparison bad fingerprint"] = c
    c = ComparisonProfile("c", COMPARISON)
    object.__setattr__(c, "attributes", MappingProxyType({**good}))
    out["comparison with capture attributes"] = c
    return out


class CorruptProfileTests(unittest.TestCase):
    def test_corrupt_profiles_are_not_intact_and_fingerprint_is_rejected(self):
        for label, p in _corrupt_profiles().items():
            with self.subTest(label):
                self.assertFalse(p.is_intact())
                with self.assertRaises(ProfileError):
                    p.fingerprint

    def test_corrupt_profile_is_never_compatible_even_with_same_profile_id(self):
        for label, p in _corrupt_profiles().items():
            for other in (cap("p"), p):
                with self.subTest(label):
                    for a, b in ((p, other), (other, p)):
                        res = check_profile_compatibility(a, b)
                        self.assertFalse(res.compatible)
                        self.assertEqual(res.reason, "NOT_A_PROFILE")

    def test_corrupt_profile_cannot_match_by_forging_attributes_of_a_good_one(self):
        from types import MappingProxyType

        good = cap("same")
        forged = cap("same", locale="ja-JP")
        object.__setattr__(forged, "attributes", MappingProxyType({**CAPTURE, "locale": None}))
        self.assertFalse(check_profile_compatibility(good, forged).compatible)

    def test_subclass_overriding_fingerprint_is_not_trusted(self):
        class Fake(CaptureProfile):
            @property
            def fingerprint(self):
                return cap().fingerprint

        fake = Fake("p", CAPTURE)
        self.assertFalse(fake.is_intact())
        self.assertFalse(check_profile_compatibility(cap(), fake).compatible)

    def test_valid_profiles_unchanged(self):
        a = cap()
        self.assertTrue(a.is_intact())
        self.assertTrue(ComparisonProfile("c", COMPARISON).is_intact())
        self.assertEqual(a.kind, ProfileKind.CAPTURE)
        self.assertTrue(check_profile_compatibility(cap("x"), cap("y")).compatible)
        self.assertEqual(check_profile_compatibility(cap(), cap(locale="ja-JP")).reason, "FINGERPRINT_MISMATCH")

    def test_valid_fingerprint_is_pinned(self):
        # Regression guard: the corruption checks must not change the fingerprint of a valid profile.
        import hashlib, json

        body = {"schema": "siteproof.profile.v1", "kind": "capture", "attributes": CAPTURE}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(cap().fingerprint, hashlib.sha256(raw.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
