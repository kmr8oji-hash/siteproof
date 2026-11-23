"""Synthetic local fixtures only. No AWS/browser; Node checks embedded function."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urljoin

from infra.public_web import package_public as p
from tests.aws_public.test_template_contract import audit


class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="release-package-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.web = self.root / "web"
        self.web.mkdir()
        for page, other in (("home", "compare"), ("compare", "home")):
            folder = self.web / page
            folder.mkdir()
            (folder / "index.html").write_text(
                '<!doctype html><html lang="ja"><head><link rel="stylesheet" href="styles.css">'
                '<script src="app.js" defer></script></head><body><a href="#main">skip</a>'
                f'<a href="../{other}/index.html">other</a><main id="main"></main></body></html>', encoding="utf-8")
            (folder / "styles.css").write_text("body { color: navy; }", encoding="utf-8")
            (folder / "app.js").write_text("'use strict';", encoding="utf-8")
        self.output = self.root / "new-release"
        self.template = self.root / "template.json"
        shutil.copyfile(p.DEFAULT_TEMPLATE, self.template)

    def build(self, **kwargs):
        return p.create_package(self.web, self.output, self.template, **kwargs)

    def mutate_template(self, change):
        doc = p.strict_json(self.template.read_bytes())
        change(doc)
        self.template.write_text(json.dumps(doc), encoding="utf-8")

    def test_exact_six_unchanged_bytes_hash_manifest_and_readback(self):
        manifest = self.build()
        self.assertEqual(manifest, p.verify_package(self.output, self.template))
        self.assertEqual([r["key"] for r in manifest["files"]], list(p.KEYS))
        self.assertEqual({x.name for x in self.output.iterdir()}, {"payload", "review_manifest.json"})
        for entry in manifest["files"]:
            data = (self.web / entry["key"]).read_bytes()
            self.assertEqual((self.output / "payload" / entry["key"]).read_bytes(), data)
            self.assertEqual(entry["sha256"], p.hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["bytes"], len(data))
            self.assertFalse(Path(entry["source"]).is_absolute())
        self.assertTrue(manifest["navigation_complete"])
        self.assertEqual(manifest["aws_live"], "NO-GO")

    def test_deterministic_manifest_no_timestamp_or_absolute_path(self):
        first = self.build()
        second = p.create_package(self.web, self.root / "another", self.template)
        self.assertEqual(first, second)
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_missing_file_refused_before_output_created(self):
        (self.web / "home/app.js").unlink()
        with self.assertRaises(p.PackageError): self.build()
        self.assertFalse(self.output.exists())

    def test_unexpected_internal_files_and_directories_refused(self):
        for name in ("db.sqlite", "manifest.json", ".env", ".git", "fixture.py"):
            extra = self.web / name
            extra.write_text("synthetic forbidden extra", encoding="utf-8")
            with self.assertRaises(p.PackageError): self.build()
            extra.unlink()  # only this test's fixture
        (self.web / "home/extra").mkdir()
        with self.assertRaises(p.PackageError): self.build()

    def test_traversal_and_source_overlap_refused(self):
        with self.assertRaises(p.PackageError):
            p.create_package(self.web / ".." / "web", self.output, self.template)
        with self.assertRaises(p.PackageError):
            p.create_package(self.web, self.root / "x" / ".." / "out", self.template)
        with self.assertRaises(p.PackageError):
            p.create_package(self.web, self.web / "out", self.template)

    def test_existing_empty_or_populated_output_never_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(p.PackageError): self.build()
        marker = self.output / "preserve.txt"
        marker.write_text("untouched", encoding="utf-8")
        with self.assertRaises(p.PackageError): self.build()
        self.assertEqual(marker.read_text(), "untouched")

    def test_hard_link_input_refused(self):
        source = self.web / "home/app.js"
        os.link(source, self.root / "linked.js")
        with self.assertRaises(p.PackageError): self.build()

    def test_symlink_and_reparse_flags_rejected_at_leaf_and_ancestor(self):
        # Portable, deterministic lstat simulation (no Windows symlink privilege).
        real = Path.lstat
        for target in (self.web, self.web / "home", self.web / "home/app.js"):
            for attribute in ("symlink", "reparse"):
                def fake(path, *, follow_symlinks=True):
                    s = real(path)
                    if path == target:
                        return SimpleNamespace(st_mode=0o120777 if attribute == "symlink" else s.st_mode,
                                               st_file_attributes=0x400 if attribute == "reparse" else 0)
                    return s
                with patch.object(Path, "lstat", fake), self.assertRaises(p.PackageError):
                    self.build()

    def test_changed_identity_during_read_refused(self):
        real = os.fstat
        def changed(fd):
            s = real(fd)
            return SimpleNamespace(st_dev=s.st_dev, st_ino=s.st_ino + 1, st_size=s.st_size,
                                   st_mtime_ns=s.st_mtime_ns, st_ctime_ns=s.st_ctime_ns)
        with patch.object(os, "fstat", changed), self.assertRaises(p.PackageError): self.build()

    def test_binary_invalid_utf8_oversize_assets_refused(self):
        for content in (b"\0binary", b"\xff", b"x" * (p.LIMIT + 1), b""):
            (self.web / "home/app.js").write_bytes(content)
            with self.assertRaises((p.PackageError, UnicodeError)): self.build()

    def test_malicious_refs_external_traversal_unknown_asset_and_base_refused(self):
        page = self.web / "home/index.html"
        original = page.read_text(encoding="utf-8")
        for ref in ("https://bad.invalid/a", "//bad.invalid/a", "javascript:alert(1)",
                    "../../secret", "../compare/extra.js", "%2e%2e/compare/index.html", "../compare/index.html?data=x"):
            page.write_text(original.replace("../compare/index.html", ref), encoding="utf-8")
            with self.assertRaises(p.PackageError): self.build()
        page.write_text(original.replace("<head>", '<head><base href="/">'), encoding="utf-8")
        with self.assertRaises(p.PackageError): self.build()

    def test_css_and_javascript_dependencies_refused(self):
        for key, bad in (("home/styles.css", "@import 'x.css';"), ("home/styles.css", "a{background:url(x)}"),
                         ("home/app.js", "fetch('/api');"), ("home/app.js", "new WebSocket('x');")):
            path = self.web / key
            original = path.read_bytes()
            path.write_text(bad, encoding="utf-8")
            with self.assertRaises(p.PackageError): self.build()
            path.write_bytes(original)

    def test_duplicate_html_attributes_cannot_hide_external_reference(self):
        page = self.web / "home/index.html"
        original = page.read_text(encoding="utf-8")
        for markup in (original.replace('href="../compare/index.html"', 'href="https://external.invalid" href="../compare/index.html"'),
                       original.replace('src="app.js"', 'SRC="https://external.invalid/x.js" src="app.js"')):
            page.write_text(markup, encoding="utf-8")
            with self.assertRaises(p.PackageError): self.build()

    def test_known_credential_shapes_refused_without_reading_any_real_secret(self):
        (self.web / "home/app.js").write_text('aws_secret_access_key="SYNTHETIC_NOT_A_SECRET";', encoding="utf-8")
        with self.assertRaises(p.PackageError): self.build()

    def test_preintegration_is_explicit_and_manifest_reports_missing_navigation(self):
        page = self.web / "home/index.html"
        page.write_text(page.read_text().replace('<a href="../compare/index.html">other</a>', ''), encoding="utf-8")
        with self.assertRaises(p.PackageError): self.build()
        self.assertFalse(self.build(require_navigation=False)["navigation_complete"])

    def test_template_wrong_keys_origin_root_or_redirect_refused(self):
        original = self.template.read_bytes()
        changes = [lambda d: d["Metadata"]["ApprovedObjectKeys"].append("secret.db"),
                   lambda d: d["Resources"]["Distribution"]["Properties"]["DistributionConfig"].update(DefaultRootObject="index.html"),
                   lambda d: d["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["Origins"][0].update(OriginPath="/public"),
                   lambda d: d["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"].update(FunctionAssociations=[]),
                   lambda d: d["Resources"]["RootRedirect"]["Properties"].update(FunctionCode="return request;"),
                   lambda d: d["Resources"]["AssetsBucket"]["Properties"].update(PublicAccessBlockConfiguration=dict.fromkeys(["bad1", "bad2", "bad3", "bad4"], True)),
                   lambda d: d["Resources"]["AssetsPolicy"]["Properties"]["PolicyDocument"]["Statement"][1].update(Condition={}),
                   lambda d: d["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["Origins"][0].update(OriginAccessControlId="unapproved")]
        for change in changes:
            self.mutate_template(change)
            with self.assertRaises(p.PackageError): self.build()
            self.template.write_bytes(original)

    def test_public_policy_cannot_expand_principal_action_or_keys(self):
        original = self.template.read_bytes()
        for name, value in (("Principal", "*"), ("Action", "s3:*"), ("Resource", ["*"]), ("Condition", {})):
            self.mutate_template(lambda d: d["Resources"]["AssetsPolicy"]["Properties"]["PolicyDocument"]["Statement"][0].update({name: value}))
            with self.assertRaises(p.PackageError): self.build()
            self.template.write_bytes(original)

    def test_manifest_tampering_types_duplicate_keys_and_extra_root_refused(self):
        self.build()
        path = self.output / "review_manifest.json"
        original = path.read_bytes()
        for field, value in (("aws_live", "GO"), ("navigation_complete", 1), ("files", [])):
            doc = json.loads(original)
            doc[field] = value
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)
        path.write_text('{"files":[],"files":[]}', encoding="utf-8")
        with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)
        path.write_bytes(original)
        (self.output / "unapproved.txt").write_text("extra")
        with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)

    def test_payload_tampering_and_additional_file_refused(self):
        self.build()
        (self.output / "payload/home/app.js").write_text("changed")
        with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)
        (self.output / "payload/secrets.txt").write_text("synthetic")
        with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)

    def test_write_failure_leaves_partial_output_and_never_claims_success(self):
        original = p.write_new
        count = 0
        def fail_second(path, data):
            nonlocal count
            count += 1
            if count == 2: raise OSError("synthetic disk failure")
            original(path, data)
        with patch.object(p, "write_new", fail_second), self.assertRaises(OSError): self.build()
        self.assertTrue(self.output.is_dir())
        with self.assertRaises(p.PackageError): p.verify_package(self.output, self.template)
        with self.assertRaises(p.PackageError): self.build()

    def test_real_assets_checked_without_guessing_other_lane_hashes(self):
        web = Path(__file__).resolve().parents[2] / "web"
        files, manifest = p.inspect_sources(web, require_navigation=False)
        self.assertEqual(set(files), set(p.KEYS))
        if manifest["navigation_complete"]:
            self.assertEqual(p.inspect_sources(web)[1], manifest)
        else:
            with self.assertRaises(p.PackageError): p.inspect_sources(web)

    def test_root_alias_hazard_and_fixed_redirect_resolve_all_references(self):
        self.assertEqual(urljoin("https://offline.invalid/", "styles.css"), "https://offline.invalid/styles.css")
        self.assertNotIn("styles.css", p.KEYS)
        for ref, key in (("styles.css", "home/styles.css"), ("app.js", "home/app.js"), ("../compare/index.html", "compare/index.html")):
            self.assertEqual(urljoin("https://offline.invalid/home/index.html", ref), "https://offline.invalid/" + key)
        doc = p.strict_json(self.template.read_bytes())
        self.assertEqual(audit(doc), [])
        code = doc["Resources"]["RootRedirect"]["Properties"]["FunctionCode"]
        # Installed Node only; this is not an AWS runtime or real browser.
        script = code + "\nconst assert=require('node:assert/strict'); const root=handler({request:{uri:'/',headers:{host:{value:'evil.invalid'}},querystring:{x:{value:'hostile'}}}}); assert.equal(root.statusCode,302); assert.equal(root.headers.location.value,'/home/index.html'); assert.equal(root.headers['cache-control'].value,'no-store'); for(const uri of ['/home/index.html','/compare/index.html','/secret','//evil.invalid','/%2f']) {const r={uri}; assert.equal(handler({request:r}),r);}"
        proc = subprocess.run(["node", "-"], input=script, text=True, capture_output=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__": unittest.main()
