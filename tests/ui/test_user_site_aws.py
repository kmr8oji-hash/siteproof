"""A user's own site: imported AWS-B results reach HOME, the author's AWS records never appear on it, and no drive letter is needed.

Offline and synthetic only: no AWS, no network, no Docker.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from src.noxiworks import operations
from src.noxiworks.archive import Archive, import_export
from src.noxiworks.site_workflow import Site

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 22, 6, 0, 0, tzinfo=timezone.utc)


def stamp(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%SZ')


def write_export(directory, page_id):
    (directory / page_id).mkdir(parents=True)
    (directory / 'manifest.json').write_text(json.dumps({'schema': 'siteproof.aws-b-export.v1', 'source': 'AWS_EXPORT', 'target_ids': [page_id],
                                                         'exported_at': stamp(NOW - timedelta(minutes=2))}), encoding='utf-8')
    slots = [NOW - timedelta(hours=h, minutes=10) for h in (3, 2, 1, 0)]
    (directory / page_id / 'head.json').write_text(json.dumps({'Item': {
        'pk': {'S': 'CONTROL#' + page_id}, 'sk': {'S': 'HEAD'}, 'enabled': {'BOOL': True}, 'execution_generation': {'N': '1'},
        'policy_version': {'S': 'p1'}, 'target_hostname': {'S': 'www.example.com'}, 'last_slot': {'S': stamp(slots[-1])}}}), encoding='utf-8')
    items = [{'pk': {'S': 'RUN#' + page_id}, 'sk': {'S': stamp(t)}, 'state': {'S': 'RECORDED'}, 'outcome': {'S': 'FAIL' if i == 1 else 'PASS'},
              'reason': {'S': 'HTTP_503' if i == 1 else 'HTTP_200'}, 'http_status': {'N': '503' if i == 1 else '200'}, 'elapsed_ms': {'N': '120'},
              'claimed_at': {'S': stamp(t + timedelta(seconds=1))}, 'finished_at': {'S': stamp(t + timedelta(seconds=2))},
              'execution_generation': {'N': '1'}, 'policy_version': {'S': 'p1'}} for i, t in enumerate(slots)]
    (directory / page_id / 'runs.json').write_text(json.dumps({'Items': items}), encoding='utf-8')


class UserSiteAws(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.site = Site.register(self.root / 'sites', 'MySite', 'https://www.example.com/', ['Desktop'], True, NOW)
        self.targets = self.site.root / 'targets.json'
        self.plan = self.site.root / 'capture_plan.json'

    def test_the_default_pages_still_show_the_authors_records(self):
        with mock.patch.dict(os.environ):
            os.environ.pop('SITEPROOF_TARGETS', None)
            self.assertFalse(operations.user_site())
            self.assertIn('5サイトの監視', operations.home_section())

    def test_a_users_pages_never_show_the_authors_aws_records(self):
        with mock.patch.dict(os.environ, {'SITEPROOF_TARGETS': str(self.targets)}):
            self.assertTrue(operations.user_site())
            section = operations.home_section()
            self.assertNotIn('5サイトの監視', section)
            self.assertIn('未取得', section)
            out = self.root / 'ops'
            out.mkdir()
            operations.write(out)
            page = (out / 'aws-operations.html').read_text('utf-8')
            self.assertNotIn('2026-11-15', page)
            self.assertIn('未取得', page)

    def test_import_export_to_home_without_any_drive_and_for_the_registered_page(self):
        page_id = self.site.page_id
        export = self.root / 'export'
        write_export(export, page_id)
        archive_dir = self.root / 'aws-archive'
        with mock.patch.dict(os.environ, {'SITEPROOF_TARGETS': str(self.targets), 'SITEPROOF_CAPTURE_PLAN': str(self.plan)}):
            result = import_export(Archive(archive_dir), export)
            self.assertEqual(result['counts']['new'], 4)
            self.assertEqual(Archive(archive_dir).verify(), [])
            # an export that names a page that is not the user's is refused (the author's pages are not configured here)
            other = self.root / 'other'
            write_export(other, 'noxiworks-home')
            with self.assertRaises(ValueError):
                import_export(Archive(self.root / 'a2'), other)
        out = self.root / 'home'
        done = subprocess.run([sys.executable, '-B', '-m', 'src.noxiworks', '--archive', str(archive_dir), '--out', str(out), '--now', stamp(NOW),
                               '--targets', str(self.targets), '--capture-plan', str(self.plan)],
                              cwd=ROOT, capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        text = ''.join((out / name).read_text('utf-8') for name in ('index.html', 'activity.html', 'details.html'))
        self.assertIn('MySite', text)
        self.assertIn('503', text)
        for author in ('noxiworks.com', 'Tokyo Trouble Navi', '5サイトの監視'):
            self.assertNotIn(author, text)


if __name__ == '__main__':
    unittest.main()
