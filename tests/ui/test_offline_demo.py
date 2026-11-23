"""tools/build_offline_demo.py: the repository-only demo builds offline, covers every case, and is labelled synthetic throughout."""
import json
from pathlib import Path
import tempfile
import unittest

from src.aws_b.model import parse_utc
from src.noxiworks.baseline_registry import read as read_registry
from src.noxiworks.local_capture import LocalCaptureRefused, attach
from src.noxiworks.product import empty_snapshot
from tools.build_offline_demo import DEMO_NOW, DOWN_PAGE, build_demo


class OfflineDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='siteproof-demo-')
        cls.out = Path(cls.tmp.name) / 'demo'
        cls.report = build_demo(cls.out, parse_utc(DEMO_NOW))
        cls.view = json.loads((cls.out / 'ui' / 'view.json').read_text('utf-8'))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_three_cases_for_both_profiles(self):
        self.assertEqual(self.report['cases'], {
            'unchanged': {'Desktop': 'NO_VISUAL_CHANGE_DETECTED', 'Mobile': 'NO_VISUAL_CHANGE_DETECTED'},
            'unstable': {'Desktop': 'UNKNOWN', 'Mobile': 'UNKNOWN'},
            'changed': {'Desktop': 'VISUAL_CHANGED', 'Mobile': 'VISUAL_CHANGED'}})
        self.assertFalse(self.report['real_site_access'] or self.report['aws_access'])

    def test_view_is_synthetic_with_http_images_and_history(self):
        self.assertEqual(self.view['source'], 'FIXTURE')
        pages = {p['target_id']: p for p in self.view['pages']}
        self.assertEqual({t: p['http']['state'] for t, p in pages.items() if p['http']['state'] != 'UP'}, {DOWN_PAGE: 'DOWN'})
        self.assertEqual(pages['ttn-home']['change']['state'], 'CHANGED')
        self.assertTrue({'baseline', 'diff', 'mobile_baseline', 'mobile_diff'} <= set(pages['ttn-home']['available_assets']))
        classes = sorted(h['class'] for h in self.view['monitoring']['history'])
        self.assertEqual(classes, ['CHANGED', 'CHANGED', 'UNCHANGED', 'UNCHANGED', 'UNKNOWN', 'UNKNOWN'])
        review = (self.out / 'ui' / 'review.html').read_text('utf-8')
        self.assertIn('合成デモの撮影（実サイトの撮影ではありません）', review)
        self.assertNotIn('実サイト撮影：済み', review)

    def test_a_synthetic_run_goes_only_on_an_empty_or_synthetic_snapshot(self):
        run = self.out / 'data' / 'changed' / 'run'
        fixture = json.loads((self.out / 'data' / 'snapshot.json').read_text('utf-8'))
        registry = read_registry(self.out / 'data' / 'registry')
        self.assertEqual(attach(fixture, [run], registry)[0]['source'], 'FIXTURE')
        with self.assertRaises(LocalCaptureRefused):
            attach({**empty_snapshot(), 'source': 'AWS_EXPORT'}, [run], registry)


if __name__ == '__main__':
    unittest.main()
