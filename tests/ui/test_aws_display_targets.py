"""AWS-B pages of an imported archive are DISPLAYED next to a registered site without editing that site's signed targets.json.

Why it was needed: the archive's public files embed each page's label/URL from the active targets, so a build with the site's targets refused an archive
imported with the repo's targets ("public file differs from a rebuild"), and the only way to show the AWS pages was to add them to the site's targets.json,
which a monitoring permit pins (permit.TARGET_FILES): the permit then no longer matched. Offline: the capture test double and local files only.
"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from src.noxiworks import archive as archives
from src.noxiworks import product
from src.noxiworks.app import utc_now
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]
AWS = ['noxiworks-home', 'noxiworks-taxi', 'hms-home', 'hms-concierge', 'ttn-home']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Metadata(unittest.TestCase):
    def test_the_archives_page_metadata_does_not_depend_on_the_active_targets(self):
        default = archives._target_meta()
        self.assertTrue(set(AWS) <= set(default))
        with mock.patch.dict('os.environ', {'SITEPROOF_TARGETS': str(ROOT / 'src/noxiworks/targets.json')}):
            self.assertEqual(archives._target_meta(), default)


@needs_ssh
class WithASite(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=3)
        self.site = self.app.site
        self.manifest = self.site.root / 'aws-archive' / 'public' / 'MANIFEST.json'

    def archive_lists(self, targets):
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(json.dumps({'targets': {t: {} for t in targets}}), encoding='utf-8')

    def test_nothing_to_add_without_an_archive(self):
        self.assertIsNone(self.app.display_targets(self.site))

    def test_the_five_pages_are_offered_as_a_separate_display_file_and_the_signed_files_are_untouched(self):
        before = {n: sha(self.site.root / n) for n in ('targets.json', 'capture_plan.json', 'real/permit.json', 'real/permit.json.sig')}
        self.archive_lists(AWS + ['aws-b-http-fixture'])                     # the fixture is not a repo page: not shown
        out = self.app.display_targets(self.site)
        data = json.loads(out.read_text('utf-8'))
        self.assertEqual([p['target_id'] for p in data['pages']], AWS)
        self.assertEqual(out.parent, self.site.root)
        self.assertNotEqual(out.name, 'targets.json')
        self.assertEqual({n: sha(self.site.root / n) for n in before}, before)

    def test_registered_ids_win_and_an_explicit_path_ignores_the_display_file(self):
        self.archive_lists(AWS)
        out = self.app.display_targets(self.site)
        with mock.patch.dict('os.environ', {'SITEPROOF_TARGETS': str(self.site.root / 'targets.json'), 'SITEPROOF_DISPLAY_TARGETS': str(out)}):
            ids = [p['target_id'] for p in product.settings()['pages']]
            self.assertEqual(ids, [self.site.page_id] + AWS)
            self.assertEqual([p['target_id'] for p in product.settings(self.site.root / 'targets.json')['pages']], [self.site.page_id])
        registered = json.loads((self.site.root / 'targets.json').read_text('utf-8'))
        registered['pages'].append({**json.loads(out.read_text('utf-8'))['pages'][0], 'label': 'MINE'})
        mine = self.site.root / 'mine.json'
        mine.write_text(json.dumps(registered), encoding='utf-8')
        with mock.patch.dict('os.environ', {'SITEPROOF_TARGETS': str(mine), 'SITEPROOF_DISPLAY_TARGETS': str(out)}):
            labels = {p['target_id']: p['label'] for p in product.settings()['pages']}
            self.assertEqual(labels[AWS[0]], 'MINE')

    def test_the_permit_still_matches_and_a_changed_target_is_still_refused(self):
        self.archive_lists(AWS)
        self.app.display_targets(self.site)
        self.app.rebuild_site()                                              # a build with the display file must not change what the permit pins
        ready = lambda: {c['key']: c['ok'] for c in self.app.monitor().real().readiness(utc_now())}
        self.assertTrue(ready()['permission'])
        targets = self.site.root / 'targets.json'
        original = targets.read_text('utf-8')
        data = json.loads(original)
        data['pages'].append(json.loads((self.site.root / 'aws-display-targets.json').read_text('utf-8'))['pages'][0])
        targets.write_text(json.dumps(data), encoding='utf-8')               # the old workaround: editing the signed file
        self.assertFalse(ready()['permission'])                              # is refused, exactly as before (verification not relaxed)
        targets.write_text(original, encoding='utf-8')
        self.assertTrue(ready()['permission'])


if __name__ == '__main__':
    unittest.main()
