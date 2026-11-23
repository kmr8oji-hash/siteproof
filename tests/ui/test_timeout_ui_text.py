"""UI wording after a failed real capture: no "runs again" promise while monitoring is stopped or the permit cannot run, and an
automatically created Baseline is never worded as a formal USER approval. Offline: the real app.js function runs in node.

What this does NOT show: the rendered browser page (that is checked by the GUI rehearsal, not here).
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
APP_JS = (ROOT / 'src/noxiworks/app_assets/app.js').read_text('utf-8')
NODE = shutil.which('node')


@unittest.skipUnless(NODE, 'node not available')
class RerunPromise(unittest.TestCase):
    def again(self, **state):
        source = re.search(r'  function again\(s, whenAuto\) \{.*?\n  \}\n', APP_JS, re.S).group(0)
        script = source + 'process.stdout.write(JSON.stringify(again(' + json.dumps(state) + ", 'AUTO')));"
        return json.loads(subprocess.run([NODE, '-e', script], capture_output=True, text=True, encoding='utf-8', timeout=30, check=True).stdout)

    def test_monitoring_stopped_never_promises_a_rerun(self):
        text = self.again(monitor={'enabled': False}, real_capture_available=True)
        self.assertIn('自動では再実行しません', text)
        self.assertNotIn('AUTO', text)

    def test_permit_exhausted_or_conditions_unmet_never_promises_a_rerun(self):
        text = self.again(monitor={'enabled': True}, real_capture_available=False)
        self.assertIn('自動では再実行しません', text)
        self.assertNotIn('AUTO', text)

    def test_the_promise_is_kept_only_while_everything_holds(self):
        self.assertEqual(self.again(monitor={'enabled': True}, real_capture_available=True), 'AUTO')

    def test_every_failure_notice_goes_through_it(self):
        for outcome in ("'UNKNOWN'", "'FAILED'", "'NO_BASELINE'"):
            line = next(l for l in APP_JS.splitlines() if "last.outcome === " + outcome in l)
            self.assertIn('again(s,', line, outcome)
        self.assertNotIn("再実行します。'];", APP_JS)


class BaselineWording(unittest.TestCase):
    def source(self, name):
        return (ROOT / 'src/noxiworks' / name).read_text('utf-8')

    def test_an_auto_created_baseline_is_not_called_approved(self):
        review, captures = self.source('review.py'), self.source('captures.py')
        self.assertIn('baseline_standing', review)                      # the wording follows the Baseline's standing (see test_ui_state_fix)
        self.assertIn('正式承認ではない', review)
        self.assertIn('正式承認ではない', captures)

    def test_the_formal_approval_wording_remains_for_a_user_approved_baseline(self):
        review, captures = self.source('review.py'), self.source('captures.py')
        for text in ('Baseline承認済み', 'USERが承認済みです', '（USER承認）'):
            self.assertIn(text, review)
        self.assertIn('Baseline承認済み・承認後の撮影と比較は未実施', captures)

    def test_the_auto_actor_prefix_matches_the_actor_the_monitor_records(self):
        from src.noxiworks.site_monitor import AUTO_ACTOR
        self.assertTrue(AUTO_ACTOR.startswith('SiteProof自動作成'))


if __name__ == '__main__':
    unittest.main()
