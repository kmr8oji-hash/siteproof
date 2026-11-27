"""Restore of a verified backup into a NEW folder (offline, temporary folders only): verification first, refusals, every monitor and mail switch OFF in the copy, the
record, partial failure, the command line. The backup and the original data are never changed."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from src.noxiworks import backup, retention
from src.noxiworks.uiview import monitor_view
from tools import restore_backup

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)
A, B = 'site-aaaaaaaa', 'site-bbbbbbbb'


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


def dirs(root):
    return sorted(p.relative_to(root).as_posix() for p in Path(root).rglob('*') if p.is_dir())


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-restore-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        files = {f'sites/{A}/site.json': {'site_id': A}, f'sites/{B}/site.json': {'site_id': B},
                 f'sites/{A}/monitor.json': {'enabled': True, 'interval_seconds': 900, 'next_due_at': '2026-11-25T12:15:00Z', 'paused_reason': None},
                 f'sites/{B}/monitor.json': {'enabled': False, 'paused_reason': 'USER', 'next_due_at': None},
                 f'sites/{A}/http-monitor.json': {'enabled': True, 'ever_enabled': True, 'next_due_at': '2026-11-25T12:05:00Z', 'interval_seconds': 300},
                 f'sites/{A}/pages/{A}-p2/monitor.json': {'enabled': True, 'next_due_at': '2026-11-25T12:30:00Z'},
                 f'sites/{A}/pages/{A}-p2/http-monitor.json': {'enabled': True, 'next_due_at': '2026-11-25T12:30:00Z'},
                 f'sites/{A}/email-notify.json': {'schema': 'siteproof.email-notify.v1', 'enabled': True, 'enabled_at': '2026-11-20T00:00:00Z'},
                 'notify/email.json': {'schema': 'siteproof.email-notify.v1', 'enabled': True, 'enabled_at': '2026-11-20T00:00:00Z', 'stopped_reason': None, 'kinds': ['FAILURE']},
                 'trust/permit-ledger/p1': 'one use'}
        for rel, value in files.items():
            f = self.data / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
        (self.data / 'trust' / 'allowed_signers').write_text('site-owner ssh-ed25519 AAAA', encoding='utf-8')
        (self.data / f'sites/{A}/runs/r1').mkdir(parents=True)
        (self.data / f'sites/{A}/runs/r1/a.txt').write_text('run one', encoding='utf-8')
        (self.data / f'sites/{A}/history.jsonl').write_text('{"n": 1}\n', encoding='utf-8')
        self.kept = self.tmp / 'backups'
        self.kept.mkdir()
        self.made = backup.create(self.data, self.kept, NOW)
        self.backup = Path(self.made['path'])
        self.dest = self.tmp / 'restored'
        self.backup_before, self.data_before = tree(self.backup), tree(self.data)

    def untouched(self):
        self.assertEqual(tree(self.backup), self.backup_before)
        self.assertEqual(tree(self.data), self.data_before)


class Restore(Base):
    def test_a_verified_backup_is_copied_and_every_copy_is_checked(self):
        self.assertTrue(self.made['ok'])
        result = backup.restore(self.backup, self.dest, LATER)
        self.assertEqual((result['ok'], result['problems'], result['path']), (True, [], str(self.dest.resolve())))
        copied, original = tree(self.dest), tree(self.data)
        changed = {'RESTORE-RECORD.json'} | set(result['switched_off'])
        self.assertEqual({k: v for k, v in copied.items() if k not in changed}, {k: v for k, v in original.items() if k not in set(result['switched_off'])})
        self.assertEqual(sorted(result['switched_off']), sorted([f'sites/{A}/monitor.json', f'sites/{B}/monitor.json', f'sites/{A}/http-monitor.json', f'sites/{A}/pages/{A}-p2/monitor.json',
                                                                 f'sites/{A}/pages/{A}-p2/http-monitor.json', f'sites/{A}/email-notify.json', 'notify/email.json']))
        self.untouched()

    def test_empty_runs_and_ui_folders_come_back_for_the_data_the_sites_and_the_pages(self):
        backup.restore(self.backup, self.dest, LATER)
        found = dirs(self.dest)
        for expected in ('runs', 'ui', f'sites/{A}/runs', f'sites/{A}/ui', f'sites/{B}/runs', f'sites/{B}/ui', f'sites/{A}/pages/{A}-p2/runs', f'sites/{A}/pages/{A}-p2/ui'):
            self.assertIn(expected, found)
        self.assertEqual(list((self.dest / 'runs').iterdir()), [])

    def test_every_monitor_and_mail_switch_of_the_copy_is_off_with_the_reason_restored(self):
        backup.restore(self.backup, self.dest, LATER)
        for rel in (f'sites/{A}/monitor.json', f'sites/{B}/monitor.json', f'sites/{A}/http-monitor.json', f'sites/{A}/pages/{A}-p2/monitor.json', f'sites/{A}/pages/{A}-p2/http-monitor.json'):
            value = json.loads((self.dest / rel).read_text('utf-8'))
            self.assertEqual((value['enabled'], value['paused_reason'], value['next_due_at']), (False, 'RESTORED', None), rel)
        for rel in (f'sites/{A}/email-notify.json', 'notify/email.json'):
            value = json.loads((self.dest / rel).read_text('utf-8'))
            self.assertEqual((value['enabled'], value['stopped_reason']), (False, 'RESTORED'), rel)
        self.assertEqual(json.loads((self.dest / 'notify/email.json').read_text('utf-8'))['kinds'], ['FAILURE'])  # the rest of a file is kept
        self.assertEqual(json.loads((self.dest / f'sites/{A}/monitor.json').read_text('utf-8'))['interval_seconds'], 900)
        self.untouched()

    def test_permits_ledgers_and_the_trust_file_are_copied_as_they_are_and_the_record_says_what_changed(self):
        backup.restore(self.backup, self.dest, LATER)
        self.assertEqual(tree(self.dest)['trust/permit-ledger/p1'], tree(self.data)['trust/permit-ledger/p1'])
        self.assertEqual(tree(self.dest)['trust/allowed_signers'], tree(self.data)['trust/allowed_signers'])
        record = json.loads((self.dest / 'RESTORE-RECORD.json').read_text('utf-8'))
        self.assertEqual((record['schema'], record['complete'], record['problems'], record['scope'], record['restored_at'], record['backup_created_at']),
                         ('siteproof.restore-record.v1', True, [], 'ALL', '2026-11-26T09:00:00Z', '2026-11-25T12:00:00Z'))
        self.assertEqual(len(record['switched_off']), 7)
        by_path = {s['path']: s for s in record['switched_off']}
        self.assertEqual((by_path[f'sites/{A}/monitor.json']['was_enabled'], by_path[f'sites/{B}/monitor.json']['was_reason']), (True, 'USER'))
        text = ' '.join(record['note'])
        self.assertIn('同時に使わないでください', text)
        self.assertIn('停止した状態', text)

    def test_one_site_only(self):
        result = backup.restore(self.backup, self.dest, LATER, A)
        self.assertTrue(result['ok'])
        self.assertFalse((self.dest / 'sites' / B).exists())
        self.assertFalse((self.dest / 'trust').exists())
        self.assertFalse((self.dest / 'notify').exists())  # what is not the site's is not restored: the data-wide mail channel stays with the original
        self.assertTrue((self.dest / 'sites' / A / 'runs' / 'r1' / 'a.txt').is_file())
        self.assertFalse((self.dest / 'runs').exists())
        self.assertEqual(json.loads((self.dest / f'sites/{A}/monitor.json').read_text('utf-8'))['paused_reason'], 'RESTORED')
        with self.assertRaises(backup.BackupRefused):
            backup.restore(self.backup, self.tmp / 'nope', LATER, 'site-cccccccc')
        with self.assertRaises(backup.BackupRefused):
            backup.restore(self.backup, self.tmp / 'nope', LATER, '../x')
        self.assertFalse((self.tmp / 'nope').exists())

    def test_a_site_backup_restores_to_a_site_folder(self):
        small = Path(backup.create(self.data, self.kept, LATER, A)['path'])
        result = backup.restore(small, self.tmp / 'one', LATER)
        self.assertTrue(result['ok'])
        self.assertEqual(sorted(p.name for p in (self.tmp / 'one' / 'sites').iterdir()), [A])
        self.assertFalse((self.tmp / 'one' / 'runs').exists())


class Refusals(Base):
    def test_a_backup_that_does_not_verify_is_never_restored(self):
        (self.backup / 'sites' / A / 'history.jsonl').write_text('tampered', encoding='utf-8')
        with self.assertRaises(backup.BackupRefused) as why:
            backup.restore(self.backup, self.dest, LATER)
        self.assertIn('復元しません', str(why.exception))
        self.assertFalse(self.dest.exists())
        (self.backup / 'MANIFEST.json').unlink()
        with self.assertRaises(backup.BackupRefused):
            backup.restore(self.backup, self.dest, LATER)
        self.assertFalse(self.dest.exists())

    def test_the_destination_must_be_new_or_an_empty_folder(self):
        self.dest.mkdir()
        (self.dest / 'something.txt').write_text('mine', encoding='utf-8')
        with self.assertRaises(backup.BackupRefused):
            backup.restore(self.backup, self.dest, LATER)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), ['something.txt'])
        file = self.tmp / 'a-file'
        file.write_text('x', encoding='utf-8')
        with self.assertRaises(backup.BackupRefused):
            backup.restore(self.backup, file, LATER)
        empty = self.tmp / 'empty'
        empty.mkdir()
        self.assertTrue(backup.restore(self.backup, empty, LATER)['ok'])
        with self.assertRaises(backup.BackupRefused):  # a second time: it is no longer empty
            backup.restore(self.backup, empty, LATER)

    def test_the_destination_and_the_backup_never_overlap(self):
        for dest in (self.backup, self.backup / 'inside', self.kept, self.tmp):
            with self.assertRaises(backup.BackupRefused, msg=str(dest)):
                backup.restore(self.backup, dest, LATER)
        self.assertEqual(sorted(p.name for p in self.backup.iterdir()), sorted(['MANIFEST.json', 'sites', 'notify', 'trust']))
        self.untouched()

    def test_not_enough_free_space_refuses_before_anything_is_written(self):
        with mock.patch.object(backup.shutil, 'disk_usage', return_value=mock.Mock(free=10)):
            with self.assertRaises(backup.BackupRefused):
                backup.restore(self.backup, self.dest, LATER)
        self.assertFalse(self.dest.exists())


class Failure(Base):
    def test_a_failed_copy_leaves_the_new_folder_says_so_and_touches_nothing_else(self):
        real = backup._copy_plain
        calls = []

        def flaky(src, dst):
            calls.append(src)
            if len(calls) == 3:
                raise OSError('disk went away')
            return real(src, dst)
        with mock.patch.object(backup, '_copy_plain', flaky):
            result = backup.restore(self.backup, self.dest, LATER)
        self.assertFalse(result['ok'])
        self.assertEqual(len([p for p in result['problems'] if p.startswith('COPY_FAILED:')]), 1)
        self.assertTrue(self.dest.is_dir())  # left for the user to look at
        record = json.loads((self.dest / 'RESTORE-RECORD.json').read_text('utf-8'))
        self.assertFalse(record['complete'])
        self.assertEqual(record['problems'], result['problems'])
        self.untouched()

    def test_a_copy_that_does_not_match_is_reported_not_kept_quiet(self):
        with mock.patch.object(backup, '_sha256', side_effect=lambda p: 'bad' if str(p).endswith('history.jsonl') and str(self.dest) in str(p) else hashlib.sha256(Path(p).read_bytes()).hexdigest()):
            result = backup.restore(self.backup, self.dest, LATER)
        self.assertFalse(result['ok'])
        self.assertIn(f'COPY_MISMATCH:sites/{A}/history.jsonl', result['problems'])

    def test_a_monitor_that_cannot_be_switched_off_is_a_failed_restore(self):
        (self.data / f'sites/{B}/http-monitor.json').write_text('not json{', encoding='utf-8')
        again = Path(backup.create(self.data, self.kept, LATER)['path'])
        result = backup.restore(again, self.dest, LATER)
        self.assertFalse(result['ok'])
        self.assertIn(f'NOT_SWITCHED_OFF:sites/{B}/http-monitor.json', result['problems'])
        self.assertFalse(json.loads((self.dest / 'RESTORE-RECORD.json').read_text('utf-8'))['complete'])


class Words(unittest.TestCase):
    def test_the_stop_reason_is_told_in_words_and_does_not_hide_other_states(self):
        for channel in ('IMAGE', 'HTTP', 'EMAIL'):
            text = retention.stop_reason_text({'enabled': False, 'paused_reason': 'RESTORED'}, channel)
            self.assertIn('復元', text)
            self.assertIn('同時に使わない', text)
            self.assertNotIn('理由コード', text)
        ready = [{'ok': True, 'label': 'x', 'state': ''}]
        common = dict(enabled=False, running=False, paused_reason='RESTORED', last=None, readiness=ready, setup=None, hold=None)
        view = monitor_view(**common, permit=None)
        self.assertEqual(view['state'], 'STOPPED')
        self.assertIn('復元', view['label'] + view['reason'])
        self.assertTrue(view['can_start'])
        expired = monitor_view(**common, permit={'state': 'EXPIRED'})
        self.assertEqual(expired['state'], 'PERMIT_EXPIRED')  # an expired permit is still what is shown
        not_ready = monitor_view(**{**common, 'readiness': [{'ok': False, 'label': 'Docker', 'state': '応答しません'}]}, permit=None)
        self.assertEqual(not_ready['state'], 'NOT_READY')
        self.assertFalse(not_ready['can_start'])


class CommandLine(Base):
    def run_tool(self, *args, **kw):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            code = restore_backup.main([*map(str, args)], now=LATER, **kw)
        return code, stdout.getvalue()

    def test_without_yes_it_asks_and_no_means_nothing_happens(self):
        code, text = self.run_tool('--backup', self.backup, '--dest', self.dest, ask=lambda prompt: 'n')
        self.assertEqual(code, 1)
        self.assertIn('何も変更していません', text)
        self.assertFalse(self.dest.exists())
        code, _ = self.run_tool('--backup', self.backup, '--dest', self.dest, ask=mock.Mock(side_effect=EOFError))
        self.assertEqual(code, 1)
        self.assertFalse(self.dest.exists())

    def test_yes_restores_and_the_words_name_the_next_step(self):
        code, text = self.run_tool('--backup', self.backup, '--dest', self.dest, '--yes')
        self.assertEqual(code, 0)
        self.assertIn('復元しました', text)
        self.assertIn('すべて照合済み', text)
        self.assertIn('RESTORED', text)
        self.assertIn('同時に使わないでください', text)
        self.assertIn('SiteProof.cmd --data', text)
        code, text = self.run_tool('--backup', self.backup, '--dest', self.tmp / 'second', '--site', A, ask=lambda prompt: 'y')
        self.assertEqual(code, 0)
        self.assertTrue((self.tmp / 'second' / 'sites' / A).is_dir())

    def test_a_refusal_is_reported_with_exit_1_and_a_partial_copy_with_exit_2(self):
        code, text = self.run_tool('--backup', self.backup, '--dest', self.backup / 'x', '--yes')
        self.assertEqual((code, '中止しました' in text), (1, True))
        with mock.patch.object(backup, '_copy_plain', side_effect=OSError('x')):
            code, text = self.run_tool('--backup', self.backup, '--dest', self.dest, '--yes')
        self.assertEqual(code, 2)
        self.assertIn('途中までのコピーを残しています', text)
        self.assertIn('ほかのフォルダには触れていません', text)
        self.untouched()


if __name__ == '__main__':
    unittest.main()
