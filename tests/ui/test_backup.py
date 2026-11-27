"""Local data backup (offline, temporary folders only): copy, manifest, verification, refusals. Nothing is uploaded; the source is never changed."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from src.noxiworks import backup
from tools import backup_data

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
NAME = 'siteproof-backup-20261125T120000Z'


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-backup-test-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        self.dest = self.tmp / 'backups'
        self.dest.mkdir()
        self.site = self.data / 'sites' / 'site-aaaaaaaa'
        self.other = self.data / 'sites' / 'site-bbbbbbbb'
        for rel, text in (('sites/site-aaaaaaaa/site.json', '{"site_id": "site-aaaaaaaa"}'), ('sites/site-aaaaaaaa/runs/r1/a.txt', 'run one'),
                          ('sites/site-aaaaaaaa/http-history.jsonl', '{"n": 1}\n'), ('sites/site-aaaaaaaa/notify.lock', 'x'), ('sites/site-aaaaaaaa/.tmp-partial', 'x'),
                          ('sites/site-aaaaaaaa/ui/gen1/index.html', '<html>'), ('sites/site-aaaaaaaa/empty/e.txt', 'e'), ('sites/site-bbbbbbbb/site.json', '{"site_id": "site-bbbbbbbb"}'),
                          ('trust/allowed_signers', 'site-owner ssh-ed25519 AAAA'), ('notify/email.json', '{}'), ('background/run.log', 'log'), ('background/state.json', '{}'),
                          ('ui/top.html', 'x'), ('empty/x', 'x'), ('日本語/メモ.txt', 'unicode name')):
            f = self.data / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding='utf-8')
        db = self.site / 'workspace' / 'state.db'
        db.parent.mkdir(parents=True)
        con = sqlite3.connect(db)
        con.execute('create table t (a integer, b text)')
        con.executemany('insert into t values (?, ?)', [(i, 'row%d' % i) for i in range(50)])
        con.commit()
        con.close()
        self.before = tree(self.data)


class Create(Base):
    def test_copies_what_belongs_leaves_out_what_does_not_and_changes_nothing_at_the_source(self):
        result = backup.create(self.data, self.dest, NOW)
        out = self.dest / NAME
        self.assertEqual((result['ok'], result['path'], result['problems'], result['changed'], result['skipped']), (True, str(out.resolve()), [], [], []))
        copied = tree(out)
        self.assertIn('MANIFEST.json', copied)
        self.assertEqual(sorted(k for k in copied if k != 'MANIFEST.json' and not k.endswith('state.db')),
                         sorted(['sites/site-aaaaaaaa/site.json', 'sites/site-aaaaaaaa/runs/r1/a.txt', 'sites/site-aaaaaaaa/http-history.jsonl', 'sites/site-bbbbbbbb/site.json',
                                 'trust/allowed_signers', 'notify/email.json', 'background/state.json', '日本語/メモ.txt']))
        for left_out in ('sites/site-aaaaaaaa/ui', 'sites/site-aaaaaaaa/empty', 'ui', 'empty', 'sites/site-aaaaaaaa/notify.lock', 'sites/site-aaaaaaaa/.tmp-partial', 'background/run.log'):
            self.assertFalse((out / left_out).exists(), left_out)
        manifest = json.loads((out / 'MANIFEST.json').read_text('utf-8'))
        self.assertEqual((manifest['schema'], manifest['scope'], manifest['counts']['files']), ('siteproof.backup-manifest.v1', 'ALL', len(manifest['files'])))
        self.assertEqual(manifest['files']['trust/allowed_signers']['sha256'], hashlib.sha256(b'site-owner ssh-ed25519 AAAA').hexdigest())
        for needle in ('sites/site-aaaaaaaa/ui/', 'ui/', 'empty/', 'sites/site-aaaaaaaa/notify.lock', 'background/run.log'):
            self.assertIn(needle, manifest['excluded'])
        self.assertNotIn(str(self.data), json.dumps(manifest))  # no local path leaks into the manifest
        self.assertEqual(tree(self.data), self.before)  # the source is untouched
        self.assertTrue(backup.verify(out)['ok'])

    def test_a_sqlite_database_is_copied_as_a_consistent_snapshot(self):
        backup.create(self.data, self.dest, NOW)
        copy = self.dest / NAME / 'sites/site-aaaaaaaa/workspace/state.db'
        con = sqlite3.connect(copy)
        self.assertEqual(con.execute('select count(*), max(b) from t').fetchone(), (50, 'row9'))
        con.close()
        manifest = json.loads((self.dest / NAME / 'MANIFEST.json').read_text('utf-8'))
        self.assertEqual(manifest['files']['sites/site-aaaaaaaa/workspace/state.db']['method'], 'sqlite-backup')

    def test_a_locked_database_is_skipped_with_a_report_and_the_rest_is_still_backed_up(self):
        with mock.patch.object(backup, '_copy_sqlite', return_value=None):  # what _copy_sqlite returns for a locked database (tested next)
            result = backup.create(self.data, self.dest, NOW)
        self.assertFalse(result['ok'])
        self.assertEqual(result['skipped'], [{'path': 'sites/site-aaaaaaaa/workspace/state.db', 'reason': 'SQLITE_LOCKED'}])
        self.assertTrue((self.dest / NAME / 'sites/site-aaaaaaaa/site.json').is_file())
        self.assertFalse((self.dest / NAME / 'sites/site-aaaaaaaa/workspace/state.db').exists())
        manifest = json.loads((self.dest / NAME / 'MANIFEST.json').read_text('utf-8'))
        self.assertIn('SQLITE_LOCKED:sites/site-aaaaaaaa/workspace/state.db', manifest['problems'])
        self.assertTrue(backup.verify(self.dest / NAME)['ok'])  # what was copied is intact

    def test_the_real_locked_database_path_returns_none_instead_of_raising(self):
        holder = sqlite3.connect(self.site / 'workspace' / 'state.db', isolation_level=None)
        holder.execute('begin exclusive')
        try:
            real_connect = sqlite3.connect
            with mock.patch('sqlite3.connect', lambda target, *a, **k: real_connect(target, *a, **{**k, 'timeout': 0.05})):
                self.assertIsNone(backup._copy_sqlite(self.site / 'workspace' / 'state.db', self.tmp / 'x.db'))
        finally:
            holder.close()
        self.assertFalse((self.tmp / 'x.db').exists())

    def test_a_file_that_changes_while_it_is_copied_is_reported(self):
        first = self.data / 'background' / 'state.json'  # the first file in the sorted copy order
        real_fsync, done = os.fsync, []

        def fsync(fd):
            if not done:  # the end of the first file's copy: the source grows now
                done.append(1)
                with first.open('a', encoding='utf-8') as f:
                    f.write(' more')
            return real_fsync(fd)
        with mock.patch.object(backup.os, 'fsync', fsync):
            result = backup.create(self.data, self.dest, NOW)
        self.assertFalse(result['ok'])
        self.assertEqual(result['changed'], ['background/state.json'])
        manifest = json.loads((self.dest / NAME / 'MANIFEST.json').read_text('utf-8'))
        self.assertTrue(manifest['files']['background/state.json']['changed_while_copying'])
        self.assertEqual(manifest['changed_while_copying'], ['background/state.json'])
        self.assertNotIn('changed_while_copying', manifest['files']['trust/allowed_signers'])

    def test_one_site_only(self):
        result = backup.create(self.data, self.dest, NOW, site='site-bbbbbbbb')
        self.assertTrue(result['ok'])
        self.assertEqual(sorted(tree(self.dest / NAME)), ['MANIFEST.json', 'sites/site-bbbbbbbb/site.json'])
        manifest = json.loads((self.dest / NAME / 'MANIFEST.json').read_text('utf-8'))
        self.assertEqual((manifest['scope'], manifest['site_id']), ('SITE', 'site-bbbbbbbb'))
        for bad in ('site-cccccccc', '../trust', 'site-aaaaaaaa/runs', ''):
            with self.assertRaises(backup.BackupRefused):
                backup.create(self.data, self.dest, NOW.replace(second=1), site=bad)
        self.assertFalse((self.dest / 'siteproof-backup-20261125T120001Z').exists())

    def test_it_refuses_a_destination_inside_the_data_a_data_inside_the_destination_and_an_existing_backup(self):
        inside = self.data / 'sites'
        with self.assertRaises(backup.BackupRefused):
            backup.create(self.data, inside, NOW)
        with self.assertRaises(backup.BackupRefused):
            backup.create(self.data, self.data, NOW)
        with self.assertRaises(backup.BackupRefused):
            backup.create(self.data, self.tmp / 'missing-parent', NOW)
        with self.assertRaises(backup.BackupRefused):
            backup.create(self.tmp / 'no-data', self.dest, NOW)
        nested = self.dest / 'data2'
        nested.mkdir()
        (nested / 'f.txt').write_text('x', encoding='utf-8')
        backup.create(nested, self.dest, NOW)  # a data folder inside the parent of the backup is fine as long as the backup folder is new...
        self.assertTrue((self.dest / NAME / 'f.txt').is_file())
        first = tree(self.dest / NAME)
        with self.assertRaises(backup.BackupRefused):
            backup.create(self.data, self.dest, NOW)  # same second, same name: never overwritten
        self.assertEqual(tree(self.dest / NAME), first)
        self.assertEqual(tree(self.data), self.before)
        self.assertFalse(any(self.data.rglob('siteproof-backup-*')))

    def test_a_private_key_refuses_everything_before_anything_is_written(self):
        header = '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\nAAAA\n'
        (self.data / 'trust' / 'oops').write_text(header, encoding='utf-8')
        with self.assertRaises(backup.BackupRefused) as cm:
            backup.create(self.data, self.dest, NOW)
        self.assertIn('trust/oops', str(cm.exception))
        self.assertEqual(list(self.dest.iterdir()), [])
        (self.data / 'trust' / 'oops').write_text('-----BEGIN ' + 'PUBLIC KEY-----\n', encoding='utf-8')  # a public key is fine
        self.assertTrue(backup.create(self.data, self.dest, NOW)['ok'])

    def test_links_are_not_followed_or_copied(self):
        outside = self.tmp / 'outside'
        outside.mkdir()
        (outside / 'secret.txt').write_text('outside', encoding='utf-8')
        try:
            os.symlink(outside, self.site / 'linked', target_is_directory=True)
            os.symlink(outside / 'secret.txt', self.site / 'linked.txt')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks need a privilege on this machine')
        result = backup.create(self.data, self.dest, NOW)
        self.assertEqual(sorted(s['path'] for s in result['skipped']), ['sites/site-aaaaaaaa/linked', 'sites/site-aaaaaaaa/linked.txt'])
        self.assertFalse(result['ok'])
        self.assertFalse(any('secret.txt' in k for k in tree(self.dest / NAME)))
        self.assertTrue((outside / 'secret.txt').is_file())


class Verify(Base):
    def setUp(self):
        super().setUp()
        backup.create(self.data, self.dest, NOW)
        self.out = self.dest / NAME

    def test_a_good_backup_verifies_and_every_kind_of_damage_is_found(self):
        good = backup.verify(self.out)
        self.assertEqual((good['ok'], good['missing'], good['mismatch'], good['extra']), (True, [], [], []))
        self.assertGreater(good['checked'], 5)
        target = self.out / 'sites/site-aaaaaaaa/site.json'
        target.write_text('{"site_id": "tampered"}', encoding='utf-8')
        self.assertEqual(backup.verify(self.out)['mismatch'], ['sites/site-aaaaaaaa/site.json'])
        target.write_text('{"site_id": "site-aaaaaaaa"}', encoding='utf-8')
        self.assertTrue(backup.verify(self.out)['ok'])
        (self.out / 'trust/allowed_signers').unlink()
        self.assertEqual(backup.verify(self.out)['missing'], ['trust/allowed_signers'])
        (self.out / 'added.txt').write_text('new', encoding='utf-8')
        self.assertEqual(backup.verify(self.out)['extra'], ['added.txt'])
        self.assertFalse(backup.verify(self.out)['ok'])

    def test_a_backup_without_a_readable_manifest_or_with_unsafe_paths_is_refused(self):
        manifest = self.out / 'MANIFEST.json'
        good = manifest.read_text('utf-8')
        manifest.write_text('not json', encoding='utf-8')
        self.assertEqual(backup.verify(self.out)['problems'], ['MANIFEST_UNREADABLE'])
        manifest.write_text(json.dumps({'schema': 'other', 'files': {}}), encoding='utf-8')
        self.assertFalse(backup.verify(self.out)['ok'])
        data = json.loads(good)
        data['files']['../escape.txt'] = {'sha256': 'x', 'bytes': 1}
        manifest.write_text(json.dumps(data), encoding='utf-8')
        self.assertIn('UNSAFE_PATH:../escape.txt', backup.verify(self.out)['problems'])
        manifest.unlink()
        self.assertFalse(backup.verify(self.out)['ok'])
        self.assertFalse(backup.verify(self.tmp / 'nothing')['ok'])


class Tool(Base):
    def run_tool(self, argv):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            code = backup_data.main(argv)
        return code, out.getvalue()

    def test_the_tool_creates_verifies_and_refuses(self):
        code, text = self.run_tool(['--data', str(self.data), '--dest', str(self.dest)])
        self.assertEqual(code, 0, text)
        self.assertIn('どこにも送信していません', text)
        folder = next(self.dest.glob('siteproof-backup-*'))
        code, text = self.run_tool(['--verify', str(folder)])
        self.assertEqual((code, text[:3]), (0, 'OK：'))
        (folder / 'trust' / 'allowed_signers').write_text('changed', encoding='utf-8')
        code, text = self.run_tool(['--verify', str(folder)])
        self.assertEqual((code, text[:3]), (1, 'NG：'))
        code, text = self.run_tool(['--data', str(self.data), '--dest', str(self.data / 'sites')])
        self.assertEqual(code, 1)
        self.assertIn('中止しました', text)
        with mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            backup_data.main(['--data', str(self.data)])
        self.assertEqual(tree(self.data), self.before)


if __name__ == '__main__':
    unittest.main()
