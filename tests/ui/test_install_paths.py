"""Where SiteProof lives and where its data lives: Japanese paths (the generated background launcher is REALLY run by cmd.exe), the remembered data folder, --where,
status over several sites, the pre-update and uninstall helpers. No network, no Docker, no schtasks: the Windows task tool is replaced everywhere; the one thing that really
runs is a generated .cmd against a throw-away data folder in which nothing is due, a stub program that only records what it received, and SiteProof.cmd with --where."""
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from src.noxiworks import app as app_module
from src.noxiworks.site_workflow import Site
from tools import background_monitor as bm
from tools import pre_update, uninstall_check

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
JP = 'テスト 日本語フォルダ'
ON_WINDOWS = os.name == 'nt' and shutil.which('cmd.exe') is not None
ROOT = Path(__file__).resolve().parents[2]
REAL_PYTHON = sys.executable  # setUp replaces sys.executable for the launcher tests
RUN_ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONIOENCODING': 'utf-8'}


def run_cmd(cmd, *args, cwd=None):
    """Run a .cmd the way the Task Scheduler / a double click does (cmd.exe /c), without a console window."""
    line = 'cmd.exe /d /s /c ""' + str(cmd) + '" ' + ' '.join(args) + '"'
    return subprocess.run(line, capture_output=True, timeout=120, cwd=cwd, env=RUN_ENV, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-paths-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.site = Site.register(self.data / 'sites', 'A', 'https://my-site.com/', ['Desktop'], True, NOW)
        self.sid = self.site.root.name
        self.python = self.tmp / 'py' / 'python.exe'
        self.python.parent.mkdir()
        self.python.write_bytes(b'')
        (self.python.parent / 'pythonw.exe').write_bytes(b'')
        patch = mock.patch.object(bm.sys, 'executable', str(self.python))
        patch.start()
        self.addCleanup(patch.stop)


class Launcher(Base):
    def expected(self, data, python, root=ROOT, channel='image', action='tick'):
        folder = Path(data).resolve() / 'background'
        return ('@echo off\r\n' f'cd /d "{root}"\r\n' 'set PYTHONDONTWRITEBYTECODE=1\r\n'
                f'"{python}" -B tools\\background_monitor.py {action} --data "{Path(data).resolve()}" --site {self.sid} >> "{folder / (self.sid + "-" + channel + ".log")}" 2>&1\r\n')

    def test_all_ascii_paths_write_exactly_the_file_it_always_wrote(self):
        cmd = bm.launcher(self.data, self.sid, 'image')
        raw = cmd.read_bytes()
        self.assertEqual(raw, self.expected(self.data, (self.python.parent / 'pythonw.exe').resolve()).encode('ascii'))
        self.assertNotIn(b'chcp', raw)
        self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
        self.assertTrue(raw.isascii())

    def test_a_japanese_path_gives_utf8_without_bom_and_chcp_as_the_second_line(self):
        data = self.tmp / JP / 'データ'
        (data / 'sites').mkdir(parents=True)
        shutil.move(str(self.site.root), str(data / 'sites' / self.sid))
        cmd = bm.launcher(data, self.sid, 'http', 5)
        raw = cmd.read_bytes()
        self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
        text = raw.decode('utf-8')
        lines = text.split('\r\n')
        self.assertEqual(lines[:2], ['@echo off', 'chcp 65001 >nul'])
        self.assertIn(JP, text)
        self.assertEqual(text.replace('chcp 65001 >nul\r\n', '', 1), self.expected(data, (self.python.parent / 'pythonw.exe').resolve(), channel='http', action='http-tick')
                         .replace('--site ' + self.sid, '--site ' + self.sid + ' --every 5'))
        self.assertNotIn('\n\n', text.replace('\r\n', '\n'))

    def test_a_japanese_interpreter_or_program_folder_is_enough_for_utf8(self):
        jp_python = self.tmp / JP / 'python.exe'
        jp_python.parent.mkdir()
        jp_python.write_bytes(b'')
        with mock.patch.object(bm.sys, 'executable', str(jp_python)):
            raw = bm.launcher(self.data, self.sid, 'image').read_bytes()
        self.assertTrue(raw.startswith(b'@echo off\r\nchcp 65001 >nul\r\n'))
        self.assertIn(JP.encode('utf-8'), raw)
        with mock.patch.object(bm, 'ROOT', self.tmp / JP / 'プログラム'):
            self.assertIn('プログラム', bm.launcher(self.data, self.sid, 'image').read_text('utf-8'))

    def test_a_percent_sign_is_doubled_in_either_form(self):
        data = self.tmp / '100%ほんと' / 'd'
        (data / 'sites').mkdir(parents=True)
        shutil.move(str(self.site.root), str(data / 'sites' / self.sid))
        text = bm.launcher(data, self.sid, 'image').read_text('utf-8')
        self.assertIn('100%%ほんと', text)
        self.assertNotIn('100%ほんと', text)

    def test_control_characters_quotes_and_unsupported_characters_still_refuse_and_write_nothing(self):
        for bad in ('x"y', 'x\x01y', 'x\ny', 'x\u202ey', 'x\ud800y', 'x\ue000y', 'x\u0378y', 'x\x7fy'):
            self.assertIsNotNone(bm.batch_problem('C:\\ok', 'C:\\' + bad), repr(bad))
        for good in ('C:\\spe', 'C:\\データ フォルダ\\ひらがな', 'D:\\日本語\\𠮷野家', 'C:\\100%ほんと'):
            self.assertIsNone(bm.batch_problem(good), good)
        for bad in ('x"y', 'x\x01y'):
            shutil.rmtree(self.data / 'background', True)
            with mock.patch.object(bm, 'ROOT', Path('C:/' + bad)), self.assertRaises(SystemExit) as stop:
                bm.launcher(self.data, self.sid, 'image')
            self.assertIn('タスクは登録していません', str(stop.exception))
            self.assertFalse((self.data / 'background').exists())
        with mock.patch.object(bm, 'schtasks') as schtasks, mock.patch.object(bm, 'ROOT', Path('C:/x"y')), self.assertRaises(SystemExit):
            bm.install(self.data, None, False, self.sid, 'image')
        schtasks.assert_not_called()

    def test_install_dry_run_with_a_japanese_data_folder_prints_the_task_command_and_registers_nothing(self):
        data = self.tmp / JP / 'データ'
        (data / 'sites').mkdir(parents=True)
        shutil.move(str(self.site.root), str(data / 'sites' / self.sid))
        with mock.patch.object(bm, 'schtasks') as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(bm.install(data, None, True, self.sid, 'image'), 0)
        schtasks.assert_not_called()
        self.assertIn(JP, out.getvalue())
        self.assertTrue((data / 'background' / f'{self.sid}-image.cmd').read_bytes().startswith(b'@echo off\r\nchcp 65001 >nul\r\n'))


@unittest.skipUnless(ON_WINDOWS, 'cmd.exe is needed')
class RealCmd(Base):
    """The generated launcher, really run by cmd.exe from folders with Japanese names."""

    def japanese_data(self):
        data = self.tmp / JP / 'データ'
        (data / 'sites').mkdir(parents=True)
        shutil.move(str(self.site.root), str(data / 'sites' / self.sid))
        return data

    def test_the_real_tick_through_a_japanese_data_folder_runs_and_writes_its_log(self):
        data = self.japanese_data()
        (data / 'sites' / self.sid / 'monitor.json').write_text(json.dumps({'enabled': True, 'next_due_at': '2999-01-01T00:00:00Z', 'interval_seconds': 900}), encoding='utf-8')
        with mock.patch.object(bm.sys, 'executable', REAL_PYTHON):  # the real interpreter, the real program
            for channel in ('image', 'http'):
                cmd = bm.launcher(data, self.sid, channel, 5 if channel == 'http' else None)
                self.assertTrue(cmd.read_bytes().startswith(b'@echo off\r\nchcp 65001 >nul\r\n'))
                done = run_cmd(cmd)
                self.assertEqual(done.returncode, 0, done.stdout[-300:] + done.stderr[-300:])
                log = data / 'background' / f'{self.sid}-{channel}.log'
                self.assertTrue(log.is_file(), channel)  # written through the Japanese path
                self.assertNotIn('Traceback', log.read_text('utf-8', errors='replace'))
                self.assertNotIn('not recognized', log.read_text('utf-8', errors='replace'))
        self.assertFalse(list((data / 'sites' / self.sid / 'runs').glob('*')) if (data / 'sites' / self.sid / 'runs').exists() else False)  # nothing was inspected

    def test_a_japanese_program_folder_and_interpreter_receive_exactly_the_paths_that_were_written(self):
        import venv
        program = self.tmp / JP / 'プログラム'
        (program / 'tools').mkdir(parents=True)
        (program / 'tools' / 'background_monitor.py').write_text(
            'import json, os, sys\n'
            'data = sys.argv[sys.argv.index("--data") + 1]\n'
            'os.makedirs(os.path.join(data, "background"), exist_ok=True)\n'
            'open(os.path.join(data, "background", "proof.json"), "w", encoding="utf-8").write(json.dumps({"cwd": os.getcwd(), "argv": sys.argv[1:], "exe": sys.executable}, ensure_ascii=False))\n'
            'print("ran", ascii(sys.argv[1:]))\n', encoding='utf-8')
        try:
            venv.EnvBuilder(with_pip=False, symlinks=False).create(self.tmp / JP / '環境')
        except Exception as exc:  # no venv on this PC: the data and program parts below still run with the real interpreter
            self.skipTest('venv not available: ' + type(exc).__name__)
        python = self.tmp / JP / '環境' / 'Scripts' / 'python.exe'
        data = self.japanese_data()
        with mock.patch.object(bm.sys, 'executable', str(python)), mock.patch.object(bm, 'ROOT', program):
            cmd = bm.launcher(data, self.sid, 'image')
        text = cmd.read_bytes().decode('utf-8')
        self.assertTrue(text.startswith('@echo off\r\nchcp 65001 >nul\r\n'))
        for jp in ('プログラム', '環境', 'データ'):
            self.assertIn(jp, text)
        done = run_cmd(cmd)
        self.assertEqual(done.returncode, 0, done.stdout[-300:] + done.stderr[-300:])
        proof = json.loads((data / 'background' / 'proof.json').read_text('utf-8'))
        self.assertEqual(os.path.normcase(proof['cwd']), os.path.normcase(str(program)))
        self.assertEqual(proof['argv'], ['tick', '--data', str(data.resolve()), '--site', self.sid])
        self.assertEqual(os.path.normcase(os.path.dirname(proof['exe'])), os.path.normcase(str(python.parent)))
        log = (data / 'background' / f'{self.sid}-image.log').read_text('utf-8', errors='replace')
        self.assertIn('ran', log)  # the program's output reached the log of the Japanese-named folder

    def test_site_proof_cmd_from_a_folder_with_a_japanese_name_runs_and_says_where(self):
        link = self.tmp / JP / 'プログラム'
        link.parent.mkdir()
        made = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(ROOT)], capture_output=True, timeout=60)
        if made.returncode != 0:
            self.skipTest('a junction could not be made')

        def cleanup():
            os.rmdir(link)  # the junction only; never what it points to
        self.addCleanup(cleanup)
        data = self.tmp / JP / 'データ'
        done = run_cmd(link / 'SiteProof.cmd', '--where', '--data', '"' + str(data) + '"', cwd=self.tmp)
        out = done.stdout.decode('utf-8', errors='replace')
        self.assertEqual(done.returncode, 0, out[-400:] + done.stderr.decode('utf-8', errors='replace')[-300:])
        self.assertIn('データフォルダ：' + str(data.resolve()), out)
        self.assertIn('まだありません', out)  # --where starts nothing and creates nothing
        self.assertFalse(data.exists())


class Status(Base):
    def test_status_without_a_site_lists_every_site_and_channel_read_only_and_how_to_stop_everything(self):
        other = Site.register(self.data / 'sites', 'B', 'https://other-site.com/', ['Desktop'], True, NOW + timedelta(seconds=1))
        registered = {bm.task_name(self.data, self.sid, 'image'), bm.task_name(self.data, other.root.name, 'http')}
        asked = []

        def ask(*args):
            asked.append(args)
            self.assertEqual(args[0], '/Query')
            return mock.MagicMock(returncode=0 if args[2] in registered else 1, stdout='TaskName: ' + args[2], stderr='')
        with mock.patch.object(bm, 'schtasks', side_effect=ask), mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(bm.main(['status', '--data', str(self.data)]), 0)
        text = out.getvalue()
        for sid in (self.sid, other.root.name):
            self.assertIn('=== ' + sid, text)
            for channel in ('image', 'http'):
                self.assertTrue(any(a[2] == bm.task_name(self.data, sid, channel) for a in asked))
        self.assertIn('すべて止めるには', text)
        self.assertIn(f'remove --data "{self.data.resolve()}" --site {self.sid} --channel image', text)
        self.assertIn(f'remove --data "{self.data.resolve()}" --site {other.root.name} --channel http', text)
        self.assertNotIn(f'--site {self.sid} --channel http', text)  # only what is registered
        self.assertIn('このサイトの監視をすべて停止', text)
        self.assertTrue(all(a[0] == '/Query' for a in asked))  # never a change

    def test_status_with_nothing_registered_says_so(self):
        with mock.patch.object(bm, 'schtasks', return_value=mock.MagicMock(returncode=1, stdout='', stderr='')), mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            bm.main(['status', '--data', str(self.data)])
        self.assertIn('登録されているバックグラウンドのタスクはありません', out.getvalue())
        self.assertNotIn('すべて止めるには', out.getvalue())

    def test_status_with_no_site_at_all_is_still_the_plain_message(self):
        shutil.rmtree(self.site.root)
        with mock.patch.object(bm, 'schtasks') as schtasks, self.assertRaises(SystemExit) as stop:
            bm.main(['status', '--data', str(self.data)])
        self.assertIn('登録されていません', str(stop.exception))
        schtasks.assert_not_called()


class RememberedFolder(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-settings-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.local = self.tmp / 'LocalAppData'
        patch = mock.patch.dict(os.environ, {'LOCALAPPDATA': str(self.local)})
        patch.start()
        self.addCleanup(patch.stop)
        self.settings = self.local / 'SiteProof' / 'settings.json'

    def run_main(self, *args):
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            code = app_module.main([*map(str, args)])
        return code, out.getvalue()

    def test_without_a_settings_file_the_default_is_the_base_folder_as_before(self):
        self.assertEqual(app_module.default_data(), self.local / 'SiteProof')
        self.assertEqual(app_module.settings_file(), self.settings)
        self.assertFalse(self.local.exists())  # asking creates nothing

    def test_remember_writes_the_choice_atomically_and_moves_no_data(self):
        mine = self.tmp / 'mein' / 'データ'
        mine.mkdir(parents=True)
        (mine / 'keep.txt').write_text('mine', encoding='utf-8')
        code, text = self.run_main('--data', mine, '--remember', '--where')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(self.settings.read_text('utf-8')), {'schema': 'siteproof.settings.v1', 'data_folder': str(mine.resolve())})
        self.assertEqual(sorted(p.name for p in self.settings.parent.iterdir()), ['settings.json'])  # no temporary file left
        self.assertIn('データは移動していません', text)
        self.assertEqual((mine / 'keep.txt').read_text('utf-8'), 'mine')
        self.assertEqual(sorted(p.name for p in mine.iterdir()), ['keep.txt'])
        self.assertEqual(app_module.default_data(), mine.resolve())
        code, text = self.run_main('--where')
        self.assertEqual(code, 0)
        self.assertIn('データフォルダ：' + str(mine.resolve()), text)
        self.assertIn('前に選んだフォルダ', text)

    def test_remember_creates_a_missing_folder_but_not_one_that_cannot_exist(self):
        fresh = self.tmp / 'new' / 'place'
        self.assertEqual(self.run_main('--data', fresh, '--remember', '--where')[0], 0)
        self.assertTrue(fresh.is_dir())
        blocker = self.tmp / 'a-file'
        blocker.write_text('x', encoding='utf-8')
        before = self.settings.read_text('utf-8')
        code, text = self.run_main('--data', blocker / 'sub', '--remember', '--where')
        self.assertEqual(code, 2)
        self.assertIn('記憶しません', text)
        self.assertEqual(self.settings.read_text('utf-8'), before)  # the earlier choice is still there

    def test_a_remembered_folder_that_is_gone_is_an_error_never_a_silent_empty_folder(self):
        mine = self.tmp / 'drive' / 'data'
        self.run_main('--data', mine, '--remember', '--where')
        shutil.rmtree(mine)
        for args in (('--where',), ()):
            code, text = self.run_main(*args)  # without --where it must stop before any server starts
            self.assertEqual(code, 2)
            self.assertIn(str(mine), text)
            self.assertIn('見つかりません', text)
            self.assertIn('勝手に始めることはしません', text)
        self.assertFalse(mine.exists())  # not re-created
        self.assertFalse((self.local / 'SiteProof' / 'registry').exists())  # and no fallback data was made in the base folder
        with self.assertRaises(app_module.DataFolderError):
            app_module.default_data()

    def test_a_damaged_settings_file_is_an_error_and_an_explicit_data_still_works(self):
        self.settings.parent.mkdir(parents=True)
        for bad in ('not json{', '{}', '{"data_folder": 5}', '{"data_folder": "  "}', '[]'):
            self.settings.write_text(bad, encoding='utf-8')
            code, text = self.run_main('--where')
            self.assertEqual(code, 2, bad)
            self.assertIn('読めません', text)
        explicit = self.tmp / 'explicit'
        explicit.mkdir()
        code, text = self.run_main('--where', '--data', explicit)
        self.assertEqual(code, 0)
        self.assertIn('--data で指定', text)

    def test_remember_needs_a_folder_and_where_names_a_missing_default_without_creating_it(self):
        with mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            app_module.main(['--remember'])
        self.assertFalse(self.settings.exists())
        code, text = self.run_main('--where')
        self.assertEqual(code, 0)
        self.assertIn(str(self.local / 'SiteProof'), text)
        self.assertIn('既定の場所', text)
        self.assertIn('まだありません', text)
        self.assertFalse(self.local.exists())

    def test_the_tests_never_touch_the_real_settings(self):
        self.assertTrue(str(app_module.settings_file()).startswith(str(self.tmp)))


class Helpers(Base):
    def test_uninstall_check_lists_without_removing_anything(self):
        before = sorted(str(p) for p in self.tmp.rglob('*'))
        (self.tmp / 'data-backups' / 'siteproof-backup-20261124T120000Z').mkdir(parents=True)
        settings = self.tmp / 'LocalAppData' / 'SiteProof' / 'settings.json'
        settings.parent.mkdir(parents=True)
        settings.write_text('{}', encoding='utf-8')
        snapshot = sorted(str(p) for p in self.tmp.rglob('*'))
        asked = []

        def query(data, site, channel):
            asked.append((site, channel))
            return channel == 'image'
        out = []
        self.assertEqual(uninstall_check.main(['--data', str(self.data)], query=query, settings=settings, out=out.append), 0)
        text = '\n'.join(out)
        self.assertEqual(asked, [(self.sid, 'image'), (self.sid, 'http')])
        self.assertIn(bm.task_name(self.data, self.sid, 'image') + f'（{self.sid}・画像監視）：登録されています', text)
        self.assertIn('HTTP監視）：登録されていません', text)
        self.assertIn(f'remove --data "{self.data.resolve()}" --site {self.sid} --channel image', text)
        self.assertNotIn(f'--site {self.sid} --channel http', text)
        self.assertIn('siteproof-backup-20261124T120000Z', text)
        self.assertIn(str(settings), text)
        self.assertIn('~/.ssh', text)
        self.assertIn('資格情報マネージャー', text)
        self.assertIn('元に戻せません', text)
        self.assertIn('プログラムのフォルダを削除しても', text)
        self.assertEqual(sorted(str(p) for p in self.tmp.rglob('*')), snapshot)  # nothing created, nothing removed
        self.assertNotEqual(before, snapshot)  # (the folders above were made by this test, not by the tool)

    def test_uninstall_check_says_when_tasks_cannot_be_asked(self):
        out = []
        uninstall_check.main(['--data', str(self.data)], query=lambda d, s, c: None, settings=self.tmp / 'none.json', out=out.append)
        self.assertIn('問い合わせられませんでした', '\n'.join(out))
        self.assertIn('status で確認', '\n'.join(out))

    def test_pre_update_checks_backs_up_verifies_and_changes_no_program_file(self):
        (self.data / 'trust').mkdir()
        (self.data / 'trust' / 'allowed_signers').write_text('k', encoding='utf-8')
        probes = {'python': lambda: ((3, 15, 1), 'p'), 'ssh_keygen': lambda: 'ssh', 'docker_cli': lambda: None, 'background': lambda d, s, c: False,
                  'path_problem': lambda d: None, 'free_bytes': lambda p: 50 << 30, 'writable': lambda p: True, 'now': lambda: NOW,
                  'switches': lambda: {'http': False, 'mail': False, 'dns': False}}
        out = []
        program = {p: p.stat().st_mtime_ns for p in (ROOT / 'tools').glob('*.py')}
        code = pre_update.main(['--data', str(self.data)], probes=probes, now=NOW, out=out.append)
        text = '\n'.join(out)
        self.assertEqual(code, 0, text)
        kept = self.tmp / 'data-backups' / 'siteproof-backup-20261125T120000Z'
        self.assertTrue((kept / 'MANIFEST.json').is_file())
        self.assertIn('確認 OK', text)
        self.assertIn('プログラムの更新は行っていません', text)
        self.assertIn('監視設定を更新', text)
        self.assertIn('~/.ssh', text)
        self.assertIn('Docker CLI', text)  # a missing item is listed with its next step
        self.assertEqual({p: p.stat().st_mtime_ns for p in program}, program)
        out = []
        self.assertEqual(pre_update.main(['--data', str(self.tmp / 'nowhere')], probes=probes, now=NOW, out=out.append), 1)
        self.assertFalse((self.tmp / 'nowhere').exists())
        self.assertFalse((self.tmp / 'nowhere-backups').exists())


if __name__ == '__main__':
    unittest.main()
