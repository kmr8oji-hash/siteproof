"""Bounded local LIVE-plan generation only; no AWS, network or browser."""
from contextlib import redirect_stdout, redirect_stderr

from tests import cfn_contract as cfn
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'docs/aws_portfolio/AWS_B_IAM_20261112/prepare-live-templates.py'
NOW = datetime(2026, 11, 13, 3, tzinfo=timezone.utc)
TRIAL = '20261113-120000'


# The generator embeds the operator's AWS account and is not part of the public repository: without it these tests cannot run.
@unittest.skipUnless(GENERATOR.is_file(), 'AWS-B template generator is not published (AWS_B_IAM_20261112/prepare-live-templates.py)')
class LiveGenerator(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('live_generator_under_test', GENERATOR)
        self.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.generator)
        clock = Mock(wraps=datetime)
        clock.now.return_value = NOW
        self.clock = patch.object(self.generator, 'datetime', clock)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        guard = patch.object(socket, 'socket', side_effect=AssertionError('network forbidden'))
        guard.start()
        self.addCleanup(guard.stop)
        # policies() refuses a placeholder account: use the generator's own account, as the real run does with SITEPROOF_AWS_ACCOUNT_ID
        from src.aws_b import fixture_plan
        account = patch.object(fixture_plan, 'ACCOUNT', self.generator.ACCOUNT)
        account.start()
        self.addCleanup(account.stop)

    def test_legacy_default_hour_and_explicit_day_preserve_plan_contracts(self):
        base = json.loads((ROOT / 'infra/aws_b/template.json').read_text('utf-8'))
        modes = [('legacy', None, '2026-11-13T04:00:00Z', 60),
                 ('start-default', '2026-11-13T03:10:00Z', '2026-11-13T04:10:00Z', 60),
                 ('explicit-day', '2026-11-13T03:10:00Z', '2026-11-14T03:10:00Z', 1440)]
        with tempfile.TemporaryDirectory() as tmp:
            for mode, start, end, duration in modes:
                with self.subTest(mode=mode):
                    out = Path(tmp) / mode
                    args = ['--out', str(out), '--trial-id', TRIAL]
                    if mode == 'legacy':
                        args += ['--end-at', end]
                    elif mode == 'explicit-day':
                        args += ['--start-at', start, '--duration-minutes', '1440']
                    if mode == 'start-default':
                        self.generator.prepare(out, TRIAL, start_at=start)
                    else:
                        with redirect_stdout(io.StringIO()):
                            self.generator.main(args)
                    names = json.loads((out / 'resource-names.json').read_text('utf-8'))
                    self.assertEqual(names['absolute_end_at'], end)
                    self.assertEqual(len(names['pages']), 5)
                    if start:
                        self.assertEqual((names['planned_start_at'], names['duration_minutes']), (start, duration))
                    for target in names['pages']:
                        t = json.loads((out / target / 'aws-b.template.json').read_text('utf-8'))
                        params, resources = t['Parameters'], t['Resources']
                        self.assertEqual(set(resources), set(base['Resources']))
                        self.assertEqual(params['ScheduleExpression']['Default'], 'rate(15 minutes)')
                        # AWS-B Lite: no per-page alarm, so no alarm period and no alarm/schedule Rule any more
                        self.assertNotIn('AlarmPeriodSeconds', params)
                        self.assertNotIn('Rules', t)
                        self.assertEqual(params['MonitorGroup']['Default'], names['prefix'])
                        self.assertEqual(params['AbsoluteEndAt']['Default'], end)
                        self.assertEqual(params['ExecutionGeneration'], base['Parameters']['ExecutionGeneration'])
                        self.assertEqual(params['ScheduleState']['Default'], 'DISABLED')
                        schedule = resources['ProbeSchedule']['Properties']
                        self.assertEqual(schedule['EndDate'], base['Resources']['ProbeSchedule']['Properties']['EndDate'])
                        self.assertNotIn('StartDate', schedule)  # a fixed StartDate goes stale and AWS then rejects every update
                        function = resources['ProbeFunction']['Properties']
                        self.assertEqual(function, base['Resources']['ProbeFunction']['Properties'])
                        self.assertEqual(function['Environment']['Variables']['ABSOLUTE_END_AT'], {'Ref': 'AbsoluteEndAt'})
                        self.assertEqual(resources['ProbeAsyncConfig']['Properties'], base['Resources']['ProbeAsyncConfig']['Properties'])
                        self.assertEqual(schedule['Target'], base['Resources']['ProbeSchedule']['Properties']['Target'])
                        self.assertEqual([k for k, r in resources.items() if r['Type'] == 'AWS::CloudWatch::Alarm'], [])
                        self.assertTrue(all(r['DeletionPolicy'] == r['UpdateReplacePolicy'] == 'Retain' for r in resources.values()))
                    # the one shared heartbeat alarm: own stack, same group and period as every page, one page more than ExpectedPages never
                    health = json.loads((out / 'health' / 'health.template.json').read_text('utf-8'))
                    hp = health['Parameters']
                    self.assertEqual((hp['MonitorGroup']['Default'], hp['ExpectedPages']['Default']),
                                     (names['prefix'], len(names['pages'])))
                    self.assertEqual(hp['HeartbeatPeriodSeconds']['Default'], 900)       # == the 'rate(15 minutes)' asserted above
                    self.assertEqual(hp['AlertTopicArn']['Default'], names['topic_arn'])
                    self.assertEqual(names['health'], {'stack': names['prefix'] + '-health', 'alarm': names['prefix'] + '-health-heartbeat'})
                    self.assertTrue(all(r['DeletionPolicy'] == r['UpdateReplacePolicy'] == 'Retain' for r in health['Resources'].values()))

    def test_six_page_modes_have_typed_rules_and_reject_mismatched_periods(self):
        from src.noxiworks.product import deployment_plan, settings
        from src.aws_b.fixture_plan import template as fixture_template
        base = json.loads((ROOT / 'infra/aws_b/template.json').read_text('utf-8'))
        url = 'https://' + 'a'*26 + '.lambda-url.us-east-1.on.aws/'
        modes = [({'end_at': '2026-11-13T04:00:00Z'}, '2026-11-13T04:00:00Z'),
                 ({'start_at': '2026-11-13T03:10:00Z', 'duration_minutes': 1440}, '2026-11-14T03:10:00Z')]
        with tempfile.TemporaryDirectory() as tmp:
            for mode, (kwargs, end) in enumerate(modes):
                out = Path(tmp) / str(mode)
                names = self.generator.prepare(out, TRIAL, fixture_url=url, **kwargs)
                self.assertEqual(set(names['pages']), {p['target_id'] for p in settings()['pages']} | {'aws-b-http-fixture'})
                self.assertEqual(names['absolute_end_at'], end)
                for target in names['pages']:
                    with self.subTest(mode=mode, target=target):
                        t = json.loads((out / target / 'aws-b.template.json').read_text('utf-8'))
                        self.assertEqual(cfn.rule_assertion_errors(t), [])
                        self.assertNotIn('Rules', t)                       # Lite: the heartbeat period is checked on the health stack instead
                        self.assertNotIn('AlarmPeriodSeconds', t['Parameters'])
                        self.assertEqual(t['Parameters']['ScheduleExpression']['Default'], 'rate(15 minutes)')
                        self.assertEqual(t['Parameters']['AbsoluteEndAt']['Default'], end)
                        self.assertEqual(t['Parameters']['ExecutionGeneration'], base['Parameters']['ExecutionGeneration'])
                        self.assertEqual(t['Resources']['ProbeAsyncConfig'], {**base['Resources']['ProbeAsyncConfig'], 'DeletionPolicy': 'Retain', 'UpdateReplacePolicy': 'Retain'})
                        self.assertEqual(t['Resources']['ProbeSchedule']['Properties']['State'], {'Ref': 'ScheduleState'})
                        self.assertEqual(t['Resources']['ProbeSchedule']['Properties']['EndDate'], base['Resources']['ProbeSchedule']['Properties']['EndDate'])
                        self.assertEqual(t['Resources']['ProbeFunction']['Properties'], base['Resources']['ProbeFunction']['Properties'])
                        self.assertFalse([k for k, r in t['Resources'].items() if r['Type'] == 'AWS::CloudWatch::Alarm'])
                self.assertEqual(json.loads((out / 'http-fixture.template.json').read_text('utf-8')), fixture_template(TRIAL, end))
                conf = json.loads((out / 'trial-config.json').read_text('utf-8'))
                from src.noxiworks.product import trial_config
                self.assertEqual(trial_config(conf)['pages'][:5], settings()['pages'])
        # Exercise the other producer: a newly supported whole-minute interval.
        plans = deployment_plan(base, {**settings(), 'http_interval_seconds': 420})
        for plan in plans:
            t = plan['template']
            self.assertEqual(cfn.rule_assertion_errors(t), [])
            self.assertEqual(t['Parameters']['ScheduleExpression']['Default'], 'rate(7 minutes)')
            self.assertIn('rate(7 minutes)', t['Parameters']['ScheduleExpression']['AllowedValues'])
            self.assertNotIn('Rules', t)
            self.assertNotIn('AlarmPeriodSeconds', plan['parameters'])

    def test_missing_expired_ambiguous_and_invalid_inputs_never_write(self):
        bad = [dict(), dict(end_at='2026-11-13T03:00:00Z'),
               dict(end_at='2026-11-13T04:00:01Z'),
               dict(end_at='2026-11-14T03:00:00Z'),
               dict(end_at='2026-11-13T04:00:00Z', duration_minutes=1440),
               dict(start_at='2026-11-13T02:59:59Z', duration_minutes=1440),
               dict(start_at='2026-11-13T03:10:00Z', end_at='2026-11-13T04:10:00Z')]
        for value in (None, True, -1, 0, 59, 61, 1441, 1440.0, '1440'):
            bad.append(dict(start_at='2026-11-13T03:10:00Z', duration_minutes=value))
        for value in ('', '2026-02-30T03:00:00Z', '2026-11-13T03:10:00',
                      '2026-11-13T03:10:00.000Z', '2026-11-13T03:10:00+00:00',
                      '2026-1-13T03:10:00Z', 123):
            bad.extend((dict(start_at=value), dict(end_at=value)))
        with tempfile.TemporaryDirectory() as tmp:
            for i, kwargs in enumerate(bad):
                with self.subTest(input=kwargs):
                    out = Path(tmp) / str(i)
                    with self.assertRaises(ValueError):
                        self.generator.prepare(out, TRIAL, **kwargs)
                    self.assertFalse(out.exists())
            existing = Path(tmp) / 'existing'
            existing.mkdir()
            (existing / 'keep').write_bytes(b'untouched')
            with self.assertRaises(ValueError):
                self.generator.prepare(existing, TRIAL, start_at='2026-11-13T03:10:00Z', duration_minutes=1440)
            self.assertEqual(list(existing.iterdir()), [existing / 'keep'])
            self.assertEqual((existing / 'keep').read_bytes(), b'untouched')
            for tail in ([], ['--end-at', '2026-11-13T04:00:00Z', '--duration-minutes', '1440'],
                         ['--start-at', '2026-11-13T03:10:00Z', '--duration-minutes', '0']):
                out = Path(tmp) / 'cli-invalid'
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                    self.generator.main(['--out', str(out), '--trial-id', TRIAL] + tail)
                self.assertEqual(exc.exception.code, 2)
                self.assertFalse(out.exists())
