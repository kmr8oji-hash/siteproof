"""In-AWS safe stop (src/aws_b/stopper.py) and its companion template (infra/aws_b/stopper.json). Offline: fake AWS clients only."""
import json
from pathlib import Path
import unittest

from src.aws_b.stopper import STOP_SCHEMA, Clients, Settings, metric_line, stop
from tests import cfn_contract as cfn
from tests.aws_b.support import Harness, at, event
from tests.aws_fakes import FakeClientError

ROOT = Path(__file__).resolve().parents[2]
STOPPER = ROOT / 'infra' / 'aws_b' / 'stopper.json'
ALARMS = ('p-heartbeat',)   # AWS-B Lite: the one shared heartbeat alarm


class FakeScheduler:
    def __init__(self, state='ENABLED', exists=True):
        self.schedule = {'Name': 'p-schedule', 'State': state, 'ScheduleExpression': 'rate(15 minutes)', 'ScheduleExpressionTimezone': 'UTC',
                         'FlexibleTimeWindow': {'Mode': 'OFF'}, 'EndDate': '2027-11-15T00:00:00Z', 'ActionAfterCompletion': 'NONE',
                         'Target': {'Arn': 'arn:probe', 'RoleArn': 'arn:role', 'Input': '{}', 'RetryPolicy': {'MaximumRetryAttempts': 0}}} if exists else None
        self.updates, self.fail_update = [], None

    def get_schedule(self, Name):
        if self.schedule is None:
            raise FakeClientError('ResourceNotFoundException')
        return dict(self.schedule)

    def update_schedule(self, **request):
        if self.fail_update:
            raise FakeClientError(self.fail_update)
        self.updates.append(request)
        self.schedule = {**self.schedule, **{k: v for k, v in request.items() if k != 'Name'}}


class FakeLambda:
    def __init__(self, reserved=1):
        self.reserved, self.puts = reserved, []

    def get_function_concurrency(self, FunctionName):
        return {} if self.reserved is None else {'ReservedConcurrentExecutions': self.reserved}

    def put_function_concurrency(self, FunctionName, ReservedConcurrentExecutions):
        self.puts.append(ReservedConcurrentExecutions)
        self.reserved = ReservedConcurrentExecutions


class FakeCloudWatch:
    def __init__(self):
        self.enabled = {a: True for a in ALARMS}
        self.disables = 0

    def disable_alarm_actions(self, AlarmNames):
        self.disables += 1
        for a in AlarmNames:
            self.enabled[a] = False

    def describe_alarms(self, AlarmNames):
        return {'MetricAlarms': [{'AlarmName': a, 'ActionsEnabled': self.enabled[a]} for a in AlarmNames if a in self.enabled]}


def stop_event(target='preview', requested_at='2026-11-20T03:00:30Z'):
    return {'schema': STOP_SCHEMA, 'target_id': target, 'requested_at': requested_at}


class Stopper(unittest.TestCase):
    def setUp(self):
        self.h = Harness()  # armed probe (generation 1) on the shared fake table
        self.settings = Settings('preview', self.h.config.table_name, 'p-schedule', 'p-probe', ALARMS)
        self.scheduler, self.lam, self.cw = FakeScheduler(), FakeLambda(), FakeCloudWatch()
        self.clients = Clients(self.h.dynamo, self.scheduler, self.lam, self.cw)

    def run_stop(self, body=None):
        return stop(body or stop_event(), self.settings, self.clients, now=lambda: at(30))

    def test_without_a_configured_alarm_the_other_layers_still_stop_and_complete(self):
        self.settings = Settings('preview', self.h.config.table_name, 'p-schedule', 'p-probe', ())
        self.assertEqual(self.run_stop().result, 'STOP_COMPLETE')
        self.assertEqual(self.cw.disables, 0)

    def test_every_layer_stops_and_reads_back(self):
        rec = self.run_stop()
        self.assertEqual(rec.result, 'STOP_COMPLETE', rec.steps)
        head = self.h.head()
        self.assertEqual((head['enabled']['BOOL'], head['execution_generation']['N']), (False, '2'))
        self.assertEqual(self.scheduler.schedule['State'], 'DISABLED')
        update = self.scheduler.updates[0]
        self.assertEqual((update['ScheduleExpression'], update['EndDate'], update['Target']['RoleArn']),
                         ('rate(15 minutes)', '2027-11-15T00:00:00Z', 'arn:role'))  # the definition is kept, only the state changes
        self.assertEqual(self.lam.reserved, 0)
        self.assertFalse(any(self.cw.enabled.values()))
        self.assertEqual(metric_line(rec)['StopComplete'], 1)

    def test_after_the_stop_a_queued_probe_event_never_probes(self):
        self.run_stop()
        out = self.h.invoke(event())  # an event already in flight for generation 1
        self.assertEqual((out['decision'], out['reason']), ('REJECTED', 'STOPPED'))
        self.assertEqual(self.h.probes, [])

    def test_a_duplicate_or_late_stop_writes_nothing_again(self):
        self.run_stop()
        writes = (len(self.scheduler.updates), len(self.lam.puts), self.h.head()['execution_generation']['N'])
        rec = self.run_stop(stop_event(requested_at='2026-11-19T00:00:00Z'))  # an old event: stopping is still safe
        self.assertEqual(rec.result, 'STOP_COMPLETE')
        self.assertEqual((len(self.scheduler.updates), len(self.lam.puts), self.h.head()['execution_generation']['N']), writes)

    def test_a_failed_layer_is_incomplete_but_the_other_layers_still_stop(self):
        self.scheduler.fail_update = 'AccessDeniedException'
        rec = self.run_stop()
        self.assertEqual(rec.result, 'STOP_INCOMPLETE')
        self.assertEqual(metric_line(rec)['StopIncomplete'], 1)
        self.assertIn({'layer': 'L2-schedule', 'ok': False, 'detail': 'update failed: AccessDeniedException'}, rec.steps)
        self.assertEqual(self.h.head()['enabled']['BOOL'], False)  # L1 alone already blocks every probe
        self.assertEqual(self.lam.reserved, 0)
        self.assertEqual(self.h.invoke(event())['reason'], 'STOPPED')

    def test_generation_moving_during_the_stop_is_reread(self):
        def bump(request):  # a concurrent re-arm wrote generation 2 just before our conditional write
            if request.get('UpdateExpression', '').startswith('SET #en = :false') and self.h.head()['execution_generation']['N'] == '1':
                self.h.dynamo.items[('CONTROL#preview', 'HEAD')]['execution_generation'] = {'N': '2'}
        self.h.dynamo.before['update_item'] = bump
        rec = self.run_stop()
        self.assertEqual(rec.result, 'STOP_COMPLETE', rec.steps)
        self.assertEqual(self.h.head()['execution_generation']['N'], '3')

    def test_refused_events_change_nothing(self):
        for body in ({'schema': 'x', 'target_id': 'preview'}, stop_event(target='other'), 'not json'):
            with self.subTest(body=body):
                rec = stop(body, self.settings, self.clients, now=lambda: at(30))
                self.assertEqual(rec.result, 'STOP_REFUSED')
        self.assertEqual(self.h.head()['enabled']['BOOL'], True)
        self.assertEqual((self.scheduler.updates, self.lam.puts, self.cw.disables), ([], [], 0))

    def test_a_schedule_already_deleted_after_its_end_counts_as_stopped(self):
        self.scheduler.schedule = None
        self.assertEqual(self.run_stop().result, 'STOP_COMPLETE')

    def test_an_unreadable_layer_is_never_reported_complete(self):
        self.h.dynamo.faults.fail('get_item', FakeClientError('AccessDeniedException'), times=10)
        rec = self.run_stop()
        self.assertEqual(rec.result, 'STOP_INCOMPLETE')
        self.assertEqual((self.scheduler.schedule['State'], self.lam.reserved), ('DISABLED', 0))  # the other layers still ran

    def test_configuration_must_be_complete(self):
        env = {'TARGET_ID': 't', 'TABLE_NAME': 'x-runs', 'SCHEDULE_NAME': 'x-schedule', 'FUNCTION_NAME': 'x-probe', 'ALARM_NAMES': 'a'}
        self.assertEqual(Settings.from_env(env).alarms, ('a',))
        self.assertEqual(Settings.from_env({**env, 'ALARM_NAMES': ''}).alarms, ())
        for broken in ({**env, 'ALARM_NAMES': 'a,b'}, {k: v for k, v in env.items() if k != 'TABLE_NAME'}):
            with self.assertRaises(ValueError):
                Settings.from_env(broken)


class StopperTemplate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = cfn.load(STOPPER)
        cls.res = cls.t['Resources']

    def test_exact_resources_and_references(self):
        self.assertEqual({k: v['Type'] for k, v in self.res.items()}, {
            'StopperLogGroup': 'AWS::Logs::LogGroup', 'StopperRole': 'AWS::IAM::Role', 'StopperFunction': 'AWS::Lambda::Function',
            'StopperAsyncConfig': 'AWS::Lambda::EventInvokeConfig', 'StopSchedulerRole': 'AWS::IAM::Role',
            'StopSchedule': 'AWS::Scheduler::Schedule', 'StopperErrorAlarm': 'AWS::CloudWatch::Alarm', 'StopIncompleteAlarm': 'AWS::CloudWatch::Alarm'})
        self.assertEqual(cfn.reference_errors(self.t, {'StopperLogGroup': {'Arn'}, 'StopperRole': {'Arn'}, 'StopperFunction': {'Arn'},
                                                       'StopSchedulerRole': {'Arn'}}), [])
        self.assertEqual(cfn.iam_wildcard_errors(self.t), [])
        self.assertIn('NO-GO', self.t['Description'])

    def test_the_stopper_may_only_stop_its_own_probe_and_never_delete(self):
        statements = cfn.statements(self.res['StopperRole']['Properties']['Policies'][0]['PolicyDocument'])
        actions = {a for s in statements for a in cfn.actions(s)}
        self.assertEqual(actions, {'dynamodb:GetItem', 'dynamodb:UpdateItem', 'scheduler:GetSchedule', 'scheduler:UpdateSchedule', 'iam:PassRole',
                                   'lambda:GetFunctionConcurrency', 'lambda:PutFunctionConcurrency', 'cloudwatch:DisableAlarmActions',
                                   'cloudwatch:DescribeAlarms', 'logs:CreateLogStream', 'logs:PutLogEvents'})
        self.assertFalse(any('Delete' in a or 'Create' in a and a != 'logs:CreateLogStream' for a in actions))
        by_sid = {s['Sid']: s for s in statements}
        self.assertEqual(by_sid['ControlItemOnly']['Condition'],
                         {'ForAllValues:StringEquals': {'dynamodb:LeadingKeys': [{'Fn::Sub': 'CONTROL#${TargetId}'}]}})
        self.assertEqual(by_sid['KeepScheduleRole']['Condition'], {'StringEquals': {'iam:PassedToService': 'scheduler.amazonaws.com'}})
        self.assertTrue(all('${ProbeStackName}' in json.dumps(by_sid[s]['Resource'])
                            for s in ('ControlItemOnly', 'ProbeScheduleOnly', 'KeepScheduleRole', 'ProbeConcurrencyOnly')))
        # Lite: one shared heartbeat alarm, named by parameter, never a wildcard
        self.assertEqual(by_sid['HeartbeatAlarmOnly']['Resource'],
                         {'Fn::Sub': 'arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:${HeartbeatAlarmName}'})

    def test_the_stop_schedule_runs_once_and_retries(self):
        p = self.res['StopSchedule']['Properties']
        self.assertEqual((p['State'], p['FlexibleTimeWindow']), ('ENABLED', {'Mode': 'OFF'}))
        self.assertNotIn('ActionAfterCompletion', p)  # CloudFormation rejects it on AWS::Scheduler::Schedule (verified on AWS 2026-11-20)
        self.assertIn('NOT DEPLOYABLE UNDER THE CURRENT OPERATOR IAM', self.t['Description'])
        self.assertEqual(p['ScheduleExpression']['Fn::Join'][1][0], 'at(')
        self.assertEqual(p['Target']['RetryPolicy'], {'MaximumRetryAttempts': 5, 'MaximumEventAgeInSeconds': 3600})
        self.assertIn('siteproof.stop.event.v1', p['Target']['Input']['Fn::Sub'])
        scheduler_role = cfn.statements(self.res['StopSchedulerRole']['Properties']['Policies'][0]['PolicyDocument'])
        self.assertEqual([(s['Action'], s['Resource']) for s in scheduler_role], [('lambda:InvokeFunction', {'Fn::GetAtt': ['StopperFunction', 'Arn']})])

    def test_stop_failures_mail_the_existing_topic(self):
        for name, metric in (('StopperErrorAlarm', 'Errors'), ('StopIncompleteAlarm', 'StopIncomplete')):
            p = self.res[name]['Properties']
            self.assertEqual((p['MetricName'], p['AlarmActions']), (metric, [{'Ref': 'AlertTopicArn'}]))

    def test_function_wiring_matches_the_stopper_settings(self):
        fn = self.res['StopperFunction']['Properties']
        self.assertEqual((fn['Handler'], fn['ReservedConcurrentExecutions']), ('src.aws_b.stopper.lambda_handler', 1))
        self.assertEqual(set(fn['Code']), {'S3Bucket', 'S3Key', 'S3ObjectVersion'})
        env = fn['Environment']['Variables']
        self.assertEqual(set(env), {'TARGET_ID', 'TABLE_NAME', 'SCHEDULE_NAME', 'FUNCTION_NAME', 'ALARM_NAMES'})
        self.assertFalse(any(k for k in env if 'SECRET' in k or 'KEY' in k or 'TOKEN' in k))
        self.assertEqual(env['ALARM_NAMES'], {'Ref': 'HeartbeatAlarmName'})


if __name__ == '__main__':
    unittest.main()
