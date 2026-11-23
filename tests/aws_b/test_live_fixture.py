"""Temporary HTTP fixture + six-page offline integration. No AWS/network/browser."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.aws_b import http_fixture
from src.aws_b.fixture_plan import TARGET
from src.aws_b.handler import Deps
from src.aws_b.model import EVENT_SCHEMA, format_utc
from src.aws_b.probe import ProbeResult
from src.aws_b.store import DynamoStore
from src.core.rules import classify_http_status
from src.noxiworks.aws_b_data import write_fixture, read_export, LocalReadStore, read_stores
from src.noxiworks.product import settings, trial_config, monitor_config, run_page, dashboard
from src.noxiworks.refresh import update, load_config, cli_stores
from tests.aws_fakes import FakeDynamo

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'docs/aws_portfolio/AWS_B_IAM_20261112/prepare-live-templates.py'  # not published (account-specific)
NOW = datetime(2026, 11, 13, 3, tzinfo=timezone.utc)
TRIAL = {'schema': 'siteproof.aws-b-trial.v1', 'trial_id': '20261113-120000',
         'fixture_url': 'https://' + 'a'*26 + '.lambda-url.us-east-1.on.aws/',
         'absolute_end_at': '2026-11-14T03:10:00Z'}
EVENT = {'version': '2.0', 'rawPath': '/', 'rawQueryString': '',
         'requestContext': {'http': {'method': 'GET'}}}


class LiveFixture(unittest.TestCase):
    def setUp(self):
        guard = patch.object(socket, 'socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)
        clock = Mock(wraps=datetime); clock.now.return_value = NOW
        self.clock = clock
        guard = patch.object(http_fixture, 'datetime', clock)
        guard.start(); self.addCleanup(guard.stop)

    def test_http_200_503_recovery_get_only_fixed_body_and_expiry(self):
        with patch.dict(os.environ, {'ABSOLUTE_END_AT': TRIAL['absolute_end_at'], 'PRIVATE_SENTINEL': 'must-not-leak'}, clear=True):
            for status in ('200', '503', '200'):
                os.environ['FIXTURE_HTTP_STATUS'] = status
                result = http_fixture.handler(EVENT, None)
                self.assertEqual(result['statusCode'], int(status))
                self.assertEqual(result['body'], http_fixture.BODY)
                self.assertNotIn('must-not-leak', json.dumps(result))
            for method in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
                event = deepcopy(EVENT); event['requestContext']['http']['method'] = method
                self.assertEqual(http_fixture.handler(event, None)['statusCode'], 405)
                self.assertEqual(os.environ['FIXTURE_HTTP_STATUS'], '200')
            self.assertEqual(http_fixture.handler({}, None)['statusCode'], 405)
            self.assertEqual(http_fixture.handler({**EVENT, 'rawQueryString': 'status=503'}, None)['statusCode'], 404)
            self.assertEqual(http_fixture.handler({**EVENT, 'rawPath': '/admin'}, None)['statusCode'], 404)
            for bad in ('', 'other', '201'):
                os.environ['FIXTURE_HTTP_STATUS'] = bad
                self.assertEqual(http_fixture.handler(EVENT, None)['statusCode'], 503)
            os.environ['ABSOLUTE_END_AT'] = '2026-11-13T03:00:00Z'
            self.assertEqual(http_fixture.handler(EVENT, None)['statusCode'], 410)

    @unittest.skipUnless(GENERATOR.is_file(), 'AWS-B template generator is not published (AWS_B_IAM_20261112/prepare-live-templates.py)')
    def test_trial_plans_permissions_and_url_binding_preserve_five_targets(self):
        spec = importlib.util.spec_from_file_location('fixture_live_generator', GENERATOR)
        gen = importlib.util.module_from_spec(spec); spec.loader.exec_module(gen)
        clock = Mock(wraps=datetime); clock.now.return_value = NOW
        original = (ROOT/'src/noxiworks/targets.json').read_bytes()
        from src.aws_b import fixture_plan
        with tempfile.TemporaryDirectory() as tmp, patch.object(gen, 'datetime', clock), patch.object(fixture_plan, 'ACCOUNT', gen.ACCOUNT):
            tmp = Path(tmp)
            before = gen.prepare(tmp/'provision', TRIAL['trial_id'], start_at='2026-11-13T03:10:00Z', duration_minutes=1440, with_fixture=True)
            self.assertEqual(len(before['pages']), 5)
            self.assertFalse((tmp/'provision/refresh-config.json').exists())
            names = gen.prepare(tmp/'six', TRIAL['trial_id'], start_at='2026-11-13T03:10:00Z', duration_minutes=1440, fixture_url=TRIAL['fixture_url'])
            self.assertEqual(len(names['pages']), 6)
            config = trial_config(TRIAL)
            self.assertEqual(config['pages'][:5], settings()['pages'])
            self.assertEqual(config['pages'][-1]['target_id'], TARGET)
            for target in names['pages']:
                t = json.loads((tmp/'six'/target/'aws-b.template.json').read_text('utf-8'))
                self.assertEqual(t['Parameters']['ScheduleExpression']['Default'], 'rate(15 minutes)')
                self.assertNotIn('AlarmPeriodSeconds', t['Parameters'])           # AWS-B Lite: no per-page alarm
                self.assertEqual(t['Parameters']['MonitorGroup']['Default'], names['prefix'])
                self.assertEqual(t['Parameters']['AbsoluteEndAt']['Default'], TRIAL['absolute_end_at'])
                self.assertEqual(t['Parameters']['ExecutionGeneration']['Default'], 1)
                self.assertEqual([r for r in t['Resources'].values() if r['Type']=='AWS::CloudWatch::Alarm'], [])
            health = json.loads((tmp/'six/health/health.template.json').read_text('utf-8'))
            self.assertEqual(health['Parameters']['ExpectedPages']['Default'], 6)      # five pages + the trial fixture
            self.assertEqual(list(health['Resources']), ['HeartbeatAlarm'])
            f = json.loads((tmp/'six/http-fixture.template.json').read_text('utf-8'))['Resources']
            self.assertEqual(len(f), 7)
            self.assertEqual(f['FixtureUrl']['Properties']['AuthType'], 'NONE')
            self.assertEqual(f['FixtureUrlPermission']['Properties']['Action'], 'lambda:InvokeFunctionUrl')
            self.assertEqual(f['FixtureUrlPermission']['Properties']['FunctionUrlAuthType'], 'NONE')
            self.assertIs(f['FixtureInvokeViaUrlPermission']['Properties']['InvokedViaFunctionUrl'], True)
            fn = f['FixtureFunction']['Properties']
            self.assertEqual((fn['ReservedConcurrentExecutions'], fn['Timeout'], fn['MemorySize']), (1,3,128))
            self.assertEqual(fn['Environment']['Variables']['ABSOLUTE_END_AT'], TRIAL['absolute_end_at'])
            self.assertNotIn('Cors', f['FixtureUrl']['Properties'])
            for policy in (tmp/'six').glob('*policy.json'):
                data = json.loads(policy.read_text('utf-8'))
                self.assertNotIn('123456789012', policy.read_text('utf-8'), policy.name)   # never a placeholder account in a generated policy
                self.assertLessEqual(len(json.dumps(data,separators=(',',':'))),6144)
                for st in data['Statement']:
                    self.assertNotEqual(st['Resource'], '*')
                    acts = st['Action'] if isinstance(st['Action'], list) else [st['Action']]
                    self.assertFalse(any(a.startswith('s3:Delete') for a in acts))
            deploy = json.loads((tmp/'six/trial-fixture-deploy-policy.json').read_text('utf-8'))
            self.assertTrue(any(s['Effect']=='Deny' and s['Action']=='lambda:InvokeFunction' for s in deploy['Statement']))
            conf = load_config(tmp/'six/refresh-config.json')
            self.assertEqual(len(conf['tables']), 6)
            from types import SimpleNamespace
            calls=[]
            def runner(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=0,stdout=json.dumps({'Items':[]} if args[2]=='query' else {}),stderr='')
            env={k:str(tmp/k) for k in ('AWS_CONFIG_FILE','AWS_SHARED_CREDENTIALS_FILE','AWS_LOGIN_CACHE_DIRECTORY','USERPROFILE')}
            stores=cli_stores(conf,runner=runner,environ=env)
            self.assertEqual(len(calls),12)
            self.assertEqual(set(stores),set(conf['tables']))
            blank=read_stores(stores,now=NOW,trial=TRIAL,source='FIXTURE')
            self.assertEqual(dashboard(blank,now=NOW)['pages'][-1]['http']['state'],'UNKNOWN')
            response=tmp/'url-response.json'
            response.write_text(json.dumps({'FunctionArn':'arn:aws:lambda:us-east-1:'+gen.ACCOUNT+':function:siteproof-b-'+TRIAL['trial_id']+'-http-fixture', 'FunctionUrl':TRIAL['fixture_url']}),encoding='utf-8')
            from contextlib import redirect_stdout
            import io
            with redirect_stdout(io.StringIO()) as stdout:
                gen.main(['--out',str(tmp/'cli-six'),'--trial-id',TRIAL['trial_id'],'--start-at','2026-11-13T03:10:00Z','--duration-minutes','1440','--fixture-url-file',str(response)])
            self.assertNotIn(TRIAL['fixture_url'],stdout.getvalue())
            self.assertEqual(len(json.loads((tmp/'cli-six/resource-names.json').read_text('utf-8'))['pages']),6)
            response.write_text(json.dumps({'FunctionArn':'another-trial','FunctionUrl':TRIAL['fixture_url']}),encoding='utf-8')
            from contextlib import redirect_stderr
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gen.main(['--out',str(tmp/'wrong-trial'),'--trial-id',TRIAL['trial_id'],'--end-at','2026-11-13T04:00:00Z','--fixture-url-file',str(response)])
            self.assertFalse((tmp/'wrong-trial').exists())
            for url in ('https://unapproved.invalid/', TRIAL['fixture_url']+'?state=503', TRIAL['fixture_url'].replace('https://','http://'), TRIAL['fixture_url'].replace('https://','https://user@')):
                with self.assertRaises(ValueError): trial_config({**TRIAL,'fixture_url':url})
        self.assertEqual((ROOT/'src/noxiworks/targets.json').read_bytes(), original)

    def test_six_page_http_pipeline_down_recovery_unknown_stale_and_stop(self):
        config = trial_config(TRIAL); page = config['pages'][-1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); write_fixture(tmp/'five', NOW)
            base = read_export(tmp/'five')
            def readers():
                return {tid:LocalReadStore(tid,x['head'],x['runs']) for tid,x in base['http'].items()}
            fake = FakeDynamo(); store = DynamoStore(fake, 'offline-fixture-runs')
            cfg = monitor_config(page, config=config, table='offline-fixture-runs', absolute_end_at=TRIAL['absolute_end_at'])
            store.arm(target_id=TARGET,hostname=cfg.hostname,policy_version=cfg.policy_version,execution_generation=1,armed_at=format_utc(NOW))
            calls=[]; current=NOW
            def probe(_deadline):
                calls.append(current)
                response=http_fixture.handler(EVENT,None)
                outcome,reason=classify_http_status(response['statusCode'],observation_reliable=True)
                return ProbeResult(outcome,reason,http_status=response['statusCode'],elapsed_ms=4)
            with patch.dict(os.environ,{'ABSOLUTE_END_AT':TRIAL['absolute_end_at']},clear=True):
                for i,status in enumerate(('200','503','200')):
                    current=NOW+timedelta(minutes=i*15); self.clock.now.return_value=current
                    os.environ['FIXTURE_HTTP_STATUS']=status
                    deps=Deps(cfg,store,probe,lambda:current,lambda line:None,attempt_id='trial-'+str(i))
                    event={'schema':EVENT_SCHEMA,'target_id':TARGET,'scheduled_time':format_utc(current),'execution_generation':1}
                    self.assertTrue(run_page(page,event,deps,config=config)['persisted'])
                    self.assertEqual(run_page(page,event,deps,config=config)['reason'],'DUPLICATE_SLOT')
                    stores=readers();stores[TARGET]=store
                    result=update(tmp/'home',now=current,stores=stores,source='FIXTURE',trial=TRIAL)
                    self.assertEqual(len(result['view']['pages']),6)
                    fixture=result['view']['pages'][-1]
                    self.assertEqual(fixture['http']['state'],'DOWN' if status=='503' else 'UP')
                    self.assertTrue(all(h['target_id']==TARGET for h in fixture['http']['history']))
                    saved=json.loads((Path(result['version'])/'snapshot.json').read_text('utf-8'))['http']
                    self.assertEqual({tid:saved[tid] for tid in base['http']},base['http'])
                    self.assertIn('デモ',(Path(result['version'])/'index.html').read_text('utf-8'))
                self.assertEqual([h['event'] for h in fixture['http']['history']],['異常を検知','復旧を確認'])
                self.assertEqual(len(calls),3)
                # Reuse the existing local export contract for all six pages as well.
                export=tmp/'six-export';export.mkdir()
                manifest={'schema':'siteproof.aws-b-export.v1','source':'FIXTURE',
                          'target_ids':list(saved),'exported_at':format_utc(current),'trial':TRIAL}
                (export/'manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
                for tid,data in saved.items():
                    folder=export/tid;folder.mkdir()
                    (folder/'head.json').write_text(json.dumps({'Item':data['head']}),encoding='utf-8')
                    (folder/'runs.json').write_text(json.dumps({'Items':data['runs']}),encoding='utf-8')
                imported=read_export(export)
                self.assertEqual(dashboard(imported,now=current)['pages'][-1]['http']['state'],'UP')
                query=json.loads((export/TARGET/'runs.json').read_text('utf-8'))
                query['Items'][0]['pk']['S']='RUN#noxiworks-home'
                (export/TARGET/'runs.json').write_text(json.dumps(query),encoding='utf-8')
                with self.assertRaises(ValueError):read_export(export)
                stores=readers();stores[TARGET]=None
                failed=update(tmp/'home',now=current,stores=stores,source='FIXTURE',trial=TRIAL)
                self.assertEqual(failed['view']['pages'][-1]['http']['state'],'UNKNOWN')
                stores[TARGET]=LocalReadStore(TARGET,None,[])
                self.assertEqual(read_stores(stores,now=current,trial=TRIAL,source='FIXTURE')['http'][TARGET]['runs'],[])
                missing=update(tmp/'home',now=current,stores=stores,source='FIXTURE',trial=TRIAL)
                self.assertEqual(missing['view']['pages'][-1]['http']['state'],'UNKNOWN')
                stores[TARGET]=store
                stale=read_stores(stores,now=current+timedelta(hours=1),trial=TRIAL,source='FIXTURE')
                self.assertEqual(dashboard(stale,now=current+timedelta(hours=1))['pages'][-1]['http']['state'],'STALE')
                store.stop(target_id=TARGET,expected_generation=1,stopped_at=format_utc(current))
                self.assertEqual(run_page(page,event,deps,config=config)['reason'],'STOPPED')
                head=fake.items[('CONTROL#'+TARGET,'HEAD')]
                head['enabled']={'BOOL':True};head['execution_generation']={'N':'2'}
                self.assertEqual(run_page(page,event,deps,config=config)['reason'],'GENERATION_MISMATCH')
                current=datetime(2026,11,14,3,10,tzinfo=timezone.utc)
                self.assertEqual(run_page(page,event,deps,config=config)['reason'],'PAST_ABSOLUTE_END')
                self.assertEqual(len(calls),3)
            # A cross-page row must become UNKNOWN for the fixture, never another page's UP.
            wrong=LocalReadStore(TARGET,base['http']['noxiworks-home']['head'],base['http']['noxiworks-home']['runs'])
            stores=readers();stores[TARGET]=wrong
            bad=read_stores(stores,now=NOW,trial=TRIAL,source='FIXTURE')
            self.assertEqual(bad['http_export']['read_errors'],{TARGET:'READ_FAILED'})
            self.assertEqual(len(settings()['pages']),5)
