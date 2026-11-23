"""AWS-B typed writes through local export to HOME; only injected fixture probes."""
from copy import deepcopy
from datetime import datetime,timezone
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from src.noxiworks.aws_b_data import write_fixture, read_export
from src.noxiworks.home import build
from src.noxiworks.product import settings, monitor_config, deployment_plan
from tests.aws_b.support import Harness, event

NOW=datetime(2026,11,12,3,0,tzinfo=timezone.utc)
ROOT=Path(__file__).resolve().parents[1]


class AwsBHome(unittest.TestCase):
    def test_typed_store_to_five_page_home_and_page_history(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(socket,'getaddrinfo',side_effect=AssertionError('network forbidden')):
            tmp=Path(tmp)
            write_fixture(tmp/'input',NOW)
            snapshot=read_export(tmp/'input')
            self.assertEqual(snapshot['source'],'FIXTURE')
            view=build(tmp/'home',snapshot,now=NOW)
            pages={p['target_id']:p for p in view['pages']}
            expected={'noxiworks-home':'UP','noxiworks-taxi':'DOWN','hms-home':'UNKNOWN','hms-concierge':'UNKNOWN','ttn-home':'UP'}
            self.assertEqual({k:p['http']['state'] for k,p in pages.items()},expected)
            self.assertEqual(pages['noxiworks-home']['http']['http_status'],200)
            self.assertEqual(pages['noxiworks-home']['http']['elapsed_ms'],80)
            self.assertEqual(pages['noxiworks-home']['http']['last_checked_at'],'2026-11-12T03:00:00Z')
            self.assertEqual([h['event'] for h in pages['noxiworks-home']['http']['history']],['異常を検知','復旧を確認'])
            self.assertEqual([h['event'] for h in pages['noxiworks-taxi']['http']['history']],['異常を検知'])
            self.assertEqual(pages['hms-home']['http']['history'],[])
            self.assertEqual(pages['hms-concierge']['http']['http_status'],None)
            for target,p in pages.items():
                self.assertTrue(all(h['target_id']==target for h in p['http']['history']))
                detail=json.loads((tmp/'home/evidence'/target/'details.json').read_text('utf-8'))
                self.assertEqual(detail['page']['target_id'],target)
            html=(tmp/'home/index.html').read_text('utf-8')
            self.assertIn('badge badge-sample">デモ',html)
            self.assertIn('HTTP 200 · 80 ms',html)
            self.assertIn('HTTP 503 · 105 ms',html)
            self.assertIn('異常・復旧履歴',(tmp/'home/details.html').read_text('utf-8'))
            self.assertEqual(len([x for x in view['expiry'] if x['kind']=='TLS証明書']),3)
            self.assertEqual(len([x for x in view['expiry'] if x['state']=='PROVIDER_MANAGED']),2)
            audit=json.loads((tmp/'input/fixture-audit.json').read_text('utf-8'))
            self.assertEqual(len(audit['probe_stub_calls']),6)
            self.assertEqual(sum(x['reason']=='DUPLICATE_SLOT' for x in audit['decisions']),6)

    def test_import_provenance_cross_page_and_unconfigured_url_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            write_fixture(tmp/'input',NOW)
            manifest=tmp/'input/manifest.json'
            original=json.loads(manifest.read_text('utf-8'))
            manifest.write_text(json.dumps({**original,'source':'AWS_EXPORT'}),encoding='utf-8')
            with self.assertRaises(ValueError):read_export(tmp/'input')
            manifest.write_text(json.dumps({**original,'target_ids':original['target_ids']+['foreign']}),encoding='utf-8')
            with self.assertRaises(ValueError):read_export(tmp/'input')
            manifest.write_text(json.dumps(original),encoding='utf-8')
            query=tmp/'input/ttn-home/runs.json'
            body=json.loads(query.read_text('utf-8'))
            body['Items'][0]['pk']['S']='RUN#hms-home'
            query.write_text(json.dumps(body),encoding='utf-8')
            with self.assertRaises(ValueError):read_export(tmp/'input')
            # A listed target with a missing response is an import failure, not a silent success.
            with self.assertRaises(FileNotFoundError):read_export(tmp/'missing')
        page=deepcopy(settings()['pages'][0])
        page['url']='https://unconfigured.invalid/'
        with self.assertRaises(ValueError):monitor_config(page,table='offline-table',absolute_end_at='2026-11-12T04:00:00Z')
        template=json.loads((ROOT/'infra/aws_b/template.json').read_text('utf-8'))
        for plan in deployment_plan(template):
            for key in ('TargetId','TargetHostname','TargetPath'):
                self.assertEqual(plan['template']['Parameters'][key]['AllowedValues'],[plan['parameters'][key]])

    def test_static_snapshot_states_freshness_and_historical_scope(self):
        from datetime import timedelta
        from src.noxiworks.product import dashboard, empty_snapshot
        from src.noxiworks.home import render, tag
        with tempfile.TemporaryDirectory() as tmp, patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            write_fixture(Path(tmp) / 'input', NOW)
            snapshot = read_export(Path(tmp) / 'input')
            fresh = dashboard(snapshot, now=NOW)
            self.assertEqual([p['http']['state'] for p in fresh['pages']], ['UP', 'DOWN', 'UNKNOWN', 'UNKNOWN', 'UP'])
            self.assertEqual(fresh['source_mode'], 'SAMPLE')
            self.assertEqual(fresh['current_monitoring_state'], 'UNKNOWN')
            self.assertEqual(fresh['pages'][0]['http']['fresh_until'], '2026-11-12T15:00:00Z')
            stopped = deepcopy(snapshot)
            stopped['http']['noxiworks-home']['head']['enabled'] = {'BOOL': False}
            self.assertEqual(dashboard(stopped, now=NOW)['pages'][0]['http']['state'], 'STOPPED')
            self.assertEqual(dashboard(stopped, now=NOW+timedelta(days=2))['pages'][0]['http']['state'], 'STOPPED')
            stale = dashboard(snapshot, now=NOW+timedelta(hours=13))
            self.assertEqual(stale['pages'][0]['http']['state'], 'STALE')
            self.assertNotIn('UP', [p['http']['state'] for p in stale['pages']])
            missing = dashboard(empty_snapshot(), now=NOW)
            self.assertEqual({p['http']['state'] for p in missing['pages']}, {'NOT_FETCHED'})
            self.assertEqual(len({tag(s) for s in ('UP','DOWN','STALE','STOPPED','UNKNOWN','NOT_FETCHED')}), 6)
            # Renderer input only: no synthetic HTTP data is exported as AWS evidence.
            historical = deepcopy(fresh)
            historical.update(source='AWS_EXPORT', source_mode='HISTORICAL')
            original = deepcopy(historical)
            html = render(historical)
            self.assertEqual(historical, original)
            self.assertIn('保存済みの監視結果', html)
            self.assertIn('過去の観測 · HTTP 200', html)
            for view in (fresh, missing, historical):
                html = render(view)
                self.assertIn('リアルタイムの情報ではありません', html)
                self.assertIn('保存済みの監視結果の概要', html)
                self.assertIn('総合品質：未評価', html)
                self.assertNotIn('現在の状態', html)
                self.assertTrue(all(p['change']['state'] == 'UNKNOWN' for p in view['pages']))

    def test_refresh_versions_new_observations_partial_read_and_render_failure(self):
        from datetime import timedelta
        from src.noxiworks.aws_b_data import LocalReadStore
        from src.noxiworks.refresh import update
        from tools.export_capture_fixture import verify_links
        import hashlib
        with tempfile.TemporaryDirectory() as tmp, patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            tmp=Path(tmp); write_fixture(tmp/'input',NOW); snap=read_export(tmp/'input')
            def readers(s):
                return {tid:LocalReadStore(tid,v['head'],v['runs']) for tid,v in s['http'].items()}
            first=update(tmp/'home',now=NOW,stores=readers(snap),source='FIXTURE')
            self.assertEqual(first['status'],'OK')
            self.assertEqual([p['http']['state'] for p in first['view']['pages']],['UP','DOWN','UNKNOWN','UNKNOWN','UP'])
            initial=Path(first['version'])/'snapshot.json'; initial_hash=hashlib.sha256(initial.read_bytes()).hexdigest()
            newer=deepcopy(snap);at=NOW+timedelta(minutes=15)
            for value in newer['http'].values():
                if value['runs']:
                    row=max(value['runs'],key=lambda r:r['sk']['S'])
                    row['sk']['S']=at.strftime('%Y-%m-%dT%H:%M:%SZ'); row['finished_at']['S']=row['sk']['S']
            second=update(tmp/'home',now=at,stores=readers(newer),source='FIXTURE')
            self.assertNotEqual(first['version'],second['version'])
            self.assertEqual(second['view']['pages'][0]['http']['last_checked_at'],'2026-11-12T03:15:00Z')
            self.assertEqual(second['view']['pages'][0]['http']['fresh_until'],'2026-11-12T03:45:00Z')
            self.assertEqual(second['view']['http_interval_seconds'],900)
            self.assertIn(Path(second['version']).name,(tmp/'home/latest.html').read_text('utf-8'))
            self.assertGreater(verify_links(Path(second['version'])),100)
            broken=readers(newer);broken['noxiworks-home']=None
            broken['ttn-home']=LocalReadStore('ttn-home',None,[])
            partial=update(tmp/'home',now=at,stores=broken,source='FIXTURE')
            pages={p['target_id']:p for p in partial['view']['pages']}
            self.assertEqual(partial['status'],'PARTIAL')
            self.assertEqual((pages['noxiworks-home']['http']['state'],pages['noxiworks-home']['http']['http_status']),('UNKNOWN',None))
            self.assertEqual(pages['ttn-home']['http']['state'],'NOT_FETCHED')
            self.assertIn('取得に失敗したページ 1',(Path(partial['version'])/'index.html').read_text('utf-8'))
            self.assertEqual(hashlib.sha256(initial.read_bytes()).hexdigest(),initial_hash)
            with patch('src.noxiworks.refresh.build',side_effect=RuntimeError('private error details')):
                with self.assertRaises(RuntimeError):update(tmp/'home',now=at,stores=readers(newer),source='FIXTURE')
            entry=(tmp/'home/latest.html').read_text('utf-8')
            self.assertIn('更新失敗',entry);self.assertIn('UNKNOWN',entry)
            self.assertNotIn('http-equiv="refresh"',entry);self.assertNotIn('private error details',entry)
            self.assertIn(Path(second['version']).name,entry)
            self.assertTrue((Path(second['version'])/'snapshot.json').is_file())
            stale=update(tmp/'stale',now=at+timedelta(hours=1),stores=readers(newer),source='FIXTURE')
            self.assertEqual(stale['view']['pages'][0]['http']['state'],'STALE')

    def test_cli_reader_is_d_environment_gated_and_get_query_only(self):
        from types import SimpleNamespace
        from src.noxiworks.refresh import load_config,cli_stores
        from src.noxiworks.aws_b_data import read_stores
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);write_fixture(tmp/'input',NOW);snap=read_export(tmp/'input')
            tables={p['target_id']:'siteproof-b-'+p['target_id'] for p in settings()['pages']}
            conf={'schema':'siteproof.aws-b-refresh.v1','profile':'siteproof-live','region':'us-east-1','tables':tables,'interval_seconds':900}
            (tmp/'refresh.json').write_text(json.dumps(conf),encoding='utf-8')
            conf=load_config(tmp/'refresh.json');calls=[]
            def runner(argv,**kwargs):
                calls.append(argv);op=argv[2];request=json.loads(argv[argv.index('--cli-input-json')+1]);self.assertTrue(request['ConsistentRead'])
                tid=next(t for t,table in tables.items() if table==request['TableName'])
                response={'Items':snap['http'][tid]['runs']} if op=='query' else {'Item':snap['http'][tid]['head']}
                self.assertIn(op,('get-item','query'))
                return SimpleNamespace(returncode=0,stdout=json.dumps(response),stderr='')
            env={k:str(tmp/k) for k in ('AWS_CONFIG_FILE','AWS_SHARED_CREDENTIALS_FILE','AWS_LOGIN_CACHE_DIRECTORY','USERPROFILE')}
            stores=cli_stores(conf,runner=runner,environ=env)
            result=read_stores(stores,now=NOW,source='FIXTURE')
            self.assertEqual(result['http_export']['read_errors'],{})
            self.assertEqual(len(calls),10)
            self.assertTrue(all(a[a.index('--profile')+1]=='siteproof-live' and '--no-paginate' in a for a in calls))
            with self.assertRaises(ValueError):cli_stores(conf,runner=runner,environ={'AWS_CONFIG_FILE':'relative'})
            self.assertEqual(len(calls),10)
            broken=cli_stores(conf,runner=lambda *a,**k:SimpleNamespace(returncode=1,stdout='',stderr='secret details'),environ=env)
            result=read_stores(broken,now=NOW,source='FIXTURE')
            self.assertEqual(len(result['http_export']['read_errors']),5)
            self.assertNotIn('secret details',json.dumps(result))

    def test_one_command_local_refresh_and_aws_gate(self):
        import sys
        from src.noxiworks.__main__ import main
        with tempfile.TemporaryDirectory() as tmp, patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            tmp=Path(tmp);write_fixture(tmp/'input',NOW)
            with patch.object(sys,'argv',['siteproof','--refresh','--aws-b-input',str(tmp/'input'),'--out',str(tmp/'home')]):main()
            self.assertTrue((tmp/'home/latest.html').is_file())
            state=json.loads((tmp/'home/refresh-state.json').read_text('utf-8'))
            path=tmp/'home'/state['generation']
            for name in ['index.html','review.html','details.html','activity.html','evidence.html','aws-operations.html']:
                self.assertTrue((path.parent/name).is_file())
            html=path.read_text('utf-8');self.assertIn('id="viewed-at"',html);self.assertIn('データ取得：',html)
            with patch.object(sys,'argv',['siteproof','--refresh-config',str(tmp/'missing.json'),'--out',str(tmp/'blocked')]):
                with self.assertRaises(SystemExit) as ex:main()
            self.assertEqual(ex.exception.code,2)
            self.assertFalse((tmp/'blocked').exists())

    def test_existing_duplicate_generation_stop_and_absolute_end_refusals(self):
        h=Harness()
        h.invoke(event())
        self.assertEqual(h.invoke(event())['reason'],'DUPLICATE_SLOT')
        self.assertEqual(len(h.probes),1)
        h.stop()
        self.assertEqual(h.invoke(event())['reason'],'STOPPED')
        old=Harness()
        old.head()['execution_generation']={'N':'2'}
        self.assertEqual(old.invoke(event())['reason'],'GENERATION_MISMATCH')
        self.assertEqual(old.probes,[])
        expired=Harness()
        expired.now=expired.config.absolute_end_at
        self.assertEqual(expired.invoke(event())['reason'],'PAST_ABSOLUTE_END')
        self.assertEqual(expired.probes,[])


if __name__=='__main__':unittest.main()
