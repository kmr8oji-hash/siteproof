"""M1 offline workspace. Synthetic fixtures are NOT real capture jobs or trusted S2.

Same SQLite file as Baseline/S1; explicit initialization, immutable fixture/result
records, no file upload, arbitrary path, network fetch, repair or automatic approval.
"""
import json
import re
import uuid
from urllib.parse import urlsplit

from src.baseline.approval import DuplicateCandidate, UnknownCandidate
from src.baseline.model import BaselineCandidate, BaselineStatus
from src.baseline.sqlite_store import SQLiteBaselineStore, BaselineStoreError
from src.comparison.profile import CaptureProfile, check_profile_compatibility, is_clean_text
from src.comparison import preview
from src.storage.m1 import M1Repository, M1Error, initialize
from .model import validate_id

KINDS = ('Desktop', 'Mobile')
ASSESSMENT = {'profile_trust': 'UNATTESTED', 'profile_reason': 'PROFILE_UNATTESTED',
              'quality': 'UNKNOWN', 'comparison': 'NOT_RUN'}


def fields(obj, names):
    if type(obj) is not dict or set(obj) != set(names.split()):
        raise M1Error('INVALID_INPUT')


def revision(value):
    if type(value) is not int or not 0 <= value <= 9007199254740991:
        raise M1Error('INVALID_REVISION')
    return value


def profile(kind, width=None, height=None, full_page=False):
    if kind not in KINDS:
        raise M1Error('PROFILE_KIND_INVALID')
    if type(full_page) is not bool:
        raise M1Error('INVALID_INPUT')
    width = width if width is not None else (1440 if kind == 'Desktop' else 390)
    height = height if height is not None else (900 if kind == 'Desktop' else 844)
    if any(type(v) is not int or not 1 <= v <= 4096 for v in (width, height)):
        raise M1Error('PROFILE_SIZE_INVALID')
    return CaptureProfile(kind, {'viewport_width': width, 'viewport_height': height,
        'device_scale_factor': 1, 'color_scheme': 'light', 'locale': 'ja-JP', 'timezone': 'Asia/Tokyo',
        'user_agent': 'SiteProof synthetic fixture ' + kind, 'reduced_motion': True, 'full_page': full_page})


def profile_body(p):
    return {'profile_id': p.profile_id, 'attributes': dict(p.attributes)}


def read_profile(body):
    obj = json.loads(body) if type(body) is str else body
    return CaptureProfile(obj['profile_id'], obj['attributes'])


class OfflineWorkspace:
    def __init__(self, db_path, storage_root):
        self.repo = M1Repository(db_path, storage_root)
        self.db_path, self.storage_root = self.repo.baselines.path, self.repo.baselines.storage_root

    @classmethod
    def create(cls, db_path, storage_root):
        SQLiteBaselineStore.create(db_path, storage_root)
        initialize(db_path, storage_root)
        return cls(db_path, storage_root)

    def state(self):
        with self.repo.read() as c:
            site = c.execute('SELECT * FROM m1_site').fetchone()
            pages = [dict(r) for r in c.execute('SELECT * FROM m1_pages ORDER BY page_id')]
            profiles = [dict(r) for r in c.execute('SELECT p.* FROM m1_profiles p WHERE revision=(SELECT MAX(revision) FROM m1_profiles q WHERE q.page_id=p.page_id AND q.kind=p.kind) ORDER BY page_id,kind')]
            captures = [json.loads(r[0]) for r in c.execute('SELECT body FROM m1_captures ORDER BY rowid DESC LIMIT 100')]
            results = [json.loads(r[0]) for r in c.execute('SELECT body FROM m1_results ORDER BY rowid DESC LIMIT 100')]
        for p in profiles:
            p['profile'] = json.loads(p.pop('body'))
        records = self.repo.baselines.read_page(limit=100).items
        baselines = [{'candidate_id': i.record.candidate.candidate_id, 'page_id': i.record.candidate.page_id,
            'profile_fingerprint': i.record.candidate.profile_fingerprint,
            'approval_state': i.record.status.value, 'candidate_version': i.candidate_version,
            'revision': i.record.revision, 'digest': i.record.registered_digest} for i in records]
        # Labels come from stored M1 capture metadata, never inferred from a hash.
        with self.repo.read() as c:
            for b,i in zip(baselines,records):
                ref = re.fullmatch(r'm1/([a-f0-9]{32})/image\.png',i.record.candidate.artifact_ref)
                row = c.execute('SELECT kind,page_id,fingerprint FROM m1_captures WHERE capture_id=?',(ref[1],)).fetchone() if ref else None
                b['kind'] = row['kind'] if row and row['page_id']==b['page_id'] and row['fingerprint']==b['profile_fingerprint'] else None
        return {'site': dict(site) if site else None, 'pages': pages, 'profiles': profiles,
            'captures': captures, 'results': results, 'baselines': baselines,
            'fixtures': ['original','changed','missing','profile-mismatch'], 'assessment': dict(ASSESSMENT),
            'history_limit': 100, 'real_job_execution': 'NOT_RUN'}

    def save_site(self, obj):
        fields(obj, 'label origin expected_revision')
        if not is_clean_text(obj['label']) or not is_clean_text(obj['origin']):
            raise M1Error('SITE_INVALID')
        u = urlsplit(obj['origin'])
        if (u.scheme != 'https' or not u.hostname or u.username or u.password
                or u.path or u.query or u.fragment or u.port not in (None,443)
                or not re.fullmatch('[a-z0-9.-]+', u.hostname) or obj['origin'] != 'https://' + u.netloc):
            raise M1Error('SITE_INVALID')
        expected = revision(obj['expected_revision'])
        with self.repo.write() as c:
            old = c.execute('SELECT * FROM m1_site').fetchone()
            if (old['revision'] if old else 0) != expected:
                raise M1Error('REVISION_CONFLICT',409)
            if old and old['origin'] != obj['origin'] and c.execute('SELECT 1 FROM m1_pages').fetchone():
                raise M1Error('SITE_ORIGIN_LOCKED',409)
            if old:
                c.execute('UPDATE m1_site SET origin=?,label=?,revision=revision+1', (obj['origin'],obj['label']))
            else:
                c.execute('INSERT INTO m1_site VALUES(1,?,?,1)', (obj['origin'],obj['label']))
        return {'saved': True}

    def save_page(self, obj):
        fields(obj,'page_id label path expected_revision')
        validate_id(obj['page_id'],'page_id')
        path = obj['path']
        if not is_clean_text(obj['label']) or not is_clean_text(path):
            raise M1Error('PAGE_INVALID')
        u = urlsplit(path)
        if not path.startswith('/') or path.startswith('//') or '\\' in path or u.scheme or u.netloc or u.query or u.fragment:
            raise M1Error('PAGE_INVALID')
        expected = revision(obj['expected_revision'])
        with self.repo.write() as c:
            if not c.execute('SELECT 1 FROM m1_site').fetchone():
                raise M1Error('SITE_REQUIRED')
            old = c.execute('SELECT * FROM m1_pages WHERE page_id=?',(obj['page_id'],)).fetchone()
            if (old['revision'] if old else 0) != expected:
                raise M1Error('REVISION_CONFLICT',409)
            if old:
                c.execute('UPDATE m1_pages SET label=?,path=?,revision=revision+1 WHERE page_id=?', (obj['label'],path,obj['page_id']))
            else:
                if c.execute('SELECT COUNT(*) FROM m1_pages').fetchone()[0] >= 5:
                    raise M1Error('PAGE_LIMIT',409)
                c.execute('INSERT INTO m1_pages VALUES(?,?,?,1)',(obj['page_id'],obj['label'],path))
                for kind in KINDS:
                    p = profile(kind)
                    c.execute('INSERT INTO m1_profiles VALUES(?,?,1,?,?)', (obj['page_id'],kind,p.fingerprint,self.repo.dump(profile_body(p))))
        return {'saved':True}

    def save_profile(self,obj):
        fields(obj,'page_id kind width height expected_revision' + (' full_page' if 'full_page' in obj else ''))
        p = profile(obj['kind'],obj['width'],obj['height'],obj.get('full_page',False))
        expected = revision(obj['expected_revision'])
        with self.repo.write() as c:
            row = c.execute('SELECT MAX(revision) FROM m1_profiles WHERE page_id=? AND kind=?',(obj['page_id'],obj['kind'])).fetchone()
            if not row[0]:
                raise M1Error('PAGE_NOT_FOUND',404)
            if row[0] != expected:
                raise M1Error('REVISION_CONFLICT',409)
            c.execute('INSERT INTO m1_profiles VALUES(?,?,?,?,?)',(obj['page_id'],obj['kind'],expected+1,p.fingerprint,self.repo.dump(profile_body(p))))
        return {'saved':True}

    def save_fixture(self,obj):
        fields(obj,'page_id kind fixture')
        data = preview.fixture(obj['fixture'])
        with self.repo.write() as c:
            row = c.execute('SELECT * FROM m1_profiles WHERE page_id=? AND kind=? ORDER BY revision DESC LIMIT 1',(obj['page_id'],obj['kind'])).fetchone()
            page = c.execute('SELECT * FROM m1_pages WHERE page_id=?',(obj['page_id'],)).fetchone()
            site = c.execute('SELECT * FROM m1_site').fetchone()
            if row is None or page is None:
                raise M1Error('PAGE_PROFILE_NOT_FOUND',404)
            p = read_profile(row['body'])
            if obj['fixture'] == 'profile-mismatch':
                attrs = dict(p.attributes); attrs['viewport_width'] += 1
                p = CaptureProfile(p.profile_id, attrs)
            cid = uuid.uuid4().hex
            body = {'capture_id':cid,'page_id':obj['page_id'],'kind':obj['kind'], 'fixture':obj['fixture'],
                'profile_fingerprint':p.fingerprint,'profile_revision':row['revision'],
                'page_revision':page['revision'],'url_snapshot':site['origin'] + page['path'],
                'source':'SYNTHETIC_FIXTURE','fixture_state':'SAVED','job_execution':'NOT_RUN',
                'quality':'UNKNOWN','profile_reason':'PROFILE_UNATTESTED','sha256':preview.digest(data) if data else None}
            c.execute('INSERT INTO m1_captures VALUES(?,?,?,?,?,?,?,?)', (cid,obj['page_id'],obj['kind'],
                self.repo.dump(profile_body(p)),p.fingerprint,body['sha256'],data,self.repo.dump(body)))
        return body

    def capture(self,cid):
        row = self.repo.row('m1_captures','capture_id',cid)
        p = read_profile(row['profile'])
        if p.fingerprint != row['fingerprint']:
            raise M1Error('FIXTURE_INTEGRITY_FAILED',503)
        if row['png'] is not None:
            if preview.digest(row['png']) != row['sha256']:
                raise M1Error('FIXTURE_INTEGRITY_FAILED',503)
            try:
                preview.decode(row['png'])
            except preview.PreviewError:
                raise M1Error('FIXTURE_INTEGRITY_FAILED',503) from None
        return row

    def register_candidate(self,obj):
        fields(obj,'capture_id')
        capture = self.capture(obj['capture_id'])
        if capture['png'] is None:
            raise M1Error('EVIDENCE_MISSING')
        candidate = BaselineCandidate('fixture-' + capture['capture_id'],capture['page_id'],capture['fingerprint'],
            'm1/' + capture['capture_id'] + '/image.png',capture['sha256'])
        try:
            record = self.repo.baselines.register(candidate)
        except DuplicateCandidate:
            raise M1Error('CANDIDATE_EXISTS',409) from None
        return {'candidate_id':candidate.candidate_id,'revision':record.revision,'digest':record.registered_digest,
                'approval_state':'BASELINE_PENDING','quality':'UNKNOWN','profile_reason':'PROFILE_UNATTESTED'}

    def compare(self,obj):
        fields(obj,'capture_id baseline_id')
        after = self.capture(obj['capture_id'])
        try:
            baseline = self.repo.baselines.get(obj['baseline_id'])
        except UnknownCandidate:
            raise M1Error('BASELINE_NOT_FOUND',404) from None
        versions = self.repo.baselines.history(baseline.candidate.page_id,baseline.candidate.profile_fingerprint)
        version = next((v.version for v in versions if v.record.candidate.candidate_id == obj['baseline_id']),None)
        reasons, metrics, diff, before = ['PROFILE_UNATTESTED'], None, None, None
        if not baseline.is_valid_approval():
            reasons.append('BASELINE_PENDING')
        match = re.fullmatch(r'm1/([a-f0-9]{32})/image\.png',baseline.candidate.artifact_ref)
        if match:
            try:
                before = self.capture(match[1])
            except M1Error as exc:
                if exc.status != 404:
                    raise
        if before is None or before['png'] is None or after['png'] is None:
            reasons.append('EVIDENCE_MISSING')
        if baseline.candidate.page_id != after['page_id']:
            reasons.append('PAGE_MISMATCH')
        if before is not None:
            if (before['sha256'] != baseline.candidate.artifact_sha256 or before['fingerprint'] != baseline.candidate.profile_fingerprint
                    or before['page_id'] != baseline.candidate.page_id):
                reasons.append('EVIDENCE_MISMATCH')
            if not check_profile_compatibility(read_profile(before['profile']),read_profile(after['profile'])).compatible:
                reasons.append('PROFILE_MISMATCH')
        if reasons == ['PROFILE_UNATTESTED']:
            try:
                metrics, diff = preview.compare(before['png'],after['png'])
            except preview.PreviewError as exc:
                reasons.append(str(exc))
        rid = uuid.uuid4().hex
        result = {'result_id':rid,'capture_id':after['capture_id'],'before_capture_id':before['capture_id'] if before else None,
            'baseline_id':obj['baseline_id'],'baseline_version':version,'page_id':after['page_id'],'kind':after['kind'],
            'baseline_digest':baseline.registered_digest,'baseline_profile_fingerprint':baseline.candidate.profile_fingerprint,
            'capture_sha256':after['sha256'],'baseline_sha256':baseline.candidate.artifact_sha256,
            'profile_fingerprint':after['fingerprint'],'preview_state':'CALCULATED' if metrics else 'UNAVAILABLE',
            'preview_only':True,'metrics':metrics,'diff_sha256':preview.digest(diff) if diff else None,
            'assessment':dict(ASSESSMENT),'reasons':reasons,'job_execution':'NOT_RUN','source':'SYNTHETIC_FIXTURE'}
        with self.repo.write() as c:
            c.execute('INSERT INTO m1_results VALUES(?,?,?,?,?)',(rid,after['capture_id'],obj['baseline_id'],self.repo.dump(result),diff))
        return result

    def result(self,rid):
        row = self.repo.row('m1_results','result_id',rid)
        result = json.loads(row['body'])
        if row['diff'] is not None and preview.digest(row['diff']) != result['diff_sha256']:
            raise M1Error('PREVIEW_INTEGRITY_FAILED',503)
        return result

    def image(self,cid):
        data = self.capture(cid)['png']
        if data is None:
            raise M1Error('EVIDENCE_MISSING',404)
        return data

    def diff_image(self,rid):
        self.result(rid)
        row = self.repo.row('m1_results','result_id',rid)
        if row['diff'] is None:
            raise M1Error('PREVIEW_UNAVAILABLE',404)
        return row['diff']

    def action(self,name,obj):
        methods = {'site':self.save_site,'page':self.save_page,'profile':self.save_profile,
                   'fixture':self.save_fixture,'candidate':self.register_candidate,'compare':self.compare}
        if name not in methods:
            raise M1Error('NOT_FOUND',404)
        try:
            return methods[name](obj)
        except (BaselineStoreError,OSError):
            raise M1Error('M1_SAVE_UNCONFIRMED',503) from None
        except (ValueError,TypeError,KeyError) as exc:
            if isinstance(exc,M1Error):
                raise
            raise M1Error('INVALID_INPUT') from None
