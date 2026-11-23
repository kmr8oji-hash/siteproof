"""Trusted Linux Worker measurements, deliberately distinct from Browser reports.

The trusted host supplies image identity over the private control channel after
checking owned container IDs/rootfs/mounts. This observer reads the Worker's own
immutable image. Requested context settings and renderer self reports cannot be
promoted to measurements by a signature or by matching these values.
"""
import hashlib
import importlib.metadata
import platform
from pathlib import Path
import secrets
import subprocess

from src.comparison.provenance import EXTRA_FIELDS, TrustedProfileAuthority, canonical
from src.comparison.profile import is_sha256_hex
from src.runtime.stability import verify as verify_stability


class WorkerProfileObserver:
    def __init__(self, image, *, executable):
        if (type(image) is not dict or set(image) != {'image_digest','os','architecture','source'}
                or not is_sha256_hex(image['image_digest'])
                or not image['source'].startswith('launcher:') or image['os'] != 'linux'
                or platform.system() != 'Linux'):
            raise ValueError('independently pinned Linux image required')
        architecture = {'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
        if architecture != image['architecture']:
            raise ValueError('worker architecture differs from pinned image')
        path=Path(executable).resolve(strict=True)
        if not path.is_relative_to('/ms-playwright') or not path.is_file():
            raise ValueError('immutable image browser binary required')
        version=subprocess.run([str(path),'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
        files=sorted(p for p in Path('/usr/share/fonts').rglob('*') if p.is_file())
        if not files: raise ValueError('font inventory unavailable')
        inventory={str(p.relative_to('/usr/share/fonts')):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        self.measured={
            'os':{'value':platform.platform(),'source':'worker:uname-in-pinned-image'},
            'architecture':{'value':architecture,'source':'worker:uname-vs-launcher-image'},
            'browser_version':{'value':version,'source':'worker:pinned-chromium-binary-version'},
            'playwright_version':{'value':importlib.metadata.version('playwright'),'source':'worker:installed-package-metadata'},
            'image_digest':{'value':image['image_digest'],'source':image['source']},
            'fonts_digest':{'value':hashlib.sha256(canonical(inventory)).hexdigest(),'source':'worker:pinned-image-font-inventory'}}
        self.binary_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        self.font_files=len(inventory)
        self.browser_reports={}
        self.repetitions={}

    def __call__(self, profile, phase, job_id):
        configured={**dict(profile.attributes),'is_mobile':profile.profile_id=='Mobile',
                    'animations':'disabled','wait_until':'load','stability_policy':'time-spaced-identical-pngs (src/runtime/stability.py)'}
        # These are instructions, NOT independently measured renderer state.
        result={k:{'value':v,'source':'configured:worker-instruction-only'} for k,v in configured.items()}
        result.update(self.measured)
        # The same trusted stability check as the S3 path (stability.verify): equal received PNG bytes AND a settled, time-spaced run
        # in the producer's shot list. Repeatability only, not authenticity of renderer settings; mandatory settings remain unverified.
        repeated=self.repetitions.get(job_id)
        result['stability_result']=({'value':'STABLE','source':repeated['verified']['source']}
                                    if repeated and repeated['verified']['value']=='STABLE' else None)
        return result

    def record_browser_report(self, job_id, report):
        self.browser_reports[job_id]=report  # Diagnostic only; never input to measured.

    def record_repetition(self, job_id, first, second, stability_report=None, expected_policy=None):
        """No producer stability report (older producers) = UNSTABLE: two equal PNGs alone may both be an unsettled first render."""
        self.repetitions[job_id]={'equal':first==second,'first_sha256':hashlib.sha256(first).hexdigest(),
                                 'second_sha256':hashlib.sha256(second).hexdigest(),
                                 'classification':'INDEPENDENT_RECEIVED_BYTE_COMPARISON',
                                 'verified':verify_stability(stability_report,first,second,expected_policy)}

    def report(self):
        configured=['viewport_width','viewport_height','device_scale_factor','is_mobile',
                    'locale','timezone','color_scheme','user_agent','reduced_motion','full_page',
                    'animations','wait_until','stability_policy']
        return {'measured':self.measured,'binary_sha256':self.binary_sha256,'font_files':self.font_files,
                'configured_only':configured,
                'field_classes':{**{k:'TRUSTED_OBSERVED' for k in self.measured},
                    **{k:'CONFIGURED_ONLY' for k in configured},
                    'browser_self_reports':'BROWSER_REPORTED','actual_renderer_fonts':'UNKNOWN',
                    'actual_renderer_conditions':'UNKNOWN'},
                'browser_self_reports':self.browser_reports,'png_repetition':self.repetitions,
                'profile_trust':'UNATTESTED','reason':'PROFILE_UNATTESTED',
                'scope':'worker image inventory measured; actual renderer conditions not independently authenticated'}


class EphemeralFixtureSigner:
    """Memory-only fixture capability; no file/env/argv/HTTP key transport.

    destroy() revokes the capability. Python cannot promise physical erasure of
    immutable bytes/copies; process/container termination ends this fixture scope.
    This is not a design for long-lived production key custody or persistence.
    """
    def __init__(self, observer):
        self.events=[]
        self.authority=TrustedProfileAuthority(secrets.token_bytes(32),observer,domain='LOCAL_MEASURED')
        self.events.append({'event':'KEY_GENERATED','key_id':self.authority.key_id,
                            'location':'trusted-worker-memory','persistent':False})

    def verification(self, label, accepted):
        self.events.append({'event':'VERIFICATION_ACCEPTED' if accepted else 'VERIFICATION_REJECTED',
                            'case':label,'key_id':self.authority.key_id})

    def destroy(self):
        self.authority.destroy()
        self.events.append({'event':'KEY_REVOKED','key_id':self.authority.key_id,
                            'physical_memory_erasure':'NOT_CLAIMED','process_exit_required':True})
