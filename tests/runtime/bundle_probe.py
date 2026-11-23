"""Host-side runner: prove, from INSIDE a Browser-identity container, what the Browser-visible project tree really is (S3-1-UNBLOCK).

One throwaway container, --network none, with exactly the Browser flags and ONLY the mounts a real-site Browser container gets (the bundle
over /opt/siteproof, the read-only resolver file; no fixture CA). The probe code is passed in-line (base64), so it is not part of the bundle.
Used by the offline rehearsal and by the real run's pre-navigation Gate: a failure there stops the run before any real-site contact.
"""
import base64
import json
from pathlib import Path

from tests.runtime.browser_bundle import BROWSER_ENTRIES, mount_args

FORBIDDEN_MODULES = ('src.storage.repository', 'src.bff.local_ui', 'src.noxiworks.product', 'src.comparison.service', 'src.runtime.service',
                     'src.runtime.docker_launcher', 'tests.runtime.validate_s3', 'tests.runtime.s3_worker', 'tests.runtime.egress_broker')
PROBE_PATHS = ('src/noxiworks/targets.json', 'src/storage/repository.py', 'src/bff/local_ui.py', 'src/aws_c/control.py', 'src/comparison/service.py',
               'tests/runtime/validate_s3.py', 'tests/runtime/s3_worker.py', 'tests/runtime/netpolicy_hardened.py', 'tests/isolation/test_transport.py',
               'web/home/index.html', 'runtime/docker/Dockerfile', 'runtime/docker/seccomp-siteproof.json')
SENTINELS = ('targets.json', 'validate_s3.py', 'validate_s2v.py', 'local_ui.py', 'siteproof.sqlite', 'netpolicy_hardened.py', 'egress_broker.py', 'seccomp-siteproof.json')


def run_bundle_probe(launch, name, tree, manifest, resolver_file, save):
    """Returns (checks, record). `name` makes a unique container name; `save(label, obj)` stores evidence."""
    source = (Path(__file__).with_name('s3p_probe.py')).read_text('utf-8')
    code = 'import base64;exec(compile(base64.b64decode(%r).decode(),"probe","exec"),{"__name__":"__main__"})' % base64.b64encode(source.encode()).decode()
    uid = 1000
    options = ['--network', 'none', '--user', f'{uid}:{uid}', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--security-opt', 'seccomp=' + launch.seccomp,
               '--read-only', '--pids-limit', '256', '--memory', '768m', '--memory-swap', '768m', '--cpus', '1', '--ulimit', 'nofile=256:256', '--shm-size', '128m',
               '--tmpfs', f'/tmp:rw,nosuid,nodev,size=256m,uid={uid},gid={uid}', '--env', 'HOME=/tmp/browser-home', *mount_args(tree),
               '--mount', f'type=bind,src={Path(resolver_file).resolve()},dst=/etc/resolv.conf,readonly']
    container = launch.create(name, options, ['python', '-c', code])
    config = {'mode': 'bundle', 'manifest': {k: v['sha256'] for k, v in manifest['files'].items()}, 'probe_paths': list(PROBE_PATHS), 'sentinels': list(SENTINELS),
              'entry_modules': [e[:-3].replace('/', '.') for e in BROWSER_ENTRIES], 'forbidden_modules': list(FORBIDDEN_MODULES)}
    out, _ = launch.bounded(container, json.dumps(config).encode() + b'\n', seconds=90)
    record = json.loads(out)
    save('bundle-probe.json', record)
    r = record['result']
    wanted_mounts = {m['dest'] for m in r['mounts']}
    checks = {
        'bundle_browser_sees_exactly_the_manifest_files_under_opt_siteproof': r['visible_files'] == r['manifest_files'] and r['symlinks'] == [],
        'bundle_no_other_project_directory_remains_visible': r['siteproof_entries'] == sorted({p.split('/')[0] for p in r['manifest_files']}),
        'bundle_every_out_of_bundle_development_path_is_unreadable': all(v != 'READABLE' for v in r['probe_paths'].values()) and set(r['probe_paths'].values()) <= {'ENOENT'},
        'bundle_entry_modules_import_from_the_bundle': all(v['imported'] for v in r['imports'].values() if v['expected']),
        'bundle_out_of_bundle_modules_cannot_be_imported': all(v['imported'] is False and v['error'] == 'ModuleNotFoundError' for v in r['imports'].values() if not v['expected']),
        'bundle_no_development_asset_by_name_is_visible_anywhere': r['sentinel_hits'] == [],
        'bundle_is_read_only_and_unwritable': r['write_into_bundle'] == {'written': False, 'errno': 'EROFS'},
        'bundle_the_only_host_derived_project_mount_is_opt_siteproof': '/opt/siteproof' in wanted_mounts and all(
            m['options'].split(',')[0] == 'ro' for m in r['mounts'] if m['dest'] in ('/opt/siteproof', '/etc/resolv.conf')),
        'bundle_no_fixture_ca_in_the_real_style_configuration': r['fixture_ca_present'] is False,
        'bundle_runs_as_the_unprivileged_browser_uid': r['uid'] == uid and any(x.split() == ['CapBnd:', '0000000000000000'] for x in record['status'])}
    return checks, record
