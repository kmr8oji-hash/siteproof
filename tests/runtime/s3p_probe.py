"""S3-1-PREFLIGHT in-container behavioural probes (T-A). One mode per run, bounded, no network, no host path touched.

  readonly  writes to protected paths (root fs, read-only bind mounts) must fail with EROFS; the allowed tmpfs writes must succeed
  storage   managed targets: a CANARY file that exists ONLY in a volume this container does not mount must not be reachable by any
            path; no Docker socket; no writable non-tmpfs mount; the mount table is returned for classification
  bundle    Browser code bundle (S3-1-UNBLOCK): the visible project tree is EXACTLY the manifest, nothing outside it can be read or imported
  pids / nofile / memory / tmpfs   enforced limits, with deliberately LOW test-only caps set by the host on a throwaway container
Every loop has a hard small bound, so a failed limit cannot load the host.
"""
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time


def name(exc):
    return errno.errorcode.get(exc.errno, type(exc).__name__) if getattr(exc, 'errno', None) else type(exc).__name__


def attempt_write(path):
    try:
        with open(path, 'wb') as f:
            f.write(b'siteproof-preflight')
        os.remove(path)
        return {'written': True}
    except OSError as exc:
        return {'written': False, 'errno': name(exc)}


def mounts():
    rows = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ')
        fields = left.split()
        rows.append({'dest': fields[4], 'options': fields[5], 'fstype': right.split()[0], 'source': right.split()[1]})
    return rows


def cgroup():
    return {n: Path('/sys/fs/cgroup/' + n).read_text().strip() for n in ('memory.max', 'pids.max', 'cpu.max')}


def readonly(config):
    protected = ['/etc/siteproof-ro-test', '/usr/local/siteproof-ro-test', '/opt/siteproof/ro-test', '/opt/siteproof/src/ro-test',
                 '/opt/siteproof/tests/runtime/ro-test', '/var/siteproof-ro-test', '/root/siteproof-ro-test']
    allowed = ['/tmp/ro-allowed', '/dev/shm/ro-allowed']
    return {'protected': {p: attempt_write(p) for p in protected}, 'allowed': {p: attempt_write(p) for p in allowed},
            'root_mount_options': next(m['options'] for m in mounts() if m['dest'] == '/'), 'uid': os.getuid()}


def storage(config):
    target, hits, scanned = config['canary'], [], 0
    for root, dirs, files in os.walk('/', followlinks=False):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in ('/proc', '/sys', '/dev')]
        scanned += len(files)
        if target in files:
            hits.append(os.path.join(root, target))
        if scanned > 400000:
            break
    paths = ('/evidence', '/evidence/' + target, '/host', '/mnt/host', '/run/desktop', '/var/lib/docker', '/var/run/docker.sock', '/run/docker.sock',
             '/var/run/docker/containerd/containerd.sock', '/proc/1/root/evidence/' + target)
    return {'canary_found_at': hits, 'files_scanned': scanned, 'direct_paths_exist': {p: os.path.exists(p) for p in paths},
            'docker_env': [k for k in os.environ if k.startswith('DOCKER')], 'mounts': mounts(), 'uid': os.getuid()}


def bundle(config):
    root = '/opt/siteproof'
    visible, symlinks = {}, []
    for base, dirs, files in os.walk(root, followlinks=False):
        symlinks += [os.path.join(base, d) for d in dirs if os.path.islink(os.path.join(base, d))]
        for f in files:
            path = os.path.join(base, f)
            rel = os.path.relpath(path, root).replace(os.sep, '/')
            if os.path.islink(path):
                symlinks.append(path)
            else:
                visible[rel] = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    unreadable = {}
    for rel in config['probe_paths']:
        path = os.path.join(root, rel)
        try:
            open(path, 'rb').read(1)
            unreadable[rel] = 'READABLE'
        except OSError as exc:
            unreadable[rel] = name(exc)
    imports = {}
    for module, expect in [(m, True) for m in config['entry_modules']] + [(m, False) for m in config['forbidden_modules']]:
        try:
            importlib.import_module(module)
            imports[module] = {'imported': True, 'expected': expect}
        except Exception as exc:
            imports[module] = {'imported': False, 'expected': expect, 'error': type(exc).__name__}
    sentinels, skip = set(config['sentinels']), ('/proc', '/sys', '/dev')
    found = []
    for base, dirs, files in os.walk('/', followlinks=False):
        dirs[:] = [d for d in dirs if os.path.join(base, d) not in skip]
        found += [os.path.join(base, f) for f in files if f in sentinels]
    return {'visible_files': visible, 'manifest_files': config['manifest'], 'symlinks': symlinks, 'probe_paths': unreadable, 'imports': imports,
            'sentinel_hits': found, 'write_into_bundle': attempt_write(root + '/siteproof-write-test'), 'fixture_ca_present': os.path.exists('/fixture-ca.crt'),
            'opt_entries': sorted(os.listdir('/opt')), 'siteproof_entries': sorted(os.listdir(root)),
            'mounts': [m for m in mounts() if m['dest'] == root or m['fstype'] in ('9p', 'virtiofs', 'fuse', 'fuse.grpcfuse', 'ext4')], 'uid': os.getuid()}


def pids(config):
    children, failed = [], None
    for _ in range(40):
        try:
            pid = os.fork()
        except OSError as exc:
            failed = name(exc)
            break
        if pid == 0:
            time.sleep(4)
            os._exit(0)
        children.append(pid)
    for pid in children:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    return {'forked': len(children), 'attempt_cap': 40, 'failed_with': failed}


def nofile(config):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    handles, failed = [], None
    for _ in range(100):
        try:
            handles.append(open('/dev/null'))
        except OSError as exc:
            failed = name(exc)
            break
    opened = len(handles)
    for h in handles:
        h.close()
    return {'soft': soft, 'hard': hard, 'opened': opened, 'attempt_cap': 100, 'failed_with': failed}


def memory(config):
    chunks = []
    for _ in range(16):  # at most 128 MiB, in 8 MiB steps; the container cap is far below that
        block = bytearray(8 * 1024 * 1024)
        for offset in range(0, len(block), 4096):
            block[offset] = 1
        chunks.append(block)
    return {'survived_allocating_mib': len(chunks) * 8}  # Reaching this line means the limit was NOT enforced.


def tmpfs(config):
    written, failed = 0, None
    chunk = b'x' * (1024 * 1024)
    try:
        with open('/tmp/fill', 'wb') as f:
            for _ in range(24):
                f.write(chunk)
                f.flush()
                written += len(chunk)
    except OSError as exc:
        failed = name(exc)
    return {'written_mib': written // (1024 * 1024), 'attempt_cap_mib': 24, 'failed_with': failed}


def main():
    config = json.loads(sys.stdin.buffer.readline(16385))
    result = {'readonly': readonly, 'storage': storage, 'bundle': bundle, 'pids': pids, 'nofile': nofile, 'memory': memory, 'tmpfs': tmpfs}[config['mode']](config)
    print(json.dumps({'mode': config['mode'], 'uid': os.getuid(), 'cgroup': cgroup(), 'result': result,
                      'status': [x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(('Cap', 'NoNewPrivs', 'Seccomp'))]}))


if __name__ == '__main__':
    main()
