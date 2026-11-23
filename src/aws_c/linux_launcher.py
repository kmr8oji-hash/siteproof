"""Linux host adapter for the existing M2 Docker launcher. Changes the CLI path only.

`src/runtime/docker_launcher.DockerLauncher` hard-codes Docker Desktop for Windows (CLI
path, context name and named-pipe endpoint) in its constructor. Everything else — the
container options (cap-drop ALL, no-new-privileges, seccomp, read-only root, limits),
the measured-preflight `seal`, the namespace re-check before every Browser start, the
bounded I/O and the archive-then-remove cleanup — is inherited unmodified, so the same
isolation contract and the same validation harness run on an EC2 Linux host.

The existing file is not edited: Windows behaviour and its tests stay byte-identical.
A PASS measured on Windows/WSL2 is NOT a PASS on EC2; the harness must be re-run there.
"""
import json
from pathlib import Path

from src.runtime.docker_launcher import DockerLauncher

LOCAL_ENDPOINT_PREFIX = 'unix://'


class LinuxDockerLauncher(DockerLauncher):
    def __init__(self, evidence, image, seccomp, *, docker='/usr/bin/docker'):
        # Mirrors the base constructor field for field; see test_linux_launcher.py,
        # which fails if the base class gains state this adapter does not set.
        self.evidence = Path(evidence)
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.cli = [docker]
        endpoint = self.call('context', 'inspect', '--format',
                             '{{.Endpoints.docker.Host}}').strip()
        if not endpoint.startswith(LOCAL_ENDPOINT_PREFIX):
            raise RuntimeError('local engine required')
        self.image = image
        self.seccomp = str(Path(seccomp).resolve())
        profile = json.loads(Path(seccomp).read_text())
        if profile.get('defaultAction') != 'SCMP_ACT_ERRNO':
            raise ValueError('bounded seccomp required')
        self.resources = {}
        self.boundary = None
        self.counter = 0
        self.retired = {}
