"""S2-A: Docker API / host-management reachability from the exact Browser identity. No Chromium.

Only the model endpoint (127.0.0.5:2375, a controlled canary the Worker owns) has a positive control: the
trusted identity must reach it and the Browser identity must not. Real Docker Desktop gateway addresses
cannot be given a positive control; they are reported as "not reachable from this identity", which is a
weaker statement than the modelled one and is labelled so in the evidence.
"""
import json
import os
from pathlib import Path
import socket


def tcp(host, port, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(.35)
        try:
            s.connect((host, port))
            return True
        except OSError:
            return False


def unix(path):
    if not os.path.exists(path):
        return 'ABSENT'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(.35)
        try:
            s.connect(path)
            return 'CONNECTED'
        except OSError:
            return 'PRESENT_NOT_CONNECTABLE'


def main():
    uid = os.getuid()
    modelled = {'docker_api_model_127.0.0.5:2375': tcp('127.0.0.5', 2375)}
    unmodelled = {'bridge_gateway_172.17.0.1:2375': tcp('172.17.0.1', 2375), 'bridge_gateway_172.17.0.1:2376': tcp('172.17.0.1', 2376),
                  'desktop_gateway_192.168.65.254:2375': tcp('192.168.65.254', 2375),
                  'desktop_host_192.168.65.2:2375': tcp('192.168.65.2', 2375),
                  'ipv6_ula_fd00::1:2375': tcp('fd00::1', 2375, socket.AF_INET6)}
    sockets = {p: unix(p) for p in ('/var/run/docker.sock', '/run/docker.sock', '/var/run/docker/containerd/containerd.sock')}
    print(json.dumps({'uid': uid, 'netns': os.readlink('/proc/self/ns/net'), 'modelled': modelled, 'unmodelled': unmodelled,
                      'unix_sockets': sockets, 'mounts_with_docker': [l for l in Path('/proc/self/mountinfo').read_text().splitlines()
                                                                      if 'docker.sock' in l],
                      'status': [x for x in Path('/proc/self/status').read_text().splitlines()
                                 if x.startswith(('Cap', 'NoNewPrivs', 'Seccomp'))]}))


if __name__ == '__main__':
    main()
