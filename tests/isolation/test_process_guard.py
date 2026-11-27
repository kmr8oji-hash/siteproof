"""src/isolation/process_guard.py in real child processes: what the guard refuses is refused BEFORE the system call, so nothing here leaves the PC.

Only 127.0.0.1 is ever reached (a listener of the test itself, where an allowed connection has to be shown). This measures the CPython-level
guard; it is not a measurement of any operating-system or network isolation.
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRELUDE = '''
import json, os, socket, sys
sys.path.insert(0, sys.argv[1])
from src.isolation.process_guard import GuardDenied, ProcessGuard
g = ProcessGuard('granted.example')
out = {}
def attempt(name, f):
    try:
        f()
        out[name] = 'ALLOWED'
    except GuardDenied:
        out[name] = 'DENIED'
    except Exception as exc:
        out[name] = 'ERROR:' + type(exc).__name__
'''
EPILOGUE = '''
print(json.dumps({'out': out, 'denied': g.denied, 'connects': g.connects, 'lookups': g.lookups}))
'''


def run(body, *args):
    p = subprocess.run([sys.executable, '-I', '-B', '-c', PRELUDE + body + EPILOGUE, str(ROOT), *map(str, args)], capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise AssertionError(p.stderr)
    return json.loads(p.stdout)


class Guard(unittest.TestCase):
    def test_every_other_way_out_is_refused_and_remembered(self):
        result = run('''
g.install()
attempt('udp', lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
attempt('raw', lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW))
attempt('ipv6', lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
attempt('other name', lambda: socket.getaddrinfo('other.example', 443))
attempt('other port', lambda: socket.getaddrinfo('granted.example', 80))
attempt('gethostbyname', lambda: socket.gethostbyname('granted.example'))
attempt('reverse', lambda: socket.gethostbyaddr('192.0.2.1'))
s = socket.socket()
attempt('unpinned', lambda: s.connect(('192.0.2.1', 443)))
g.pin('192.0.2.1', 443)
attempt('metadata', lambda: s.connect(('169.254.169.254', 80)))
attempt('private', lambda: s.connect(('10.0.0.1', 443)))
attempt('pinned address, other port', lambda: s.connect(('192.0.2.1', 80)))
attempt('bind', lambda: s.bind(('127.0.0.1', 0)))
attempt('second pin', lambda: g.pin('192.0.2.2', 443))
attempt('create_connection', lambda: socket.create_connection(('192.0.2.9', 443), timeout=1))
attempt('process', lambda: __import__('subprocess').run([sys.executable, '-c', 'pass']))
attempt('os.system', lambda: os.system('exit 0'))
attempt('write', lambda: open(os.path.join(os.environ.get('TEMP', '/tmp'), 'siteproof-guard-should-not-exist'), 'w'))
attempt('delete', lambda: os.remove('siteproof-guard-should-not-exist'))
attempt('ctypes', lambda: __import__('ctypes').CDLL('kernel32' if os.name == 'nt' else 'libc.so.6'))
attempt('urllib', lambda: __import__('urllib.request').request.urlopen('http://192.0.2.1/', timeout=1))
attempt('smtp', lambda: __import__('smtplib').SMTP('192.0.2.1', 25, timeout=1))
''')
        self.assertEqual({k: v for k, v in result['out'].items() if v == 'ALLOWED'}, {})
        for name in ('udp', 'raw', 'ipv6', 'other name', 'other port', 'gethostbyname', 'reverse', 'unpinned', 'metadata', 'private', 'pinned address, other port',
                     'bind', 'second pin', 'create_connection', 'process', 'os.system', 'write', 'delete'):
            self.assertEqual(result['out'][name], 'DENIED', name)
        self.assertIn('ctypes.dlopen', result['denied'])  # refused while ctypes is being imported, which then fails on its own
        self.assertEqual((result['connects'], result['lookups']), (0, 0))
        self.assertGreaterEqual(len(result['denied']), 19)  # remembered even though every exception was swallowed above

    def test_one_connection_to_the_pinned_address_and_no_second(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        port, seen = listener.getsockname()[1], []

        def accept():
            listener.settimeout(20)
            try:
                while True:
                    c, _ = listener.accept()
                    seen.append(1)
                    c.close()
            except OSError:
                pass
        threading.Thread(target=accept, daemon=True).start()
        result = run('''
port = int(sys.argv[2])
g.install()
g.pin('127.0.0.1', port)
a, b = socket.socket(), socket.socket()
attempt('first', lambda: a.connect(('127.0.0.1', port)))
attempt('second', lambda: b.connect(('127.0.0.1', port)))
''', port)
        self.assertEqual(result['out'], {'first': 'ALLOWED', 'second': 'DENIED'})
        self.assertEqual(result['connects'], 1)

    def test_tls_still_works_under_the_guard(self):
        # the context, the verification store and the wrapped socket are made under the guard exactly as the real probe makes them
        result = run('''
import ssl
from src.aws_b.probe import TlsTransport
g.install()
attempt('context', lambda: TlsTransport())
import threading
x, y = [], []
def wrap():
    ctx = ssl.create_default_context()
    s = socket.socket()
    t = ctx.wrap_socket(s, server_hostname='granted.example')
    t.close()
attempt('wrap', wrap)
''')
        self.assertEqual(result, {'out': {'context': 'ALLOWED', 'wrap': 'ALLOWED'}, 'denied': [], 'connects': 0, 'lookups': 0})


if __name__ == '__main__':
    unittest.main()
