"""S3-1-PREFLIGHT fixture peer: a stand-in for the real TTN page on an isolated (--internal) network. Never a real site.

HTTPS (self-signed certificate generated at start for PEER_HOST, SAN included; the PEM is logged so the host can trust it in the
disposable Browser/Worker only) plus a UDP/443 listener. Every request / datagram is logged as one JSON line: the host counts them
from the container log, which is evidence independent of whatever the connecting side reports.
  /about       200, static HTML (no external resource, no script, no animation: renders deterministically)
  /about.html  307 -> /about      (what the real site did in S3-1; lets the pre-capture HEAD rule be tested offline)
  /about.css   200
  /hang        accepts and never answers (for the Chromium stop tests)
  /            200, depends on PEER_TOP: `fixture` (default) a TALL static page (about 2400 px) plus /top.js, which throws one
               TypeError on purpose (page-script-error record); `ttn` the TTN local static build mounted read-only at /ttn (its
               first full-page screenshot re-rasterises the fixed footer once); `unstable` a tall page whose text changes every 50 ms
"""
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ['PEER_HOST']
ABOUT = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>About (fixture)</title><link rel="stylesheet" href="/about.css"><main><h1>About — SiteProof fixture</h1>'
         '<p>This is a local fixture page standing in for a static About page.</p><p class="box">Static content only.</p></main></html>').encode()
CSS = (b'*{animation:none!important;transition:none!important}body{margin:0;background:#f4f6fb;font:20px/1.6 sans-serif;color:#1b2a4a}'
       b'main{padding:32px;max-width:900px}h1{color:#213876}.box{background:#dfe6fb;padding:16px;border-radius:8px}')


TOP = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       '<title>Top (fixture)</title><link rel="stylesheet" href="/about.css"><main><h1>Top — SiteProof fixture</h1>'
       + ''.join(f'<p class="box">Section {n}: static content for a full-page capture.</p>' for n in range(1, 25))
       + '</main><script src="/top.js"></script></html>').encode()
TOP_JS = b'document.body.dataset.fixture = "top"; null.deliberateFixtureError;'
TOP_MODE = os.environ.get('PEER_TOP', 'fixture')
UNSTABLE = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Unstable (fixture)</title><link rel="stylesheet" href="/about.css"><main><h1 id="tick">0</h1>'
            + ''.join(f'<p class="box">Section {n}</p>' for n in range(1, 25)) + '</main><script src="/unstable.js"></script></html>').encode()
UNSTABLE_JS = b'setInterval(function(){document.getElementById("tick").textContent=String(Math.floor(performance.now()))},50);'
TTN_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
             '.png': 'image/png', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain'}


def ttn_file(path):
    """A file of the read-only TTN build under /ttn, or None. Plain relative paths only."""
    rel = 'index.html' if path == '/' else path.lstrip('/')
    if not rel or '..' in rel.split('/') or rel.startswith('/'):
        return None
    full = os.path.join('/ttn', rel)
    return full if os.path.isfile(full) and os.path.realpath(full).startswith('/ttn/') else None


def log(**fields):
    print(json.dumps(fields), flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _send(self, status, body=b'', ctype='text/html; charset=utf-8', location=None, head=False):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if location:
            self.send_header('Location', location)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def handle_any(self, head):
        path = self.path.split('?')[0]
        log(event='request', method=self.command, path=path, t=round(time.time(), 3))
        if path == '/about':
            self._send(200, ABOUT, head=head)
        elif path == '/about.css':
            self._send(200, CSS, 'text/css', head=head)
        elif path == '/about.html':
            self._send(307, b'', location='/about', head=head)
        elif TOP_MODE == 'ttn' and ttn_file(path):
            full = ttn_file(path)
            self._send(200, open(full, 'rb').read(), TTN_TYPES.get(os.path.splitext(full)[1], 'application/octet-stream'), head=head)
        elif path == '/' and TOP_MODE == 'unstable':
            self._send(200, UNSTABLE, head=head)
        elif path == '/unstable.js':
            self._send(200, UNSTABLE_JS, 'text/javascript', head=head)
        elif path == '/':
            self._send(200, TOP, head=head)
        elif path == '/top.js':
            self._send(200, TOP_JS, 'text/javascript', head=head)
        elif path == '/hang':
            time.sleep(120)
        else:
            self._send(404, b'', head=head)

    def do_GET(self):
        self.handle_any(False)

    def do_HEAD(self):
        self.handle_any(True)


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 443))
    while True:
        data, peer = sock.recvfrom(2048)
        log(event='udp', bytes=len(data), t=round(time.time(), 3))
        sock.sendto(data[:16], peer)


def main():
    cert, key = '/tmp/peer.crt', '/tmp/peer.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key, '-out', cert, '-subj', '/CN=' + HOST,
                    '-addext', 'subjectAltName=DNS:' + HOST], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(event='cert', pem=open(cert).read())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=udp, daemon=True).start()
    log(event='listening', host=HOST)
    server.serve_forever()


if __name__ == '__main__':
    main()
