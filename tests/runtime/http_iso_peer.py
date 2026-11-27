"""Fixture HTTPS peer for validate_http_iso.py on an isolated (--internal) network. Never a real site. Logs one JSON line per accepted connection and
request (evidence independent of what the connecting side says). The self-signed certificate names PEER_HOST, or another name for the mismatch case.
  /  200     /redirect  302 -> another host     /error  503     /long  a status line over the 16 KiB cap     /drip  one byte per 0.2 s     /hang  nothing
"""
import json
import os
import socket
import ssl
import subprocess
import threading
import time


def log(**fields):
    print(json.dumps(fields), flush=True)


def answer(client, path):
    if path == '/redirect':
        client.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://elsewhere.invalid/\r\nContent-Length: 0\r\n\r\n')
    elif path == '/error':
        client.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n')
    elif path == '/long':
        client.sendall(b'HTTP/1.1 ' + b'9' * 40000)
    elif path == '/drip':
        for byte in b'HTTP/1.1 200 OK' * 20:
            client.sendall(bytes([byte]))
            time.sleep(.2)
    elif path == '/hang':
        time.sleep(60)
    else:
        client.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok')


def serve(raw, context, source):
    try:
        raw.settimeout(15)
        with context.wrap_socket(raw, server_side=True) as client:
            data = b''
            while b'\r\n' not in data and len(data) < 4096:
                part = client.recv(1024)
                if not part:
                    return
                data += part
            path = data.split(b' ')[1].decode('ascii', 'replace') if data.count(b' ') >= 2 else '?'
            log(event='request', method=data.split(b' ')[0].decode('ascii', 'replace'), path=path, src=source, t=round(time.time(), 3))
            answer(client, path)
    except (OSError, ssl.SSLError, IndexError) as exc:
        log(event='error', kind=type(exc).__name__, detail=str(exc)[:160], src=source, t=round(time.time(), 3))


def main():
    name = os.environ.get('PEER_CERT_NAME') or os.environ['PEER_HOST']
    cert, key = '/tmp/peer.crt', '/tmp/peer.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key, '-out', cert, '-subj', '/CN=' + name,
                    '-addext', 'subjectAltName=DNS:' + name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(event='cert', pem=open(cert).read())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 443))
    server.listen(16)
    log(event='listening')
    while True:
        client, source = server.accept()
        log(event='accepted', src=source[0], t=round(time.time(), 3))
        threading.Thread(target=serve, args=(client, context, source[0]), daemon=True).start()


if __name__ == '__main__':
    main()
