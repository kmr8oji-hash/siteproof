"""S2-B diagnostic: ONE A query for the registered monitoring host to the Docker embedded resolver, from the trusted UID.

Not a probe of anything else: the name is read from the registered target file, the resolver is the one the Worker uses.
"""
import json
import socket
import time
from urllib.parse import urlsplit


def main():
    config = json.load(open('/opt/siteproof/src/noxiworks/targets.json', encoding='utf-8'))
    host = urlsplit(next(p for p in config['pages'] if p['target_id'] == 'noxiworks-home')['url']).hostname
    question = b''.join(bytes([len(x)]) + x.encode('ascii') for x in host.split('.')) + b'\x00\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(8)
        started = time.monotonic()
        try:
            s.sendto(b'\x53\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question, ('127.0.0.11', 53))
            data = s.recv(512)
            print(json.dumps({'host': host, 'rcode': data[3] & 15, 'answers': int.from_bytes(data[6:8], 'big'),
                              'ms': round((time.monotonic() - started) * 1000)}))
        except OSError as exc:
            print(json.dumps({'host': host, 'error': type(exc).__name__, 'ms': round((time.monotonic() - started) * 1000)}))


if __name__ == '__main__':
    main()
