"""S2-B-HARDEN fixture peer: a REAL, reachable TCP/443 listener on an address of the isolated (--internal) fixture network.

It stands in for "a public IP that is up": if the OS rules ever let a connection through, this process accepts it and logs
it, which is independent evidence (the host reads the container log) that does not rely on the connecting side's report.
Sends `PEER-<name>` on accept and keeps the connection up to 2 s. Logs one JSON line per accepted connection.
"""
import json
import os
import socket
import threading
import time


def serve(client, name):
    """Like a real server: greet, then hold the connection for a moment (a client that closes first is fine)."""
    try:
        client.sendall(('PEER-' + name + '\n').encode())
        client.settimeout(2)
        try:
            client.recv(1)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        client.close()


def main():
    name = os.environ['PEER_NAME']
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 443))
    server.listen(32)
    print(json.dumps({'peer': name, 'event': 'listening', 'port': 443}), flush=True)
    while True:
        client, source = server.accept()
        print(json.dumps({'peer': name, 'event': 'accepted', 'src': source[0], 't': round(time.time(), 3)}), flush=True)
        threading.Thread(target=serve, args=(client, name), daemon=True).start()


if __name__ == '__main__':
    main()
