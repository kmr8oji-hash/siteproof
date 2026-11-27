"""One HTTPS exchange through the owned CONNECT proxy, and the hard end of it. Standard library + the unchanged AWS-B TLS / status-line parts.

connect_through() asks the loopback proxy for host:443 and nothing else; TLS is end to end (the proxy sees host:port only, so the PATH is fixed by this
application code and the signed grant, never by the network boundary). exchange() keeps run_probe's outcomes: certificate / host name failures are an
observed failure of the site, a proxy refusal is not an observation of the site at all.
"""
import socket
import ssl
import threading
import time

from src.aws_b.probe import IncompleteStatusLine, TlsTransport, parse_status_line
from src.core.rules import classify_http_status

MAX_PROXY_HEAD = 4096


class ProxyRefused(Exception):
    """The proxy did not open the tunnel: nothing was sent to the site. (The proxy's own ledger, read by the host, says why.)"""


class Handle:
    def __init__(self, sock):
        self.sock = sock

    def close(self):
        self.sock.close()


class DeadlineTransport:
    """The AWS-B TLS transport with a hard end: socket timeouts bound each read, this bounds their sum."""

    def __init__(self, inner, clock=time.monotonic):
        self.inner, self.clock = inner, clock

    def exchange(self, handle, hostname, path, deadline):
        fired = threading.Event()

        def stop():
            fired.set()
            try:
                handle.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(max(0.0, deadline - self.clock()), stop)
        timer.daemon = True
        timer.start()
        try:
            result = self.inner.exchange(handle, hostname, path, deadline)
        except Exception:
            if fired.is_set():  # the hard end cut the connection: whatever the inner transport made of it, this was a timeout
                raise TimeoutError('probe deadline') from None
            raise
        finally:
            timer.cancel()
        if fired.is_set():  # the cut can also look like a clean end (EOF): a result that arrived with the hard end already fired is never a verdict
            raise TimeoutError('probe deadline')
        return result


def connect_through(proxy_port, hostname, deadline, clock=time.monotonic, make=lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)):
    """-> a socket whose far end is hostname:443 (as the proxy decided), or ProxyRefused."""
    sock = make()
    try:
        sock.settimeout(max(0.05, deadline - clock()))
        sock.connect(('127.0.0.1', proxy_port))
        authority = f'{hostname}:443'.encode('ascii')
        sock.sendall(b'CONNECT ' + authority + b' HTTP/1.1\r\nHost: ' + authority + b'\r\n\r\n')
        head = b''
        while not head.endswith(b'\r\n\r\n'):
            if len(head) >= MAX_PROXY_HEAD or clock() >= deadline:
                raise ProxyRefused('PROXY_REPLY')
            sock.settimeout(max(0.05, deadline - clock()))
            part = sock.recv(1)  # never a byte of the tunnel
            if not part:
                raise ProxyRefused('PROXY_CLOSED')
            head += part
        if not head.startswith(b'HTTP/1.1 200 '):
            raise ProxyRefused('PROXY_REFUSED')
        return sock
    except ProxyRefused:
        sock.close()
        raise
    except OSError as exc:
        sock.close()
        raise ProxyRefused('PROXY_UNREACHABLE:' + type(exc).__name__) from None
    except BaseException:
        sock.close()
        raise


def exchange(hostname, path, proxy_port, timeout, *, transport=None, connect=connect_through, clock=time.monotonic):
    """-> {'outcome', 'reason', 'http_status', 'tls_not_after', 'elapsed_ms'}. One tunnel, one request, no redirect, no retry, status line only."""
    started = clock()
    deadline = started + timeout

    def done(outcome, reason, status=None, not_after=None, **detail):
        return {'outcome': outcome, 'reason': reason, 'http_status': status, 'tls_not_after': not_after, 'elapsed_ms': int((clock() - started) * 1000), **detail}
    try:
        sock = connect(proxy_port, hostname, deadline)
    except ProxyRefused as exc:
        return done('UNKNOWN', str(exc))
    handle = Handle(sock)
    try:
        line, not_after = DeadlineTransport(transport or TlsTransport(), clock).exchange(handle, hostname, path, deadline)
    except ssl.SSLError as exc:  # the kind only (evidence for the host), never part of the verdict
        return done('FAIL', 'TLS_FAILED', tls_error=(type(exc).__name__ + ':' + str(getattr(exc, 'verify_message', None) or getattr(exc, 'reason', None) or ''))[:120])
    except TimeoutError:
        return done('FAIL', 'HTTP_TIMEOUT')
    except OSError:
        return done('FAIL', 'HTTP_IO_ERROR')
    except IncompleteStatusLine:
        return done('UNKNOWN', 'HTTP_INCOMPLETE')
    except Exception:
        return done('UNKNOWN', 'HTTP_EXCHANGE_ERROR')
    finally:
        try:
            handle.close()
        except Exception:
            pass
    status = parse_status_line(line) if type(line) is bytes else None
    if status is None:
        return done('UNKNOWN', 'HTTP_MALFORMED', None, not_after)
    outcome, reason = classify_http_status(status, observation_reliable=True)  # 3xx: UNKNOWN, the Location is never followed
    return done(outcome.value, reason, status, not_after)
