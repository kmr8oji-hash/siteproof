"""Pure predicates shared by the real-site run and its offline rehearsal (no I/O, no heavy imports)."""
import re


def head_is_as_expected(head):
    """The pre-capture HEAD rule of S3-1: exactly 200, no Location, TLS verified. A 307 (S3-1: /about.html -> /about) or anything else STOPs."""
    tls = head.get('tls') or {}
    headers = head.get('http_headers') or {}
    return (str(head.get('status', '')).startswith('HTTP/1.1 200') and tls.get('result') == 'OK'
            and re.match(r'HTTP/1\.[01] 200\b', str(head.get('http_status', ''))) is not None
            and not head.get('redirect') and not headers.get('location'))
