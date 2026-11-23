"""Temporary Function URL handler. No management HTTP API and no outbound I/O."""
from datetime import datetime, timezone
import os

BODY = 'SiteProof temporary HTTP test fixture.\n'


def handler(event, context):
    request = event.get('requestContext', {}) if type(event) is dict else {}
    http = request.get('http', {}) if type(request) is dict else {}
    method = http.get('method') if type(http) is dict else None
    headers = {'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store',
               'x-content-type-options': 'nosniff'}
    if type(event) is not dict or event.get('version') != '2.0' or method != 'GET':
        return {'statusCode': 405, 'headers': {**headers, 'allow': 'GET'}, 'body': BODY}
    if event.get('rawPath') != '/' or event.get('rawQueryString', ''):
        return {'statusCode': 404, 'headers': headers, 'body': BODY}
    try:
        raw = os.environ.get('ABSOLUTE_END_AT', '')
        end = datetime.strptime(raw, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) >= end:
            return {'statusCode': 410, 'headers': headers, 'body': BODY}
        status = {'200': 200, '503': 503}[os.environ.get('FIXTURE_HTTP_STATUS')]
    except (ValueError, KeyError, TypeError):
        status = 503  # Invalid configuration fails closed without disclosing it.
    return {'statusCode': status, 'headers': headers, 'body': BODY}
