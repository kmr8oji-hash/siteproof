"""Capture-time provenance, separate from v1 declaration hashes.

Only a trusted starter may supply an observer and key. The observer must obtain
each value independently from the launcher/worker, never from Browser frames,
HTTP input, current UI settings or historical M3 metadata. Signing is integrity
protection, not measurement. No production observer is configured by default.
"""
import hashlib
import hmac
import json

from src.comparison.profile import is_clean_text, is_sha256_hex


EXTRA_FIELDS = ('os', 'architecture', 'browser_version', 'playwright_version',
                'image_digest', 'fonts_digest', 'is_mobile', 'animations',
                'wait_until', 'stability_policy')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf8')


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def values(settings):
    return {name: item.get('value') for name, item in settings.items()}


def unverified_settings(profile):
    return {name: {'value': None, 'source': None}
            for name in (*profile.attributes, *EXTRA_FIELDS)}


def complete(profile, settings):
    expected = set(profile.attributes) | set(EXTRA_FIELDS)
    if type(settings) is not dict or set(settings) != expected:
        return False
    for name, item in settings.items():
        if (type(item) is not dict or set(item) != {'value', 'source'}
                or not is_clean_text(item['source'])
                or not item['source'].startswith(('launcher:', 'worker:'))):
            return False
        value = item['value']
        if name in profile.attributes:
            if type(value) is not type(profile.attributes[name]) or value != profile.attributes[name]:
                return False
        elif name == 'is_mobile':
            if type(value) is not bool:
                return False
        elif name in ('image_digest', 'fonts_digest'):
            if not is_sha256_hex(value):
                return False
        elif not is_clean_text(value):
            return False
    return True


def context_fingerprint(profile, settings):
    return fingerprint({'schema': 'siteproof.capture-context.m4.v1',
                        'capture_fingerprint': profile.fingerprint,
                        'conditions': values(settings)})


class TrustedProfileAuthority:
    """In-process capability; never constructed or configured by an HTTP request.

    OFFLINE_TEST receipts can validate software fixtures only. LOCAL_MEASURED
    requires an independently reviewed trusted observer; this module provides no
    browser-self-report or boolean 'trusted' adapter. The key stays outside the
    browser, SQLite, evidence files and HTTP. Reopening needs the same trusted key.
    """
    def __init__(self, key, observer, *, domain):
        if type(key) is not bytes or len(key) < 32 or not callable(observer):
            raise ValueError('trusted key and observer required')
        if domain not in ('OFFLINE_TEST', 'LOCAL_MEASURED'):
            raise ValueError('explicit trust domain required')
        self._key, self._observer, self.domain = key, observer, domain
        self.key_id = hashlib.sha256(key).hexdigest()

    def observe(self, profile, phase, job_id=None):
        # One JSON snapshot; unsupported/missing fields remain unverified.
        raw = self._observer(profile, phase, job_id)
        settings = unverified_settings(profile)
        if type(raw) is dict:
            for name in settings:
                if name in raw:
                    settings[name] = raw[name]
        return json.loads(canonical(settings))

    def sign(self, body):
        if self._key is None:
            raise ValueError('profile signing key unavailable')
        payload = {'body': body, 'domain': self.domain, 'key_id': self.key_id}
        return {**payload, 'signature': hmac.new(self._key, canonical(payload), hashlib.sha256).hexdigest()}

    def stability(self, profile, job_id):
        raw = self._observer(profile, 'stability', job_id)
        return json.loads(canonical(raw.get('stability_result') if type(raw) is dict else None))

    def verifies(self, envelope):
        if self._key is None:
            return False
        if type(envelope) is not dict or set(envelope) != {'body', 'domain', 'key_id', 'signature'}:
            return False
        if envelope['domain'] != self.domain or envelope['key_id'] != self.key_id:
            return False
        signature = envelope['signature']
        return (is_sha256_hex(signature) and
                hmac.compare_digest(signature, self.sign(envelope['body'])['signature']))

    def accepts_source(self, source):
        return ((self.domain == 'OFFLINE_TEST' and source == 'OFFLINE_FIXTURE_UNATTESTED')
                or (self.domain == 'LOCAL_MEASURED' and source == 'REAL_CHROMIUM_FIXTURE_UNATTESTED'))

    def destroy(self):
        """Revoke this capability; Python immutable bytes are not securely erasable."""
        self._key = None
