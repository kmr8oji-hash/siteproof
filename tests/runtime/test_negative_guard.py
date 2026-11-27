"""S3-1-PREFLIGHT: negative browser tests can never name the registered real host on an allowed port. Pure/offline."""
import unittest

from tests.runtime.negative_guard import NegativeTestRefused, proxied_negatives, refuse_registered_host

HOST = 'tokyo-trouble-navi-review-ai-off-2026.kmr8oji.workers.dev'


class NegativeGuardTests(unittest.TestCase):
    def test_default_proxied_negatives_never_reach_the_registered_host(self):
        urls = proxied_negatives({'host': HOST})
        self.assertIn('plain_http_unregistered', urls)
        self.assertEqual(urls['plain_http_unregistered'], 'http://plain-s2b.invalid/')
        self.assertNotIn('plain_http_registered_host', urls)
        self.assertTrue(refuse_registered_host(urls, HOST))
        for url in urls.values():  # Only a different host, or the registered host on a non-allowed port, may remain.
            self.assertTrue(HOST not in url.split('/')[2] or url.split('/')[2] != HOST or url.endswith(':8443/'), url)

    def test_registered_host_on_allowed_ports_is_refused_before_any_send_for_every_scheme_and_spelling(self):
        for url in ('http://' + HOST + '/', 'https://' + HOST + '/', 'http://' + HOST + ':80/', 'https://' + HOST + ':443/x', 'HTTP://' + HOST.upper() + '/',
                    'http://' + HOST + './', 'http://user@' + HOST + '/', 'https://' + HOST):
            with self.assertRaises(NegativeTestRefused, msg=url):
                refuse_registered_host({'x': url}, HOST)
            with self.assertRaises(NegativeTestRefused, msg=url):
                proxied_negatives({'host': HOST, 'extra_proxied': {'x': url}})

    def test_other_hosts_and_non_allowed_ports_remain_testable(self):
        for url in ('http://plain-s2b.invalid/', 'https://www.' + HOST + '/', 'https://cdn.' + HOST + '/', 'https://' + HOST + ':8443/', 'https://192.0.2.1/'):
            self.assertTrue(refuse_registered_host({'x': url}, HOST), url)

    def test_unparseable_url_is_refused(self):
        with self.assertRaises(NegativeTestRefused):
            refuse_registered_host({'x': 'http://host:notaport/'}, HOST)

    def test_skip_cannot_remove_the_guard(self):
        with self.assertRaises(NegativeTestRefused):
            proxied_negatives({'host': HOST, 'skip_proxied': ['plain_http_unregistered'], 'extra_proxied': {'x': 'http://' + HOST + '/'}})


if __name__ == '__main__':
    unittest.main()
