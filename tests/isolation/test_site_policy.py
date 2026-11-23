"""S2-A: per-site destination plan. Offline; nothing connects or resolves."""
import unittest
from unittest.mock import patch

from src.isolation import site_policy
from src.isolation.destination import check_authority
from src.isolation.site_policy import (RealSiteAccessDisabled, SiteEntry, SiteNetworkPlan, SitePolicyError,
                                       fixture_policy, normalize_hostname, real_site_policy)


def real(*hosts, enabled=False):
    return SiteNetworkPlan('REAL', (SiteEntry('owner-site', tuple(hosts)),), enabled)


class SitePolicyTests(unittest.TestCase):
    def test_real_site_access_is_disabled_by_default_and_by_flag_alone(self):
        self.assertIs(site_policy.REAL_SITE_ACCESS_ENABLED, False)
        plan = real('www.owner-site.com')
        self.assertIs(plan.enabled, False)
        with self.assertRaises(RealSiteAccessDisabled): real_site_policy(plan)
        # The plan's own flag is not enough; neither is the module constant without the plan's flag.
        with self.assertRaises(RealSiteAccessDisabled): real_site_policy(real('www.owner-site.com', enabled=True))
        with patch.object(site_policy, 'REAL_SITE_ACCESS_ENABLED', True):
            with self.assertRaises(RealSiteAccessDisabled): real_site_policy(plan)
            policy = real_site_policy(real('www.owner-site.com', enabled=True))
        self.assertTrue(check_authority(policy, 'www.owner-site.com', 443).allowed)

    def test_normalization_is_explicit_and_exact(self):
        self.assertEqual(normalize_hostname('WWW.Owner-Site.COM'), 'www.owner-site.com')
        self.assertEqual(normalize_hostname('bücher.example'), 'xn--bcher-kva.example')
        for bad in ('', ' a.example.com', 'a.example.com ', 'a.example.com.', 'localhost', '10.0.0.5', '::1', '[::1]',
                    '169.254.169.254', 'a.com:443', 'https://a.com', 'a.com/path', 'user@a.com', '*.a.com', 'a..com',
                    '-a.com', 'a_b.com', 'a.123', '0x7f.0.0.1', 'a.com\x00', 'a.com,b.com', None, 5, b'a.com'):
            with self.subTest(bad=bad):
                with self.assertRaises(SitePolicyError): normalize_hostname(bad)

    def test_hostname_matching_downstream_is_exact_not_suffix_or_wildcard(self):
        with patch.object(site_policy, 'REAL_SITE_ACCESS_ENABLED', True):
            policy = real_site_policy(real('www.owner-site.com', enabled=True))
        for host in ('owner-site.com', 'evil.www.owner-site.com', 'www.owner-site.com.evil.com', 'wwww.owner-site.com'):
            self.assertFalse(check_authority(policy, host, 443).allowed, host)
        self.assertFalse(check_authority(policy, 'www.owner-site.com', 80).allowed)
        self.assertFalse(check_authority(policy, 'www.owner-site.com', 8443).allowed)

    def test_real_and_fixture_plans_cannot_be_mixed(self):
        for host in ('a.invalid', 'a.test', 'a.example', 'a.local', 'a.internal', 'a.home.arpa', 'a.localhost'):
            with self.subTest(real=host):
                with self.assertRaises(SitePolicyError): real(host)
        with self.assertRaises(SitePolicyError):
            SiteNetworkPlan('FIXTURE', (SiteEntry('f', ('www.owner-site.com',)),))
        plan = SiteNetworkPlan('FIXTURE', (SiteEntry('f', ('fixture.invalid',)),))
        self.assertTrue(check_authority(fixture_policy(plan), 'fixture.invalid', 443).allowed)
        with self.assertRaises(SitePolicyError): real_site_policy(plan)
        with self.assertRaises(SitePolicyError): fixture_policy(real('www.owner-site.com'))

    def test_ports_duplicates_limits_and_types_are_refused(self):
        for kwargs in ({'port': 80}, {'port': 8443}, {'port': True}, {'port': '443'}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(SitePolicyError): SiteEntry('s', ('a.example.com',), **kwargs)
        with self.assertRaises(SitePolicyError): SiteEntry('Bad Id', ('a.example.com',))
        with self.assertRaises(SitePolicyError): SiteEntry('s', ())
        with self.assertRaises(SitePolicyError): SiteEntry('s', ['a.example.com'])
        with self.assertRaises(SitePolicyError): SiteEntry('s', tuple(f'h{n}.example.com' for n in range(65)))
        with self.assertRaises(SitePolicyError): real('a.example.com', 'A.EXAMPLE.COM')
        for bad in ('YES', 1, None):
            with self.assertRaises(SitePolicyError): SiteNetworkPlan('REAL', (SiteEntry('s', ('a.example.com',)),), bad)
        with self.assertRaises(SitePolicyError): SiteNetworkPlan('OTHER', (SiteEntry('s', ('a.example.com',)),))


if __name__ == '__main__':
    unittest.main()
