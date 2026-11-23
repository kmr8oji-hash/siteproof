"""Per-site destination plan. Real-site access is OFF by default and nothing here connects anywhere.

A plan names, per site, the exact hostnames the isolated browser may reach (HTTPS, port 443).
It only produces a `DestinationPolicy`; DNS answer validation, address classification, IP pinning
and peer verification stay in destination/connect_dns/connector, and OS-level isolation stays
outside this module. The application allowlist is therefore never the only boundary.

Real and fixture plans are kept apart: a REAL plan can never name a reserved or internal suffix, and a
FIXTURE plan can only name `.invalid`. Enabling real sites needs BOTH `plan.enabled` and the module
constant below, which is changed only by a reviewed code change (S2-B), never by configuration,
environment variable or request data.
"""
from dataclasses import dataclass
import ipaddress
import re

from .destination import AllowedDestination, DestinationPolicy


REAL_SITE_ACCESS_ENABLED = False

MAX_HOSTS = 64
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
FIXTURE_SUFFIX = '.invalid'
RESERVED_SUFFIXES = ('.invalid', '.test', '.example', '.localhost', '.local', '.internal', '.localdomain',
                     '.home.arpa', '.lan', '.corp', '.intranet', '.onion', '.arpa')


class SitePolicyError(ValueError):
    pass


class RealSiteAccessDisabled(SitePolicyError):
    pass


def normalize_hostname(value):
    """Exact, explicit normalization: ASCII lowercase or IDNA (punycode). Never repairs input."""
    if type(value) is not str or not value or len(value) > 253 or value != value.strip():
        raise SitePolicyError('hostname required')
    if any(c in value for c in ('/', ':', '@', '?', '#', '*', '[', ']', '\\', '%', ' ', '\x00', ',')):
        raise SitePolicyError('bare hostname only: no scheme, port, path, credentials, wildcard or address literal')
    try:
        ascii_name = value.lower() if value.isascii() else value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise SitePolicyError('invalid internationalized hostname') from None
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        pass
    else:
        raise SitePolicyError('IP literals are never allowlisted')
    labels = ascii_name.split('.')
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        raise SitePolicyError('invalid hostname (trailing dot, single label, empty or numeric label refused)')
    return ascii_name


@dataclass(frozen=True)
class SiteEntry:
    site_id: str
    hostnames: tuple
    port: int = 443

    def __post_init__(self):
        if (type(self.site_id) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}', self.site_id)
                or type(self.hostnames) is not tuple or not self.hostnames or len(self.hostnames) > MAX_HOSTS
                or self.port != 443 or type(self.port) is not int):
            raise SitePolicyError('site id, 1..64 hostnames and HTTPS port 443 required')
        object.__setattr__(self, 'hostnames', tuple(normalize_hostname(h) for h in self.hostnames))


@dataclass(frozen=True)
class SiteNetworkPlan:
    kind: str  # 'REAL' or 'FIXTURE'
    sites: tuple
    enabled: bool = False  # Off unless explicitly turned on.

    def __post_init__(self):
        if (self.kind not in ('REAL', 'FIXTURE') or type(self.sites) is not tuple or not self.sites
                or any(type(s) is not SiteEntry for s in self.sites) or type(self.enabled) is not bool):
            raise SitePolicyError('explicit kind, site entries and boolean enabled flag required')
        hosts = [h for s in self.sites for h in s.hostnames]
        if len(set(hosts)) != len(hosts) or len(hosts) > MAX_HOSTS:
            raise SitePolicyError('duplicate or too many hostnames')
        for host in hosts:
            reserved = host.endswith(RESERVED_SUFFIXES)
            if self.kind == 'REAL' and reserved:
                raise SitePolicyError('a REAL plan cannot name a reserved or internal suffix')
            if self.kind == 'FIXTURE' and not host.endswith(FIXTURE_SUFFIX):
                raise SitePolicyError('a FIXTURE plan may only name .invalid hostnames')

    def destinations(self):
        return tuple(AllowedDestination(h, s.port) for s in self.sites for h in s.hostnames)


def real_site_policy(plan):
    """The only way a REAL plan becomes a policy. Disabled by default; S2-A never enables it."""
    if type(plan) is not SiteNetworkPlan or plan.kind != 'REAL':
        raise SitePolicyError('REAL plan required')
    if REAL_SITE_ACCESS_ENABLED is not True or plan.enabled is not True:
        raise RealSiteAccessDisabled('real-site access is disabled')
    return DestinationPolicy(plan.destinations())


def fixture_policy(plan):
    """Test-only policy for offline fixtures; cannot be built from, or mixed with, a REAL plan."""
    if type(plan) is not SiteNetworkPlan or plan.kind != 'FIXTURE':
        raise SitePolicyError('FIXTURE plan required')
    return DestinationPolicy(plan.destinations())
