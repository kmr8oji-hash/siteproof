"""Browser launch contract, not an implementation or attestation of OS isolation.

An isolated launcher must implement open_browser/close outside this module. There
is deliberately no host Playwright launch, executable discovery or sandbox fallback.
The loopback proxy must be reachable inside that launcher's network boundary;
cross-namespace plumbing and every enforcement requirement below need measurement.
"""
from dataclasses import dataclass
import math
import time
from urllib.parse import urlsplit

from src.isolation.destination import check_authority
from src.isolation.transport import ConnectTransport
from src.runtime.request_audit import RequestAuditCollector, unavailable as audit_unavailable


ENFORCEMENT_REQUIREMENTS = frozenset({
    'nonroot', 'chromium_sandbox', 'read_only_root', 'no_worker_storage_mount',
    'separate_worker_identity', 'deny_direct_tcp', 'deny_direct_dns', 'deny_udp',
    'deny_ipv6', 'deny_quic', 'deny_host_management_metadata', 'proxy_only_egress',
    'cpu_memory_pid_fd_disk_limits', 'killable_process_group',
})


class RuntimeRefused(ValueError):
    pass


# Only the page's own browser context is routed to the audited proxy (see PlaywrightDriver.start).
# Everything the browser does for itself (sign-in, updater, ...) uses this browser-wide default route,
# which goes nowhere: it never reaches the audited proxy and, under the OS boundary, is dropped and
# counted there. The split is by route, never by host name.
UNREACHABLE_BROWSER_PROXY = 'http://127.0.0.1:1'

# Chromium takes the LAST --disable-features switch, so Playwright 1.64.1's own default list (pinned in
# runtime/docker) is repeated here and only PreconnectToSearch is added: the search-provider preconnect
# is browser-initiated (netlog is_preconnect) yet arrives through the page context. The E2E checks that
# this list still covers Playwright's installed defaults.
DISABLED_FEATURES = (
    'AvoidUnnecessaryBeforeUnloadCheckSync', 'DestroyProfileOnBrowserClose', 'DialMediaRouteProvider',
    'GlobalMediaControls', 'HttpsUpgrades', 'LensOverlay', 'MediaRouter', 'PaintHolding',
    'ThirdPartyStoragePartitioning', 'BlockOriginHeaderModificationOnRedirect', 'AvoidCorsURLLoaderRestartOnRedirect',
    'Translate', 'AutoDeElevate', 'OptimizationHints', 'NetworkTimeServiceQuerying', 'AimEnabled',
    'msForceBrowserSignIn', 'msEdgeUpdateLaunchServicesPreferredVersion', 'PreconnectToSearch')


@dataclass(frozen=True)
class ResourceLimits:
    seconds: float
    stage_seconds: float
    output_bytes: int
    memory_bytes: int
    processes: int
    file_descriptors: int
    cpu_seconds: int
    temporary_bytes: int

    def __post_init__(self):
        for value in vars(self).values():
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError('positive finite resource limits required')
        for name in ('output_bytes', 'memory_bytes', 'processes', 'file_descriptors',
                     'cpu_seconds', 'temporary_bytes'):
            if type(getattr(self, name)) is not int:
                raise ValueError('integer resource limit required')


class ProxyLease:
    """One owned transport and one QuotaSession for the whole multi-page batch."""
    def __init__(self, transport):
        if not isinstance(transport, ConnectTransport):
            raise RuntimeRefused('OWNED_CONNECT_TRANSPORT_REQUIRED')
        self.transport = transport
        self.ledger = transport.ledger  # Trusted CONNECT record; the browser's own reports are never used.

    def check(self, url=None):
        t = self.transport
        # Observe the actual owner, never accept an arbitrary proxy URL/config.
        if (t._listener is None or t._listener.fileno() < 0 or t._halted()
                or t._acceptor is None or not t._acceptor.is_alive()):
            raise RuntimeRefused('PROXY_UNAVAILABLE')
        host, port = t.address
        if host != '127.0.0.1' or type(port) is not int or not 0 < port < 65536:
            raise RuntimeRefused('PROXY_NOT_LOOPBACK')
        if url is not None:
            try:
                u = urlsplit(url)
                if (u.scheme != 'https' or not u.hostname or u.username is not None
                        or u.password is not None or u.fragment or
                        not check_authority(t.policy, u.hostname, u.port or 443).allowed):
                    raise ValueError()
            except (ValueError, AttributeError):
                raise RuntimeRefused('DESTINATION_REFUSED') from None
        return f'http://127.0.0.1:{port}'

    def stop(self):
        # False means cleanup is NOT confirmed (including blocking OS resolver).
        return self.transport.stop()


@dataclass(frozen=True)
class LaunchPlan:
    proxy: str
    resources: ResourceLimits
    requirements: frozenset = ENFORCEMENT_REQUIREMENTS

    def __post_init__(self):
        u = urlsplit(self.proxy)
        if (u.scheme != 'http' or u.hostname != '127.0.0.1' or not u.port
                or self.proxy != f'http://127.0.0.1:{u.port}'
                or self.requirements != ENFORCEMENT_REQUIREMENTS
                or type(self.resources) is not ResourceLimits):
            raise RuntimeRefused('INVALID_LAUNCH_PLAN')

    def playwright_options(self):
        return {'headless': True, 'chromium_sandbox': True,
                'proxy': {'server': UNREACHABLE_BROWSER_PROXY, 'bypass': '<-loopback>'},
                'args': ['--disable-quic', '--disable-background-networking',
                         '--disable-features=' + ','.join(DISABLED_FEATURES),
                         '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']}


class UnconfiguredIsolation:
    """Fail closed until a separately approved, measured runtime is installed."""
    def open_browser(self, plan):
        raise RuntimeRefused('ISOLATION_NOT_VERIFIED')


class PlaywrightDriver:
    """Injected isolated Playwright Browser; never launches on the trusted host.

    Launcher owns process-group termination, resource enforcement and shutdown.
    Playwright timeout/close alone cannot forcibly stop arbitrary blocking calls.
    Redirect/subresource policy is enforced by the same CONNECT proxy + OS boundary.
    """
    def __init__(self, launcher, lease, limits, *, is_mobile=None):
        self.launcher, self.lease, self.limits = launcher, lease, limits
        self.browser = self.context = self.page = None
        self.audit = self.final_audit = None  # Page-context request audit; see request_audit.py (untrusted, downgrade-only).
        if is_mobile is not None and type(is_mobile) is not bool:
            raise ValueError('explicit is_mobile boolean required')
        self.is_mobile = is_mobile

    def start(self, profile):
        plan = LaunchPlan(self.lease.check(), self.limits)
        self.browser = self.launcher.open_browser(plan)
        a = profile.attributes
        self.context = self.browser.new_context(
            viewport={'width': a['viewport_width'], 'height': a['viewport_height']},
            device_scale_factor=a['device_scale_factor'], color_scheme=a['color_scheme'],
            locale=a['locale'], timezone_id=a['timezone'], user_agent=a['user_agent'],
            reduced_motion='reduce' if a['reduced_motion'] else 'no-preference',
            service_workers='block', accept_downloads=False, ignore_https_errors=False,
            proxy={'server': plan.proxy, 'bypass': '<-loopback>'},
            **({'is_mobile': self.is_mobile} if self.is_mobile is not None else {}))
        # Listening starts before the first page exists, so no request of this context can precede it.
        self.audit = RequestAuditCollector()
        self.audit.attach(self.context)
        self.page = self.context.new_page()

    def http(self, url, seconds):
        self.lease.check(url)
        response = self._call(self.page.goto,url,wait_until='commit',timeout=seconds * 1000)
        if response is None:
            raise RuntimeRefused('HTTP_RESPONSE_MISSING')
        return response.status

    def load(self, seconds):
        self.lease.check()
        self._call(self.page.wait_for_load_state,'load',timeout=seconds * 1000)

    def capture(self, profile, seconds):
        self.lease.check()
        return self._call(self.page.screenshot,type='png',full_page=profile.attributes['full_page'],
                          animations='disabled',timeout=seconds * 1000)

    last_timeout=None  # What the last Playwright timeout was (operation, its limit, time spent): evidence only, never a decision input.

    @staticmethod
    def _call(operation,*args,**kwargs):
        started=time.monotonic()
        try:
            return operation(*args,**kwargs)
        except Exception as exc:
            # Optional dependency remains optional for offline tests. Playwright's
            # TimeoutError is not Python's TimeoutError; no raw exception escapes.
            if type(exc).__name__=='TimeoutError' and type(exc).__module__.startswith('playwright.'):
                PlaywrightDriver.last_timeout={'operation':getattr(operation,'__name__','?'),'limit_ms':kwargs.get('timeout'),
                                               'elapsed_ms':int((time.monotonic()-started)*1000)}
                raise TimeoutError() from None
            raise

    def request_audit(self):
        """The finalized audit, or an explicit UNAVAILABLE marker. Never an empty-looking one."""
        return self.final_audit or audit_unavailable('NOT_FINALIZED' if self.audit is not None else 'MONITOR_NOT_STARTED')

    def _finalize_audit(self):
        if self.audit is None or self.final_audit is not None:
            return
        try:
            if self.page is not None:
                self.page.evaluate('0')  # Round trip: every event queued before this point has been delivered.
            self.final_audit = self.audit.summary(final=True)
        except Exception:
            self.final_audit = audit_unavailable('FINALIZE_FAILED')

    def close(self):
        self._finalize_audit()  # While the context is still open: the end of monitoring is explicit.
        # Launcher must acknowledge process/pipe termination; False is not success.
        return self.launcher.close() if self.browser is not None else True
