# M2 offline browser runtime

This slice implements software contracts and synthetic execution, not an installed
Linux launcher, Chromium availability check, OS isolation or browser UX acceptance.

The later fixture runtime is implemented separately by `DockerLauncher` and
`tests.runtime.validate` with the dedicated files under `runtime/docker`. It
performs real preflight before Chromium and preserves measured evidence. The
default `UnconfiguredIsolation` still refuses general real-browser execution;
the fixture harness does not authorize real sites or attest capture profiles.

## Trusted startup

Use the existing explicitly initialized S1/Baseline/M1 SQLite database and evidence
root. `storage.runtime.initialize` adds only `runtime_*` tables and append-only
triggers, in one transaction. It refuses an existing/partial extension. GET never
initializes tables or migrates databases. Do not call initialization against a real
user database without the separate environment approval.

Construct `EvidenceFinalizer -> EvidenceBridge -> TrustedWorker -> RuntimeService`
on that fixed DB/root. `submit()` pins M1 site/page revisions and both stored
Desktop/Mobile profiles, creating at most ten immutable S1 child jobs. Bindings
declare profiles; hashes prove integrity, never capture provenance. A submission
failure can leave accepted, unbound S1 jobs; no automatic repair/retry is performed.

`run(batch, channel_factory, proxy_lease, resources, cancel=event)` claims a batch
once. All children share one CONNECT transport/QuotaSession, IPC output ceiling
and job deadline. `channel_factory(request, remaining_seconds)` returns a bounded
binary source, fixed producer reason and producer-cleanup confirmation. A real
factory MUST supervise startup/death/IPC in a killable isolated process. It must
not call the producer synchronously on the trusted host. Synthetic tests use
`capture()` with a fake driver and `MemoryChannel`; these are labelled
`OFFLINE_FIXTURE_UNATTESTED` in the current service. Real execution provenance
needs a separately integrated launcher before this source label can change.

The untrusted producer receives only URL, page/profile and baseline identifiers;
it receives no DB, evidence root or writable trusted-storage mount. Its capped
v0.1 frame encoder emits self-reported HTTP/LOAD/CAPTURE and PNG. The trusted
Bridge independently validates frames, PNG, hashes, context, records and S1
write-once finalization. Partial/crashed producer bytes are not adopted as complete
evidence. S1 storage failures retain orphans for the existing read-only recovery
planner; nothing is deleted, repaired or automatically retried.

`PlaywrightDriver` maps the stored profile to context options and commit/load/PNG
operations. A trusted isolated launcher must implement `open_browser(LaunchPlan)`
and `close() -> bool`. LaunchPlan fixes the owned loopback CONNECT proxy, sandbox
enabled, QUIC disabled, non-proxied WebRTC UDP disabled and service workers blocked.
These options do NOT enforce OS egress isolation. `UnconfiguredIsolation` refuses
every real launch. There is no host launch, dependency install or no-sandbox fallback.

## Required real environment (NOT VERIFIED)

Separately provision a nonroot sandboxed Chromium/Playwright execution environment
and isolated trusted Worker. Enforce all `ENFORCEMENT_REQUIREMENTS`, including
direct DNS/TCP/UDP/IPv6 denial, management/metadata denial, resource caps, no trusted
storage mount and process-group termination. The existing proxy binds loopback;
cross-namespace reachability must be designed/measured without permitting bypass.
Browser/proxy/Worker identities, namespace wiring and sandbox enforcement cannot
be inferred from a LaunchPlan or asserted by a boolean fixture flag.

Stage deadlines/cancel are cooperative inside synchronous driver calls. Pipe
waiting is bounded with a supervised reader, but blocked read/close and OS resolver
calls cannot be forcibly interrupted in Python. Cleanup=False means unconfirmed,
prevents further producers and must be resolved by the external launcher. S1 can
have committed evidence before pipe-close uncertainty; execution status does not
certify resource cleanup. Proxy stop(False) is also explicitly recorded.

## M1 local read view

Supply `runtime=service, offline=workspace` to the existing paired local HOME.
GET `/api/baselines/_m1/runtime` uses the existing Host/Origin/cookie guards, fixed
read-only SQLite connections and bounded history. There is NO HTTP browser-start
route. The local-only panel shows execution, reasons and verified S1 references;
it does not import these captures into M1 synthetic fixtures or trusted comparison.
APPROVED is a human baseline decision; PROFILE_UNATTESTED/quality UNKNOWN remain.

M4 adds an explicit opt-in `comparison=ComparisonService(...)` integration. See
`../comparison/INTERFACE.md` for additive initialization, pre-capture provenance,
pending candidate/human approval, fixed baseline versions, pixel policy and local
comparison/history routes. Default M2/M3 behavior remains unverified. The existing
fixture launcher supplies only partial image observations; it is not a complete
production profile trust source, and old M3 evidence is never reauthenticated.

M1 and public HOME/Compare assets, S1 finalizer/schema, S2 trust adapter and Baseline
approval contracts remain unchanged. Browser availability, real UX, OS isolation,
formal T01–T21 and real-site operation require separate gates.
