# M5 / R1 safety handoff — 2026-11-06 JST

Historical handoff: **RED hold, subsequently superseded by Commander RESUME-01.**
Current continuation results and limitations: [M5_VALIDATION.md](M5_VALIDATION.md).
The text below preserves the facts at the original handoff; it is not the current execution status.
No M5 commit, stage, push, reset, stash or merge has been performed.
HEAD remains `a0e7c0eb5b56b814ce0d6bd7bd4649d1afd05ed4` on `main`; index is empty.
The current authorized implementation/test changes are preserved in the worktree.

R1 arrived while the original authorized M5 execution was already in progress.
Do not start a second M5 task or discard these changes. No agent was delegated.

## RED event and current safety

The first source-layer build used BuildKit with `--pull=false --network=none`.
BuildKit nevertheless attempted registry metadata resolution for the already
local base image. Registry authorization rejected it; no package/image download
succeeded. Evidence: `.local/m5-build-02/offline-build.log`.
`--network=none` applies to RUN steps and is insufficient to block BuildKit's
metadata resolver. This external lookup was not authorized. Under R1 it requires
safety disposition before any further build/browser retry.

Subsequent builds used the classic local builder, `DOCKER_BUILDKIT=0`, the present
immutable IMAGE ID in FROM, `--pull=false --network=none --force-rm=true`, and COPY
only. No RUN, package install, registry metadata resolver, build dependency
download or host networking/firewall modification was used on that path.
The most recently tested local image is
`sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8`.
Its allowlisted source hashes are in `.local/m5-build-07/build-inputs.json`.

After receiving R1, additional implementation, builds and browser launches were
stopped. Read-only safety checks confirmed that all SiteProof test containers
from runs 01/02/03 were stopped, archived and non-forcibly removed (11 per run).
Only the same four pre-existing other-project containers remain, all exited;
their IDs/states are unchanged. Dedicated networks, volumes and images are
retained, not pruned. There was no observed Browser isolation leak or forbidden
canary reception. Per-run cleanup reports are preserved outside Docker.

## Implemented so far

- Trusted Worker independently measures Linux/platform/architecture, installed
  Playwright, Chromium binary version/hash, pinned image ID and available system
  font inventory. Configured renderer conditions and browser self reports are
  kept separate; missing mandatory authenticity stays PROFILE_UNATTESTED.
- Memory-only random fixture signing key, no key file/env/argv/browser transport;
  plan/receipt binding reused. Tampered plans and cross-job replay are rejected.
  Revocation events record logical capability destruction; physical Python memory
  erasure is explicitly not claimed. Source test-key constants were replaced by
  per-process random keys. Signed SQLite plans/receipts record key usage.
- An explicit trusted-startup-only unattested preview option computes PNG metrics
  and a diff while retaining quality UNKNOWN. No UNATTESTED -> PASS/CHANGED path
  was added. Existing default remains preview-disabled. Pixel cache reuse follows
  fresh source/approval/policy/provenance validation and never caches a verdict.
- Explicit Mobile context instruction; it is recorded as CONFIGURED_ONLY, not
  independently authenticated isMobile.
- Existing paired local UI/approval is reused. A trusted-only unused pairing-code
  renewal revokes the old code, issues a fresh 60s code and never extends the
  session or renews a consumed code. There is no renewal HTTP route.
- Source-only local image build, controlled HTTPS fixture, existing M2 preflight
  and Chromium negative probes, reusable bounded capture helper, bounded UI
  screenshot chunks, selective evidence export and existing cleanup().

## Observed results and preserved evidence

All new-namespace preflights passed: positive canary controls worked; direct
TCP/DNS/UDP/IPv6 and host/LAN/metadata-model reception deltas were zero; proxy stop
failed closed. Real Chromium negative tests passed with nonroot, zero capabilities,
NoNewPrivs/seccomp/cgroup observations and Chromium sandbox diagnostics.

M2/M3 prior evidence volumes were read-only mounted and observed without replaying
or authenticating their captures. Original DB hashes were identical across the
reads: M2 `cb658626b0c333db88105787826b7ac438be5857f81fbbb1d2e04374b4ddc396`;
M3 `bacdb64e9203432387cb3f9a631e65b9df5a7a39acda16178e136e1e7237769f`.

Run 02 completed the following Desktop/Mobile real Chromium scenarios before a
final UI fixture failure: initial S1/candidate creation, real UI explicit approval,
same-image zero diff, changed-image nonzero diff, baseline v1 pinned despite later
v2 approval, profile mismatch UNKNOWN/no diff, key/receipt unavailability UNKNOWN,
clone-only manifest/PNG corruption rejection, HTTP timeout -> TIMED_OUT/no adopted
evidence, deliberate producer exit 7 -> FAILED_EXECUTION/no adoption. Both image
comparison cases remained **unattested preview / quality UNKNOWN**.

Run 02 also exercised real paired UI cookies, CSRF refusal, keyboard pairing,
explicit approval/history and loaded all three baseline/current/diff PNGs. It did
not complete error/missing-image/session-expiry checks. Viewport screenshots were
visually read; no personal USER UX acceptance is asserted.

Primary artifacts:

- `.local/m5-run-02/*-result.json`, `chromium-network.json`, `preflight.json`
- `.local/m5-run-02/s1/` — S1 DB, original capture evidence, observer/key events
- `.local/m5-run-02/negative-evidence/` — deliberately corrupted disposable clones
- `.local/m5-run-02/ui-desktop.png`, `ui-mobile.png`
- `.local/m5-run-03/validation-result.json`, `cleanup.json`, `initial-result.json`
- `.local/m5-run-0{1,2,3}/other-containers-before.json` and `other-containers-after.json`

No signing key was exported; `/evidence/private` TLS keys were excluded. Named
volumes are retained. Existing user DB, M3 original evidence, Obsidian and public
CloudFront/web/infra assets were not modified.

## Test and UI failure status

Completed offline limited groups observed in this M5 session:

- 39 PASS: M5 profile/key/preview/sink tests + lifecycle/runtime contracts.
- 26 PASS: M4 comparison acceptance + M5 profile/key/preview tests.
- 50 PASS: real JS/mock-DOM UI comparison/runtime/image checks.
- 28 PASS: pairing renewal + existing approval/local UI checks.

These groups overlap; do not sum them as distinct tests. Two additional regression
processes were started, but their final tool-session output was unavailable after
the steered R1 update; do not report them as PASS. M4's recorded 383 PASS remain
historical evidence and were not all rerun.

Real harness acceptance is **FAIL / incomplete**, not PASS:

1. Run 01: UI screenshot JSON exceeded the existing 512 KiB control-line cap.
   Fixed by bounded 32 KiB screenshot chunks, without increasing the cap.
2. Run 02: final missing-image check searched for a newly stored result without
   refreshing history. Added an explicit refresh/wait and improved screenshot
   scroll position.
3. Run 03: a TimeoutError occurred during the initial real UI approval phase,
   which had passed in runs 01/02. Its exact substep is not diagnosed. No more
   trials should be launched until Commander disposition under R1. Add only safe
   stage diagnostics if approved; do not expose raw Playwright form exceptions,
   pairing codes or cookies.

The product tolerance is still not adopted. The fixture explicitly uses a zero
changed-pixel threshold for its deterministic static page. Full renderer/profile
authenticity, long-lived production key custody, final real UI acceptance and
USER personal UX remain UNKNOWN / NOT RUN.

## Commander decision

Recommended: review the registry-lookup incident and the verified offline-only
replacement path, then permit a narrowly scoped continuation to diagnose the UI
approval wait and finish missing/session checks. Maintain PROFILE_UNATTESTED and
quality UNKNOWN for unverifiable conditions. No new attestation architecture or
product threshold decision is required to preserve this safe status.

Alternative: retain the worktree/evidence and close M5 incomplete, without commit.
Do not commit until the R1 completion/conditional Git gate is actually satisfied.

Maintained gates: formal T01–T21 UNKNOWN; AWS Worker Pilot NO-GO; v0.7 NOT ADOPTED /
NOT FROZEN; C-02 DEFERRED / OPEN; Search Fabric existing gates unchanged.
