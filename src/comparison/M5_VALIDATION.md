# M5 local Chromium / profile / UI validation — 2026-11-06

Disposition: **controlled local technical acceptance complete** using retained
capture evidence plus narrowly resumed UI trials. This does not authenticate all
renderer conditions, adopt a production tolerance, or close USER UX / formal gates.
Every real capture comparison remains **PROFILE_UNATTESTED / quality UNKNOWN**.
Historical failed runs remain failed; their useful observations are reused only
where independently recorded. No overall PASS is assigned to runs 01/02/03.

## Safety disposition and local-only continuation

Commander RESUME-01 superseded the historical RED hold in `M5_HANDOFF.md`.
The BuildKit log `.local/m5-build-02/offline-build.log` identifies the initiator
and target: FROM resolution requested metadata for
`docker.io/library/siteproof-m2-runtime@sha256:dacff418323c87551f51508e54740642514dffd1030224887424dc840cf781b8`.
Registry authorization returned `insufficient_scope` / pull access denied. The log
contains no successful layer/package download. This unauthorized lookup occurred;
it must not be described as an entirely offline original build.

The replacement historical source-only builder uses `DOCKER_BUILDKIT=0`, FROM an
already inspected local IMAGE ID, COPY only, no RUN/install, `--pull=false`,
`--network=none`, and `--force-rm=true`. BuildKit's resolver is excluded, rather
than assuming the RUN network option prevents metadata requests.

**No Docker build was executed during RESUME-01.** Local image inspect confirmed
`sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8`
(Linux/amd64) was present. Its embedded Chromium, Playwright, Python, OpenSSL,
namespace tools and dependencies were reused. Narrow test / BFF / HTML / CSS
source overlays were mounted read-only; these overlays are not image attestation.
Each Docker create used the inspected immutable image ID. No registry resolver,
package installer, external site/AWS operation, host firewall/network change,
daemon configuration change, or dependency download was invoked on this path.

Resume inputs `.local/m5-run-02/s1` and `m5-run-03/s1` were mounted read-only;
SQLite backup and allowlisted job-directory copies created new test workspaces in
new owned volumes. Original exported captures/DBs, M2/M3 volumes, user databases,
Obsidian, `web/**` and CloudFront resources were not modified. Final hash checks
matched all 73 run02 and 13 run03 exported S1 files against their original export
manifests (`.local/m5-resume-safety.json` records these and current source hashes).

Before each real Chromium launch in a new namespace, the existing M2 controls
passed: positive canary reachability, UID1000 direct TCP/DNS/UDP/IPv6 refusal,
host/LAN/metadata models, UID1003 UI-only access, and stopped-proxy fail-closed.
Actual Chromium negative tests recorded zero forbidden canary deltas and positive
drop counters for all four protocol rules. Namespace/PID/seccomp sandbox, nonroot,
zero capabilities, NoNewPrivs and bounded cgroups were observed. This is a local
fixture boundary observation, not formal T01–T21 certification.

## Trusted observations and signing

The original run02 Worker independently observed:

| Item | Observation / classification |
| --- | --- |
| OS | Linux 6.6.87.2 microsoft-standard-WSL2 / glibc2.39; TRUSTED_OBSERVED |
| Architecture | amd64, Worker uname matched launcher image inspect; TRUSTED_OBSERVED |
| Chromium binary | Google Chrome for Testing 156.0.8078.4 and binary SHA-256; TRUSTED_OBSERVED |
| Playwright | Installed package metadata 1.64.1; TRUSTED_OBSERVED |
| Image | Launcher inspected owned container/image ID, pinned in plan/receipt; TRUSTED_OBSERVED |
| Available fonts | 212 `/usr/share/fonts` files, per-file hashes and inventory digest; TRUSTED_OBSERVED |
| Viewport/DPR/isMobile, locale/timezone, color scheme, screenshot range, animation/wait/stability instructions | CONFIGURED_ONLY |
| JS viewport, DPR, locale/timezone, media queries, user agent, fonts status | BROWSER_REPORTED diagnostic data |
| Actual renderer conditions and fonts used | UNKNOWN |

Available font inventory does not prove which fonts rendered a page. Equal
received PNGs prove only repeatability of those bytes. Neither matching settings,
browser claims nor signatures promote missing mandatory measurements. The latest
observer report explicitly exposes the four classification names; no historical
M3 data was retroactively certified. Resume UI reads old signed records without
recovering their destroyed key and never upgrades their quality.

Fixture signing uses fresh random 32-byte keys in the trusted UID1001 Worker's
memory. No key file/env/argv/HTTP/Browser transport or Git literal was introduced.
Existing plan/receipt job, attempt, evidence, profile, baseline and policy binding
is reused. Real fixture tampered-plan and cross-job replay checks rejected both;
offline tests also exercise other-key rejection, tampering and revocation.
KEY_GENERATED, verification rejection and KEY_REVOKED events are retained;
signed records retain key IDs for usage. Revocation disables signing/verification.
Physical Python memory erasure is not claimed; process termination ends custody.
Production persistence, rotation/KMS and long-lived key custody remain UNKNOWN.

## Approval Timeout diagnosis and limited fixes

Read-only inspection of run03's exported SQLite found **zero decisions/versions**.
Thus there was no successful approval transaction hidden behind a display wait.
The original error logged only TimeoutError; its exact historical substep and
HTTP resource cannot be reconstructed and remain UNKNOWN.

Safe stage/HTTP diagnostics were added: monotonic time, fixed path, method and
status only; no bodies, headers, cookies, pairing values or raw form exceptions.
Resume02 observed 503 responses for `/local/m1.js` and `/local/runtime.js` during
HOME startup. Existing HOME requested two stylesheets plus five deferred scripts
against an unchanged **four-connection** BFF limit. Missing baseline controller
was a concrete hypothesis for approval-panel waiting without an approval POST.

Resume05 reproduced the mechanism in a disposable page: old parallel-script HOME
with local baseline.js response intercepted as 503 -> controller absent -> clicking
candidate does not dispatch approval and leaves the panel hidden. This proves
the mechanism, **not** that baseline.js specifically failed in original run03.

Fix: serve the five existing scripts, in the same order, as one bounded static
`/local/workspace.js` response. Individual fixed assets remain compatible; CSP,
authentication, session, Origin, CSRF, response cap and connection cap are unchanged.
There is no timeout extension, automatic approval retry or approval bypass.

Resume05 then loaded all controllers and explicitly approved both original run03
candidates on a **copy** through the real UI. Timeline: detail/history/session
200 -> unchecked confirmation -> human-test check/click -> authenticated CSRF
dispatch -> transaction return -> POST 200 -> list/detail/history 200 -> APPROVED.
Worker transaction times were ~25ms and ~44ms. Approval history and immutable v1
records were preserved. Original run03 DB still has zero approvals.

Additional limited fixture fixes: screenshot output is divided into bounded 32KiB
chunks instead of raising the 512KiB control-line limit; missing-image tests
refresh history before looking for new results. Resume history reads old results
without assuming their jobs remain in the latest-10 Job list. The already passed
run02 compare-button write/history test was reused rather than replayed on an
invisible old Job. When all controllers loaded, a mobile grid intrinsic-width
overflow became visible; local panel/form min-width constraints corrected it.

## Evidence reused and final real UI observations

Run02 retained successful Desktop/Mobile real HTTPS fixture observations:

| Scenario | Result |
| --- | --- |
| Initial capture -> S1 -> candidate | COMPLETED, BASELINE_PENDING, UNKNOWN |
| Explicit UI approval | APPROVED v1 for both profiles |
| Same pixels | 0 changed pixels for both; preview only / UNKNOWN |
| Changed pixels | Desktop 8,096; Mobile 8,092; diff PNG generated; preview only / UNKNOWN |
| v2 approved after deferred submission | Job still compared against pinned v1; histories retained |
| Profile mismatch | UNKNOWN / PROFILE_MISMATCH, no metrics/diff |
| Key/receipt unavailable | UNKNOWN / PROFILE_UNATTESTED, no quality PASS |
| Clone-only PNG/manifest corruption | Rejected, UNKNOWN and no diff |
| Plan tampering / cross-job replay | Rejected |
| Slow fixture | TIMED_OUT, no adopted evidence |
| Producer exit 7 | FAILED_EXECUTION, capped partial output preserved, no adoption |

Fixture policy explicitly permits **zero changed pixels** for its deterministic
static page, rationale stored in the signed plan and each result. This is a test
setting, not a product default. Without an explicit policy, comparison remains
UNKNOWN / THRESHOLD_UNDEFINED. An explicit trusted-startup preview opt-in allows
only unattested/unstable image preview, keeps quality UNKNOWN, and never converts
it to PASS or CHANGED. Default preview remains disabled. Cached pixel work follows
fresh integrity/approval/profile/policy checks; cached verdicts are not trusted.

Final complementary scoped trials:

- `.local/m5-resume-05/validation-result.json`: **PASS, RESUME_APPROVAL_ONLY**.
- `.local/m5-resume-07/validation-result.json`: **PASS, RESUME_HISTORY_ONLY**.
- Resume07 all checks true: all HOME controllers loaded, unauthenticated results
  hidden, keyboard pairing/focus, HttpOnly/SameSite Strict cookie path, Japanese
  UNKNOWN/profile reasons, same/changed observation labels, three source/diff PNGs
  loaded, invalid CSRF ->403, desktop/mobile no document overflow, missing PNG
  ->422 with clear UI error, state503 clears rows, destroyed session401 clears rows.
- `ui-desktop.png` and `ui-mobile.png` from resume07 were visually inspected.
  This is automated operation/display validation, not USER personal usability signoff.

Failed scoped trials are retained, not relabeled: resume01's two approvals passed
but a test-only HOME switch changed the allowed port and was correctly blocked;
the harness now runs the two workspaces separately. Resume02/03 exposed old-Job
selection mistakes; resume04 stopped **before Browser startup** on fixture TLS
`certificate is not yet valid` (clock-related validity observation, no bypass).
A fresh limited retry passed with TLS validation intact. Resume06 completed error/
expiry checks but failed the mobile-overflow aggregate, corrected in resume07.

## Limited regression tests

Completed groups overlap; do not sum them as unique tests:

- 39 PASS: `tests.runtime.test_m5_profile`, `test_lifecycle`, `test_contracts`
  (latest run 8.988s).
- 26 PASS (earlier M5 evidence): `tests.comparison.test_m4` plus M5 profile tests.
- 50 PASS (earlier M5 evidence): M4/runtime/image comparison UI groups.
- 29 PASS: LocalUITests + ApprovalTests + PairingRenewalTests, including ordered
  workspace script, unchanged four-connection bound, cookie/CSRF and approval (3.513s).
- 16 PASS: local Baseline + M4 comparison JS/UI regressions (23.757s).

Two earlier processes whose terminal results were unavailable are NOT counted as
PASS. No unrelated full-suite repetition, real external site, production profile
attestation or USER personal UX test was run. Existing M4 formal results are reused.

## Cleanup and checkpoint scope

All owned test containers were stopped, logs/evidence archived outside Docker,
ownership/stopped state rechecked and containers removed non-forcibly by cleanup().
Every run/resume cleanup report is retained. No SiteProof container remains;
the same four pre-existing other-project containers remain exited and unchanged.
Dedicated volumes/networks/images are retained, with no broad prune or rm -v.
No secret/TLS private-key directory was exported.

Permitted checkpoint covers observer/provenance/preview, bounded output handling,
Mobile context instruction, local UI startup/layout/pairing, corresponding tests
and these contracts. No destructive schema migration or historical evidence edit.

Remaining gates: formal T01–T21 **UNKNOWN**; AWS Worker Pilot **NO-GO**;
v0.7 **NOT ADOPTED / NOT FROZEN**; C-02 **DEFERRED / OPEN**; Search Fabric gates
unchanged. USER UX, actual renderer authenticity, product tolerance and production
key management remain open. The local technical completion is not a blanket M5
quality/security certification.

Reproduction is local-environment specific: existing cached image and run02/run03
exports are required. `python -B -m tests.runtime.validate_m5 --evidence <new-path>
--resume-ui` runs approval diagnosis; `--resume-history` runs retained image/history
UI tests. No build is needed. `--image` may select another already local source
snapshot; inspect pins its ID before any create. Building/downloading a missing
runtime is not authorized by these commands or by this report.
