# M4 capture comparison contract

This is an offline-tested software integration. It does not assert real-browser
UX acceptance, production capture attestation, real-site permission or a formal
T01–T21 result. Obsidian remains the design/status source of truth.

## Explicit trusted startup

Use the existing S1 + Baseline + M1 + runtime database and evidence root. On a
separately authorized database, call `storage.comparison.initialize(db, root)`
once. It adds only `m4_*` tables and append-only triggers, atomically, and refuses
an existing/partial extension. It never initializes on GET. No M3 database was
migrated or raw evidence edited for this milestone.

Create `ComparisonService(workspace, authority=..., policy=...)` and pass it as
`RuntimeService(..., comparison=service)`. The paired `LocalBaselineHOME` uses that
same instance. Omitting the service preserves M2/M3 behavior. No HTTP job-start,
observer configuration, key, path, SQL, threshold or baseline-selection input is
accepted. Existing Host, Origin, cookie, pairing, CSRF, approval actor, response
size and deadline bounds remain in force for existing routes. New confined M4
PNG responses have an explicit 32 MiB binary limit matching the S1 reader, streamed
in 64 KiB chunks under the same deadline. The existing 256 KiB JSON/static/M1
response limit, Browser/Proxy quotas and all authentication guards are unchanged.

`PixelPolicy(maximum_changed_pixels, rationale)` has **no default**. In acceptance
tests the trusted starter explicitly chooses `0`, meaning exact RGBA equality;
one different pixel is CHANGED. This is an offline test policy, not an adopted
production tolerance. Without a policy, results are UNKNOWN/THRESHOLD_UNDEFINED.
The method/version, threshold, rationale and decode limits are pinned before the
Job starts and retained with every result. The core pixel rule and diff colors
reuse `comparison.preview`, matching the previous local Compare implementation.

## Provenance and unresolved production sources

The v1 CaptureProfile declaration/hash is unchanged and remains a declaration.
M4 adds a versioned context fingerprint over it and OS, architecture, Browser/
Playwright version, immutable image ID, fonts inventory hash, isMobile, animations,
wait and stability policy. Every v1 setting and added condition needs an
independent `launcher:` or `worker:` observation, including its acquisition source.
Source prefixes route provenance; they are not proof by themselves.

`TrustedProfileAuthority` is a trusted, in-process startup capability. Its
observer must independently measure/enforce conditions in the actual capture
environment. HTTP, Browser frames, browser self-reports, UI configuration, image
tags, arbitrary flags and old evidence declarations are not observers. The key
must be provisioned and retained by the trusted starter outside the browser,
SQLite, evidence root and HTTP. No key is generated, logged or persisted here.
Losing/changing it makes later compatibility checks UNATTESTED; there is no
automatic re-signing or repair.

The signed pre-capture plan binds the accepted JobSnapshot hash, declared profile,
context, source, comparison policy and exact baseline version/digest. A one-use,
in-memory permit must be issued while RUNNING **before** invoking the producer.
After successful bounded ingestion, a receipt binds the same plan to the adopted
attempt, snapshot, screenshot and S1 manifest hashes. Post observations must
match every prepared condition, and an independent worker stability observation
must explicitly report STABLE. Producer/source/proxy cleanup uncertainty prevents
verified compatibility. A lost permit cannot be reconstructed after a crash;
historical M3 evidence cannot acquire a plan or receipt retroactively.

`DockerLauncher.capture_profile_observations` independently rechecks the owned
container and immutable image ID and records **only** image OS, architecture and
image digest. It performs no launch, exec or network action. It does not establish
browser/package versions, actual fonts, isMobile, screenshot settings or stable
rendering. There is **no complete LOCAL_MEASURED observer wired to the existing
M3 fixture launcher**. Those missing conditions deliberately remain UNATTESTED.
Integrating independently measured capture conditions and trusted key lifecycle
requires a later real-runtime gate. The built-in default is UNKNOWN.

Acceptance tests inject synthetic worker/launcher observations under the separate
OFFLINE_TEST domain; UI/results label them TRUSTED_TEST and offline synthetic
validation. They cannot authenticate REAL_CHROMIUM_FIXTURE_UNATTESTED sources.
LOCAL_MEASURED accepts only the explicitly recorded real Chromium fixture source,
not arbitrary real websites. No real-site source or general browser launcher has
been added. Fixture PASS/CHANGED cannot upgrade M3, formal or operational gates.

## S1, Baseline and checks

S1 observation reuses the confined reader, read-only SQLite transaction, full
manifest/database verification, hashes, exact adopted attempt and bounded PNG
bytes from the same observation. Dimensions must match the declared viewport/DPR
(full-page height may be larger). M4 supports the existing 8-bit RGB/RGBA,
non-interlaced, IHDR/IDAT/IEND PNG format up to 4096 per side, 4,194,304 pixels and
32 MiB. Unsupported chunks, size/format/hash failures are explicit refusals.
Legacy preview defaults remain 65,536 pixels / 1 MiB. Metadata readback validates
CRC, inflation and filter bounds without reconstructing all pixels.

Successful capture evidence creates an immutable **pending human-review
candidate**, even when its profile is unverified. This is not an authorized
trusted S2 use of an unattested fingerprint. The old S1/S2 refusal adapter remains
unchanged and refusal-only. The M4 candidate stores its context and exact original
S1 evidence pins separately. The existing Baseline Store owns registration,
one-shot approval, expected-revision/current-version CAS, immutable versions and
history. The existing paired approval UI requires explicit confirmation and
revalidates M4 candidate evidence before deciding. Approval never certifies a
profile. A failed/skipped capture cannot create a candidate or auto-approval.

Submit selects a current approved M4 head of the same page and Desktop/Mobile
kind, preferring an identical full context. Its ID is fixed in JobIntent/
JobSnapshot and version/digest in the M4 signed plan. A mismatching same-kind head
is retained to explain PROFILE_MISMATCH. Approval after submission never changes
that Job's baseline. To use a newly approved version, submit a new Job.

Comparison independently reads both original images/manifests, validates the
Baseline's exact approved version/digest/evidence, both receipts, full compatible
contexts and all required checks. Only then can the explicit pixel policy produce
PASS or CHANGED. CHANGED observes a difference, not a defect. An explicit check
FAIL stays FAIL; SKIPPED is retained and never converted to PASS. Missing checks,
pending/unset Baseline, unverified/mismatching profiles, unstable capture, missing
or inconsistent evidence, unsupported PNG and undefined threshold stay UNKNOWN
with reasons. S1 terminal states and original CAPTURE UNKNOWN rows are never
rewritten by comparison.

Candidate registration and the M4 candidate link use separate existing-store
transactions. A failure can leave a registered candidate without a link. Such a
candidate cannot pass M4 approval validation. The event records an unconfirmed
save; no retry, automatic adoption, orphan deletion or repair occurs. The same
conservative rule applies to ambiguous result writes.

## Local UI and history

HOME links to Job evidence, Baseline details/explicit approval, comparison and
history. Only local BFF assets changed; the six public static HOME/Compare files
remain untouched. The UI shows Japanese reasons, profile provenance, human state,
fixed baseline version, current/baseline/diff images and CHANGED's meaning.

Paired fixed routes under `/api/baselines/_m4/`:

- GET `state`: latest 10 jobs (one 5-page Desktop/Mobile batch) and 25 results.
- GET `history/{offset}`: 25 results, bounded offset 0..10000, next_offset.
- GET `image/{job_id}`: reverified original S1 PNG, never caller paths.
- GET `result/{id}` and `result/{id}/{baseline|current|diff}`: immutable result and
  evidence images, reverified at selection/access.
- POST `candidate`, `compare`: exact `{job_id}` only, using existing CSRF guards.

History list entries explicitly show a saved point-in-time observation and
NOT_RECHECKED. Selection rechecks sources and reports VERIFIED or UNAVAILABLE.
Loss/corruption later does not rewrite an old result; it hides its images and
clearly labels the historical observation. A new comparison then yields UNKNOWN.
Diff PNG bytes/digest, metrics, conditions and reasons are append-only in the
same SQLite file. Original images and manifests are never overwritten or copied
into a second evidence tree.

Software tests use synthetic images, disposable databases, mock DOM and numeric
loopback HTTP only. Large PNG comparison throughput, real browser image loading,
native cookies, keyboard/accessibility, responsive rendering, explicit policy
choice and independently measured production profiles remain real UX/runtime
gates. BFF deadlines are not automatically widened for large PNGs;
a timed-out write is unconfirmed and must be reconciled from history, not retried.

Maintained gates: formal T01–T21 UNKNOWN; AWS Worker Pilot NO-GO; v0.7 NOT ADOPTED /
NOT FROZEN; C-02 DEFERRED / OPEN; Search Fabric gates unchanged.

## Operational image verdict and connection audit (S1-A/S1-B)

`compare()` adds `operational` (`operational.py`): `VISUAL_CHANGED`, `NO_VISUAL_CHANGE_DETECTED`
or `UNKNOWN` under the explicit exact-RGBA policy. It is not a quality assurance, never changes
`quality`, and keeps `PROFILE_UNATTESTED`; equal SHA-256 only proves byte equality.

The trusted CONNECT proxy (`isolation/ledger.py`, hooked in `ConnectTransport._serve`) records every
attempt as host/port/decision/reason only (no URL, query, credential or cookie). `RuntimeService.run`
stores one `network_audit` event per job window. The verdict is `UNKNOWN` for the current AND the
Baseline capture unless that audit exists, is complete, has at least one connection and no blocked
or failed connection. A missing/unavailable/overflowed ledger is never read as "0 blocked". A CONNECT
proxy cannot see resource types (JS/CSS/font/image); the audit says `resource_types: NOT_OBSERVABLE`.
Results saved before this record are shown as "not recorded"; no audit is ever reconstructed.
Strict PASS/CHANGED does not consume the audit.
