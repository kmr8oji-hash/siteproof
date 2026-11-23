# SITEPROOF-M4-COMPARISON-BATCH-01 implementation record

Date: 2026-11-06 JST. Executor validation, not Commander or real UX signoff.

WP0 checkpoint: `6b7391a0862aaee28bf9df9093412b1f4ca1cedf`.
Parent: `478ddf268f7931e4c12dc6856bda2979d18c4cf2`.
The corrected Start Gate contained only the authorized three cleanup files.
The limited review confirmed archive-before-remove, exact owned ID/label and
stopped-state rechecks, non-forced removal, preserved named volumes, visible
cleanup failures, and unchanged Browser sandbox/Proxy/quota requirements.
The 34 offline lifecycle/runtime tests were rerun and passed before the commit.

## Implemented and verified

- Explicit additive M4 SQLite extension; immutable plans, receipts, candidate
  evidence links, results and diff bytes. GET does not initialize/migrate.
- Capture context/provenance binds pre-capture JobSnapshot, source, settings,
  policy and baseline pin to the adopted S1 attempt/image/manifest. Ephemeral
  capture permits prevent retrospective signing. Missing independent conditions,
  failed signatures, replay, unstable captures and cleanup uncertainty fail closed.
- Reused S1 confined readback, existing versioned Baseline Store and paired
  explicit approval UI. Capture success creates PENDING/BASELINE_PENDING review
  candidates. Approval uses expected revision/current version and rechecks M4
  evidence. No job auto-approves a candidate or rewrites an approved version.
- Approved version/digest fixed at submit; later approval does not rebind a Job.
  Exact pixel comparison requires two verified compatible contexts, both valid
  S1 images/manifests, required successful checks and an explicit threshold policy.
  HTTP FAIL and downstream SKIPPED are preserved separately from execution state.
- Japanese local HOME -> Job evidence -> candidate/detail -> explicit approval ->
  comparison -> baseline/current/diff -> paged history. Missing images, stale
  historical observations, UNKNOWN and CHANGED's meaning are explicit.
- Five-page / Desktop+Mobile constraints, pinned profile revisions, read-only
  SQLite reopen, evidence write-once behavior and approval conflicts are tested.
- Reverified M4 PNGs use an explicit 32 MiB binary response cap with 64 KiB writes
  and existing deadlines. A roughly 314 kB synthetic PNG was delivered correctly. The
  old JSON/static/M1 response limits and Browser/Proxy/shared output quotas remain.

## Final limited test results

Run each group in a **separate Python process**. Older test modules install global
audit hooks at import; importing every suite in one process produces unrelated
fixture-root/process-boundary conflicts. Explicit class selection avoids imported
TestCase duplication. No audit hook was disabled or weakened.

| Group | Command after `python -B -m unittest` | Result |
|---|---|---|
| M4 acceptance + launcher observations | `tests.comparison.test_m4 tests.runtime.test_profile_observations` | 24 PASS |
| New paired comparison/Baseline API | `tests.bff.test_comparison` | 5 PASS |
| Runtime/S1/S2/models/Baseline regression | `tests.integration.test_m2_runtime.M2Tests tests.integration.test_s1_evidence.S1EvidenceTests tests.integration.test_s2_adapter tests.comparison.test_profile tests.comparison.test_decision tests.baseline.test_sqlite_store tests.baseline.test_approval` | 200 PASS |
| Existing paired/Bearer BFF/approval/runtime view | `tests.bff.test_baseline.BFFTests tests.bff.test_approval.ApprovalTests tests.bff.test_local_ui.LocalUITests tests.bff.test_runtime_view.RuntimeViewTests` | 51 PASS |
| JS + mock DOM + loopback UI/Compare regression | `tests.ui.test_m4_comparison tests.ui.test_offline_m1 tests.ui.test_runtime_view tests.ui.test_local_baseline tests.ui.test_image_compare` | 69 PASS |
| Cleanup/runtime safety regression | `tests.runtime.test_lifecycle tests.runtime.test_contracts` | 34 PASS |

Final groups: **383 test executions PASS, 0 FAIL, 0 SKIPPED**. They include 33 new
tests (21 M4 acceptance, 5 BFF, 4 mock-DOM/HTTP UI, 3 launcher observations).
`node --check src/bff/ui/comparison.js` and `git diff --check` also passed.
Intermediate failures were corrected: replay rejection-code priority, incorrect
cross-suite test invocation, and a large-PNG fixture exceeding the deliberately
shared 1 MiB synthetic batch quota. The latter was fixed by reducing the fixture,
without changing the quota. No residual failing acceptance case is hidden.

The 12 requested acceptance categories are exercised by `test_m4.py`,
`test_comparison.py`, `test_m4_comparison.py` and relevant existing tests. The UI
group executes actual JS against authenticated temporary SQLite/loopback HTTP,
but its DOM is mocked. It does not render a native browser.

## Remaining UNKNOWN / next real gate

**M4 offline software integration: PASS. Complete real capture-profile trust and
real-browser practical UX: UNKNOWN / NOT RUN.**

The real launcher can independently observe only image OS/architecture/immutable
image ID in this change. Complete Browser/Playwright versions, fonts, enforced
isMobile/context/screenshot options and capture stability require an independently
measured trusted observer and a reviewed external key lifecycle. None is silently
inferred from M3/browser output. The complete observer is not wired to M3; its
past evidence remains PROFILE_UNATTESTED and cannot gain PASS/CHANGED here.
OFFLINE_TEST/TRUSTED_TEST observations are synthetic and cannot certify real
Chromium sources. Production difference tolerance is not chosen; missing policy
remains THRESHOLD_UNDEFINED. The tests explicitly use zero changed pixels.

Next separately authorized gate must provision the new schema on a designated
test DB, integrate and independently measure the real trusted observer, choose
the comparison policy, and exercise new captures with explicit approvals. Verify
real PNG formats/limits/throughput, image loading, paired cookies, Japanese error
flows, keyboard/accessibility, Desktop/Mobile and responsive layouts. No production
user DB or M3 original evidence was modified. M3 raw evidence was not newly
reauthenticated or promoted through this offline task.

No real browser/Docker Job, real-site/DNS/AWS request, push, reset, stash, merge,
hook bypass, destructive migration, orphan deletion or automatic repair occurred.
The six public HOME/Compare files and all `web/**` / `infra/**` files are unchanged.
The Obsidian canonical documents were read only.

Maintained gates: formal T01–T21 UNKNOWN; AWS Worker Pilot NO-GO; v0.7 NOT ADOPTED /
NOT FROZEN; C-02 DEFERRED / OPEN; Search Fabric AWS HOLD / Gate3 NOT PASS / FD-1 STOP /
K1 CONFLICT OPEN unchanged.

## M4 file inventory

- `src/runtime/docker_launcher.py`, `src/runtime/service.py`, `src/runtime/INTERFACE.md`
- `src/bridge/s1_evidence.py`
- `src/comparison/provenance.py`, `src/comparison/service.py`, `src/comparison/preview.py`,
  `src/comparison/INTERFACE.md`, `src/comparison/M4_VALIDATION.md`
- `src/storage/comparison.py`
- `src/bff/approval.py`, `src/bff/local_ui.py`, `src/bff/ui/comparison.js`,
  `src/bff/ui/index.html`, `src/bff/ui/baseline.css`
- `tests/comparison/support.py`, `tests/comparison/test_m4.py`,
  `tests/bff/test_comparison.py`, `tests/runtime/test_profile_observations.py`,
  `tests/ui/test_m4_comparison.py`

M4 is a single commit directly after the WP0 checkpoint, using the authorized
feature commit message. The final SHA/parent and clean index/worktree are verified
after commit and reported in the completion response (a file cannot contain its
own commit SHA).
