# Lane B contract-derived offline matrix

Formal T01-T21 correspondence: **UNKNOWN**. The approved handoff supplies only the
aggregate name, with no authoritative per-case definitions. The descriptive groups
below are local traceability labels, not invented original test numbers. Passing
these tests does not establish formal T01-T21 completion.

The tests run against committed integration HEAD
`4e9a41ee944525a017a18a05f75c022d32e8058f` plus Lane B's allowlist changes only.
No uncommitted Lane A code is imported. Python 3.15 standard library only; every
wired test owns a `siteproof-int01-lane-b-` TemporaryDirectory, SQLite database,
and artifact root. No ports, sockets, DNS, workers, browsers, VMs, or external
services are used. The `.invalid` URL is snapshot data only.

## Production path and evidence provenance

`src.bridge.EvidenceBridge.finalize(job_id, attempt_id, bounded_source)` obtains
the canonical AttemptRef from the finalizer's Repository, requires the current
attempt and SAVING job, checks INT-07 connection IDs/epoch, calls real
`src.isolation.frames.FrameReader.read`, converts nominal dataclasses/enums via
`adapt_stream`, and calls real `src.storage.finalizer.EvidenceFinalizer.finalize`.
The return value retains the original transport diagnostic and actual S1 outcome.

`fixtures.py` explicitly imports the existing `tests/isolation/wire_fixtures.py`
by file-module path, without modifying it. It uses its header/packet/END and real
1x1 PNG builders. Record bytes are synthetic `siteproof.record.v0.1` JSON;
neither S1 `synthetic.make_frame` nor its signature-only PNG is used. These tests
verify transport/consistency/persistence, not the truth of browser observations.

## Traceability

Method names below are in `test_adapter.py` (`AdapterTests`) or `test_wired.py`
(`WiredEvidenceTests`, `WiredTransportTests`, `WiredAttemptSafetyTests`). Several
methods contain deterministic subcases; unittest counts methods, not subcases.

| Contract/source references | Tests and acceptance evidence |
| --- | --- |
| `src/isolation/INTERFACE.md`, INT-07; `src/isolation/frames.py`, VerifiedFrame/StreamSummary; `src/core/frames.py` | `test_every_frame_and_summary_field_preserved`: all 13+3 fields, four kinds, check enums, payload identity. `test_all_terminations_and_incorrect_counts_preserved`: all five terminations and incorrect totals unchanged. `test_frame_order_and_duplicates_not_changed`, `test_incorrect_evidence_is_never_repaired`: no sorting, dropping, repair, rehashing, or context replacement. |
| Same contract; nominal type requirements in `src/core/ingest.py` | `test_incompatible_frame_fields_rejected`, `test_incompatible_wrapper_and_summary_rejected`, `test_bridge_requires_real_finalizer`: reject wrong classes, mutable payloads/containers, bool/nonnumeric counters, enum objects where S0 strings are required, unknown enum values. |
| `src/storage/finalizer.py`, _write_evidence/_commit; `src/storage/manifest.py`, verify_published/compare_with_db; `tests/storage/test_finalize.py`, NormalFinalizeTests | `test_http_load_pass_persisted_and_reopened`: actual artifacts/manifest hashed and read back, fresh Repository handle, DB/check/artifact comparison, adopted attempt and version. |
| `src/core/records.py`, derive_report; `src/core/rules.py`, required_artifact_kinds/derive_quality; `tests/core/test_records.py`, OutcomeDerivation | `test_capture_baseline_states_persist_unknown_with_real_png`: no baseline -> UNKNOWN/BASELINE_PENDING; existing baseline without comparison -> UNKNOWN/COMPARISON_NOT_RUN; actual PNG persisted and manifest verified. `test_explicit_unknowns_stay_unknown`. |
| `src/core/rules.py`, classify_http_status; `tests/core/test_records.py`, test_http_status_classes | `test_http_status_classes_derive_without_promotion`: range boundaries 100/199/200/299/300/399/400/599 plus 404/500; 2xx PASS, 4xx/5xx FAIL, 1xx/3xx UNKNOWN and unresolved reasons. |
| `src/core/records.py`, validate_skips; `tests/core/test_records.py`, SkipJustification; PF04 documentation correction | `test_explicit_http_failure_justifies_follower_skips`: HTTP FAIL with explicit LOAD/CAPTURE UPSTREAM_HTTP_FAILED records; quality FAIL. `test_invalid_skips_rejected`: HTTP skip, absent/PASS/UNKNOWN upstream, arbitrary reason, LOAD and CAPTURE followers all rejected without persistence. |
| `src/storage/finalizer.py`, build_results; `src/core/rules.py`, validate_report; `tests/storage/test_finalize.py`, EvidenceFailureTests | `test_missing_required_records_or_png_never_autofilled`: empty CLEAN stream, missing records, missing capture record with PNG, successful capture without PNG rejected. `test_failed_capture_without_png_is_explicit_fail`, `test_unexpected_png_for_failed_capture_rejected`. |
| `src/core/records.py`, _load_json/parse_record/derive_report; `tests/core/test_records.py`, ParserRejectsMalformedInput | `test_record_syntax_and_schema_rejections`: strict UTF8, JSON structure, duplicate keys, nonfinite constants, bool/out-of-range status, unexpected/missing fields, wrong schema/type, payload context forgery, empty reason. `test_capture_baseline_and_comparison_fabrication_rejected`: baseline disagreement, fabricated SAME/CHANGED/PASS, wrong reserved reason. |
| `src/core/ingest.py`, verify_frame/verify_stream; `tests/core/test_ingest.py` | `test_s1_rechecks_page_profile_required_check_and_duplicates`: transport CLEAN but S1 rejects context/check/slot mismatches. `test_s1_rejects_preserved_post_reader_corruption`, `test_s1_rejects_preserved_wrong_summary_counts`: deliberate post-reader boundary mutations prove incorrect IDs/epoch/seq/hash/length/payload/provenance/schema/check mapping/counts reach real S1 unchanged and are rejected. These mutation tests are distinguished from ordinary wired runs. |
| `src/isolation/frames.py`, _header/read; `tests/isolation/test_frames.py`, `tests/isolation/test_connection_boundary.py` | `test_wire_protocol_failures_do_not_adopt_prefix`: missing END, truncation, trailing data, wrong sequence/magic/version/kind, bad/boolean lengths, extra fields, empty IDs, invalid END, invalid UTF8/duplicate keys. `test_wire_context_claims_rejected`: job/attempt/epoch wire claims cannot replace canonical context. |
| `src/isolation/frames.py`, FrameLimits/_read_piece/_check_time; existing isolation transport tests | `test_transport_quotas`: header, record, PNG, stream and frame-count limits. `test_invalid_png_container_and_pixel_limit`: signature-only/truncated/corrupt/trailing PNGs and pixel quota rejected. `test_timeout_error_and_deadline_become_timed_out`: source timeout/exact deadline. `test_source_errors_and_invalid_reads_are_protocol_errors`. `test_bounded_fragmented_source_not_closed_or_seeked`: bounded short reads, caller retains source ownership. |
| INT-07; `src/storage/repository.py`, get_attempt/latest_attempt; `src/storage/finalizer.py`, entry checks; `tests/storage/test_finalize.py`, AttemptAndTerminalTests | `test_canonical_repository_attempt_context`: current epoch 7 comes only from Repository. `test_canonical_connection_id_preconditions_are_not_sanitized`: trailing-newline IDs are rejected before reading, including committed PF03 model defect. `test_stale_attempt_rejected_before_read`, `test_unknown_and_invalid_context_rejected_before_read`, `test_non_saving_and_terminal_jobs_rejected_before_read`. |
| `src/storage/repository.py`, transition/commit_completed; `src/storage/finalizer.py`, _fail/_commit; existing StaleAttemptDuringFinalizeTests/CancelRaceAndFailpointTests | `test_attempt_changed_during_read_cannot_adopt_or_fail_new_attempt`: valid and failed transport both fence stale attempts. `test_new_attempt_during_commit_is_lost_race`, `test_new_attempt_during_failure_does_not_terminalise_it`, `test_cancel_during_commit_wins`: newer owner/terminal state untouched, no evidence adopted, unadopted files retained. |
| `src/storage/finalizer.py`, precommit verification/_resolve; `src/storage/manifest.py`, verify_published; existing storage integrity/failpoint tests | `test_precommit_artifact_corruption_never_adopted`, `test_manifest_readback_detects_post_commit_artifact_tampering`, `test_lost_commit_ack_resolved_from_database`, `test_rolled_back_commit_remains_not_committed`: actual SQLite/file behavior and explicit commit-state distinctions. |

## Limits and unresolved dependencies

- Lane A owns PF01/PF02/PF03/PF06 hardening and PF05 corrections. No combined-lane
  integration or formal acceptance is claimed. S1 standalone paths are outside
  Lane B ownership; bridge type/precondition rejection does not fix those paths.
- S0 PNG checks establish container/chunk/CRC validity, not complete decoding or
  agreement of IDAT with IHDR. S1 re-verification is its committed behavior.
- A synchronous FrameReader cannot interrupt blocking I/O. The caller must supply
  bounded/nonblocking input or a source with its own timeout. No production
  transport, worker, OS isolation, or network integration was implemented here.
- Existing finalizer filesystem/SQLite atomicity and residual post-verification
  TOCTOU limits remain; this bridge does not claim to eliminate them.
- Gate states remain unchanged: v0.7 COMMANDER DRAFT / NOT ADOPTED / NOT FROZEN;
  LOCAL-ISOLATION NOT VERIFIED; AWS LIVE NO-GO; C-02 DEFERRED/OPEN;
  Search Fabric AWS HOLD. Formal T01-T21 correspondence remains UNKNOWN.
