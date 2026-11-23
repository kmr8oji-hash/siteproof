# S0 offline interface — SITEPROOF-LOCAL-BATCH-02-A

This package contains offline decision/accounting/transport validation only.
It uses Python's standard library. It does not resolve DNS, open sockets,
start a proxy/browser, create a VM, or enforce operating-system isolation.
**LOCAL-ISOLATION is UNVERIFIED.**

## Contract and S1 consumption

Contract version remains `siteproof.bridge.v0.1`. The 13 VerifiedFrame fields,
three StreamSummary fields, kinds, check types and termination values are unchanged.
No shared contract module, S1 implementation or S0-to-S1 adapter is created here.
**Actual S0/S1 connection and integration tests have not been performed.**

```python
from src.isolation.frames import FrameReader, TrustedContext

# source is an existing bounded BinaryIO supplied by the trusted caller.
# attempt_ref is the canonical AttemptRef obtained from S1's Repository.
# It must belong to the current JobSnapshot and current attempt, with epoch >= 1.
# Never construct this context from browser headers or record payload claims.
context = TrustedContext(job_id=attempt_ref.job_id,
                         attempt_id=attempt_ref.attempt_id,
                         lease_epoch=attempt_ref.lease_epoch)
result = FrameReader(source, context).read()
if result.summary.termination == "CLEAN":
    complete_frames = result.frames
```

`FrameReader` is single-use and does not close or seek its input. `read()` returns
a frozen `StreamResult(frames, summary, reason)`. `frames` is a tuple of frozen
`VerifiedFrame` objects with exactly these contract fields:

| Field | Value/source |
| --- | --- |
| schema_version | `siteproof.bridge.v0.1` |
| job_id, attempt_id, lease_epoch | validated `TrustedContext` |
| seq | zero-based contiguous integer |
| kind | `HTTP_RECORD`, `LOAD_RECORD`, `CAPTURE_RECORD`, `SCREENSHOT_PNG` |
| page_id, profile_id | nonempty UTF-8 identifiers, without control characters |
| check_type | `HTTP`, `LOAD`, `CAPTURE`, `CAPTURE`, respectively |
| byte_length | actual accepted payload length |
| sha256 | lowercase SHA-256 of the accepted payload bytes |
| payload | immutable bytes |
| provenance | `untrusted_browser_validated_transport` |

`StreamSummary` contains only `termination`, `frame_count`, and
`total_payload_bytes`. The latter two count accepted data frames only, excluding
END and any rejected/incomplete frame. Terminations are exactly `CLEAN`,
`TRUNCATED`, `TIMEOUT`, `OVERSIZE`, and `PROTOCOL_ERROR`. A diagnostic reason code
is in the local wrapper, not an extension of the shared summary contract.

On failure, independently transport-validated prefix frames remain in the result.
S1 must examine the summary and must not treat that prefix as a complete stream.
`CLEAN` requires a complete, valid END followed by EOF, with every frame and
limit validated. It does not establish that any expected observation was made;
END alone is a valid empty stream. Application-level completeness is S1's job.

### S1 connection preconditions and adapter responsibilities (INT-07)

- The trusted caller obtains the canonical, current AttemptRef from the Repository
  and uses its job_id, attempt_id and lease_epoch without replacement. S1 must
  recheck the attempt/epoch against its current state when accepting evidence.
- For S1 connections, lease_epoch must be an integer >= 1 (not bool). IDs must
  match the JobSnapshot/AttemptRef and S1's naming rules: ASCII letters/digits
  first, followed by letters/digits/dot/underscore/hyphen, at most 64 characters.
  page_id and profile_id in the wire header must equal the snapshot's values;
  their presence in a browser header does not make them authoritative.
- These are connection preconditions, not changes to S0's general-purpose
  validation: S0 still accepts epoch 0 and its existing wider UTF-8 ID range.
- S0 emits its own frozen dataclasses and plain strings. S1's separate nominal
  dataclass and enum checks require an explicit adapter. A future adapter must
  convert kind, check_type and termination to S1's corresponding enums, rejecting
  unknown values. It must preserve their meanings and the kind-to-check mapping.
- The adapter must not renumber/sort/drop frames, rewrite IDs or epoch, decode and
  reserialize payloads, replace payload bytes, recompute/repair sha256 or
  byte_length, or regenerate summary counts/totals/termination from a prefix.
  Preserve schema_version and provenance as well. Pass the original S0 summary
  values through the representation conversion; never turn a non-CLEAN result
  into CLEAN. S1 must independently verify IDs, kinds, sequences, lengths and hashes.
- Data seq starts at 0 and increases by exactly 1 without gaps, duplicates or
  reversal. END uses the next seq, has empty page/profile IDs and length 0, and
  must be followed by observed EOF. No EOF/timeout/temporary lack of data may be
  guessed into a successful end. S1 receives no END frame, so it depends on the
  trusted S0 summary for this transport assertion.
- frame_count counts accepted data frames only; total_payload_bytes sums their
  actual payload lengths. END and rejected/incomplete frames are excluded.
  Matching counts/totals alone cannot prove contiguous seq or required-check
  completeness. S1 must reject missing checks/artifacts and duplicate check/kind
  slots; S0 does not impose S1's application-level uniqueness requirements.

### Provisional record payload contract — Batch 02

The application-level payload contract is `siteproof.record.v0.1`, separate from
the unchanged outer `siteproof.bridge.v0.1` transport schema. HTTP_RECORD,
LOAD_RECORD and CAPTURE_RECORD payloads are UTF-8 JSON with these common fields:

| Field | Application contract |
| --- | --- |
| schema_version | `siteproof.record.v0.1` |
| record_type | `HTTP`, `LOAD` or `CAPTURE`, matching the frame kind/check_type |
| observation | JSON object |
| observation.reason_code | Nonempty string, including for UNKNOWN/SKIPPED |

HTTP_RECORD observation:

- state is OBSERVED, UNKNOWN or SKIPPED.
- OBSERVED requires status_code: an integer 100..599, never bool.
- UNKNOWN/SKIPPED must not contain status_code.
- S1's provisional classification is 200..299 -> PASS; 400..599 -> FAIL;
  100..199 or 300..399 -> UNKNOWN. A 3xx is not automatically PASS because this
  batch verifies neither a redirect destination nor a final response.
- UNKNOWN remains UNKNOWN. HTTP SKIPPED is rejected by S1 (`SKIP_NOT_JUSTIFIED`):
  HTTP has no upstream check that can justify a skip, even with an explicit reason.

LOAD_RECORD observation:

- state is SUCCEEDED, FAILED, UNKNOWN or SKIPPED.
- Only a definite success maps to PASS, and only a definite failure to FAIL.
  An inconclusive timeout or lost signal maps to UNKNOWN. LOAD/CAPTURE SKIPPED
  requires an explicit record with reason `UPSTREAM_HTTP_FAILED` and an explicit
  HTTP record deriving FAIL. Absent, UNKNOWN, PASS or SKIPPED HTTP cannot justify
  a follower skip. Missing required checks are never auto-filled as SKIPPED.

CAPTURE_RECORD observation:

- capture_state is SUCCEEDED, FAILED, UNKNOWN or SKIPPED.
- comparison_state is BASELINE_PENDING or NOT_EVALUATED. Successful capture
  without a baseline uses BASELINE_PENDING; with a baseline but no comparison it
  uses NOT_EVALUATED. This batch defines no SAME/CHANGED comparison result.
- Successful capture requires a valid SCREENSHOT_PNG for the same snapshot and
  attempt. S1 must check this application requirement even when the comparison
  outcome is UNKNOWN. S0's CLEAN alone does not prove the image was supplied.
- A first successful capture with no baseline is capture success, comparison
  BASELINE_PENDING, Check outcome UNKNOWN (not PASS/CHANGED), for example:

```json
{
  "schema_version": "siteproof.record.v0.1",
  "record_type": "CAPTURE",
  "observation": {
    "capture_state": "SUCCEEDED",
    "comparison_state": "BASELINE_PENDING",
    "reason_code": "BASELINE_NOT_SET"
  }
}
```

With complete required checks/artifacts this can yield Job COMPLETED while
quality remains UNKNOWN, unless another required check makes it FAIL. A baseline
ID alone never proves a comparison and must not yield CAPTURE PASS/CHANGED.
No comparison engine or automatic baseline registration is implemented here.

S0 safely transports record bytes; it does not parse/validate their JSON, enforce
these business rules, or create CheckReport. Malformed/nonconforming record bytes
can therefore be transport-CLEAN and must be rejected or classified appropriately
by S1. Browser observations remain untrusted claims, including reason_code; neither
transport validation, a SHA-256 digest nor a self-declared reliability flag proves
their truth. S1 must validate the record and derive CheckReport, or check any
separately supplied report against that same current-attempt record. Missing
reports must not be fabricated, and record/report contradictions must not be
adopted as successful evidence. Further application-policy details remain S1's
responsibility; S0 does not add them to the transport schema.

## Local wire format

Each frame consists of a 4-byte unsigned big-endian header length, that many
strict UTF-8 JSON bytes, and `declared_length` bytes of payload. The JSON object
has exactly these keys; extra/missing/duplicate keys are errors:

```json
{"magic":"SITEPROOF","version":"siteproof.bridge.v0.1","seq":0,"kind":"HTTP_RECORD","page_id":"page","profile_id":"profile","declared_length":3}
```

The corresponding payload can be the three bytes `abc`. The next frame can be:

```json
{"magic":"SITEPROOF","version":"siteproof.bridge.v0.1","seq":1,"kind":"END","page_id":"","profile_id":"","declared_length":0}
```

END carries no payload and consumes the next sequence number, but is not emitted
as a VerifiedFrame. Browser claims for `job_id`, `attempt_id`, or `lease_epoch`
are rejected, even when equal to the trusted values. Browser-supplied hashes,
check types, or provenance are also disallowed as extra keys. JSON booleans and
floats are not accepted as integers. JSON NaN/Infinity and malformed Unicode
are rejected in headers. Record payloads remain uninterpreted bytes in S0; the
Batch 02 application-level JSON contract above is enforced by S1, not FrameReader.

`FrameLimits` has configurable batch-only defaults:

| Limit | Default |
| --- | --- |
| JSON header | 4 KiB |
| ordinary record payload | 2 MiB |
| SCREENSHOT_PNG payload | 8 MiB |
| stream payload total | 32 MiB |
| data frame count | 64 |
| elapsed reader deadline | 30 seconds |
| PNG width × height | 40,000,000 pixels |

These are provisional test settings, **not approved production safety limits**.
The additional deadline and pixel limit are local configurable safeguards, not
changes to the shared contract. Oversize header/individual/aggregate/frame-count
claims are rejected before reading their body/payload. Reads request at most
64 KiB; no allocation uses an unchecked untrusted declared length. The reader
retains accepted payloads, and Python buffers/copies/metadata add memory beyond
the aggregate payload limit. No exact process-memory ceiling is claimed.

Short BinaryIO reads are supported. Premature EOF is TRUNCATED. Source timeout
or elapsed deadline is TIMEOUT; other source errors/malformed read results are
PROTOCOL_ERROR. Deadline checks occur before and after reads. A synchronous
reader cannot interrupt a blocking `read`; a future source/transport must provide
its own bounded reads, timeout and cancellation. It must also provide EOF after
END, since the reader checks for trailing bytes.

PNG validation checks signature, chunk bounds/types/order/CRCs, IHDR dimensions
and encoding fields, basic palette constraints, nonempty IDAT, and terminal IEND.
It never decompresses pixels and does not fully validate ancillary chunk
semantics, compressed data, scanlines, or visual content. Tests deliberately show
that CRC-correct but undecodable IDAT can pass the structural check. A future
decoder needs its own resource limits. SHA-256 is computed over bytes actually
read; there is no authenticated sender digest or independent browser-content
verification. A smaller declared record length redefines the transport boundary;
unframed leftover bytes make the stream fail, but the reader cannot infer a
sender's intended record contents.

## Destination checks

Use `src.isolation.destination.check_destination(policy, hostname, port,
resolved_addresses)`. The result is `DestinationDecision(allowed, reason,
hostname, port, addresses)`. The inputs must be supplied by the caller; this
function makes **no DNS queries**.

`DestinationPolicy` requires a nonempty tuple of `AllowedDestination(hostname,
port)` entries. Every entry is validated, including unused entries. Ports are
strict integers 1–65535. Hostnames use exact, case-insensitive ASCII DNS matching
with at least two labels. No wildcards, suffix matching, URLs, IP literals,
trailing-dot normalization, IDNA conversion, whitespace stripping, or legacy
numeric interpretation is performed. Those representations are rejected rather
than normalized. Absent or malformed policy fails closed with `POLICY_MISSING`
or `POLICY_INVALID`.

Supply a nonempty tuple/list containing the entire DNS answer set. Every answer
must parse strictly using `ipaddress`; any malformed or forbidden answer rejects
the entire destination, with no allowed subset returned. Both public IPv4 and
public native IPv6 candidates can pass. Loopback/private/link-local/reserved/
multicast/unspecified/non-global/site-local addresses, scoped addresses,
IPv4-mapped IPv6, 6to4, Teredo and known NAT64 translation ranges are denied.
Allowed answers are canonicalized/deduplicated. All IPs in the tests are synthetic
fixtures; their presence is not an actual connectivity test.

A positive decision applies only to the supplied answer set. A future connector
must pin/revalidate the actual peer against it and the exact port, handle address
selection, and prevent rebinding/redirect/proxy bypasses. No such connector or
actual DNS/peer verification exists in this batch. IP classification follows the
installed Python `ipaddress` tables; environment-specific translation/routing and
future address-registry changes require separate review.

## Communication budgets

`src.isolation.budget.NetworkBudget(attempt_limits, tunnel_limits, clock=...)`
requires two explicit `BudgetLimits(total_bytes, total_connections,
concurrent_connections, connection_attempts, duration_seconds)` objects. No v0.7
network limit values were available in this Worktree, so none are invented or
presented as approved defaults. Counts/bytes may be zero; durations must be
positive and finite. Time is trusted monotonic elapsed time, optionally injected
for tests. Invalid/regressing clock values terminate the attempt fail-closed.

The caller uses:

1. `open_tunnel(tunnel_id)`: create a new trusted tunnel counter/deadline.
2. `begin_connection(tunnel_id)`: atomically admit an attempt, reserve concurrency
   and cumulative connection capacity in both scopes, and return a connection ID.
3. `connected(connection_id)`: mark successful establishment, converting the
   cumulative reservation to a permanent cumulative count.
4. `transfer(connection_id, sent=n, received=m)`: atomically account/reserve
   `n + m` bytes in both scopes.
5. `close_connection(connection_id)`: release concurrency; failed pending attempts
   also release cumulative reservations. This cleanup is idempotent.
6. `poll(tunnel_id=None)`: check deadlines, including idle tunnels.
7. `snapshot(tunnel_id=None)`: observe counters/termination without advancing time.

Snapshots expose total bytes, cumulative established connections, current
concurrency (pending plus established), admitted connection attempts, and sticky
termination. Failed admitted attempts retain their attempt count. Rejected events
are not added to counters. Failed/closed connections never refund cumulative
established connections or bytes. Tunnel IDs cannot be reused to reset budgets;
the literal ID `attempt` is reserved for the attempt scope in decisions.

Counts/bytes equal to their cap are allowed; the next positive increment denies
and terminates the affected scope. Elapsed time equal to the duration expires.
Tunnel breaches terminate that tunnel; attempt breaches terminate all tunnels.
Termination releases active accounting reservations and preserves recorded totals.
It does not close actual sockets. Further admission/poll returns a denial; using
an already released connection for transfer/establishment raises ValueError.
Trusted lifecycle/configuration misuse also raises ValueError.

Locking makes events atomic across threads and across both counter scopes.
A future transport must invoke admission/reservation before actual connection/
byte operations, schedule `poll` while idle, handle partial I/O conservatively,
and act on termination by cancelling/closing real resources. This is logical
accounting only: no live enforcement, OS packet accounting, or networking
throughput/time guarantees have been measured.

## Self-test evidence

### Batch 01 history

Executed from the requested Worktree with Python 3.15.1:

```text
pymanager exec -V:3.15 -B -m unittest discover -s tests/isolation -p "test_*.py" -v
```

- Initial suite: 73 tests passed.
- Regression expansion: 75 tests, 1 failure and 2 errors. It reproduced pending
  cumulative-capacity overbooking and huge-clock-integer overflow in both readers
  and counters.
- Fixed pending reservations/admission/release and finite-time validation; updated
  admission-boundary assertions. Final suite: **75 PASS, 0 FAIL, 0 ERROR**.

All test inputs are generated in memory. No network, browser, VM, dependency
download, or temporary-file fixtures are used. Tests cover forbidden/mixed DNS
sets, policy absence/malformation, both budget scopes and boundaries, threaded
byte accounting, frame contract/hash/lengths, header/record/PNG/frame-count caps,
configurable aggregate cap, every truncation point of a valid stream, invalid
headers/order/context claims/END, deadlines/source errors, and PNG structure.

### Batch 02 self-test

Using the same command above and the existing Python 3.15.1 installation:

- Before changes: **75 PASS, 0 FAIL, 0 ERROR, 0 SKIPPED**.
- After changes: **94 PASS, 0 FAIL, 0 ERROR, 0 SKIPPED** (75 existing + 19 new).
- New boundary tests exercise current-context-shaped IDs/positive epochs without
  importing S1, preserve the general UTF-8/epoch-0 transport API, carry provisional
  record JSON bytes unchanged, and retain metadata/hash/lengths and data-only
  summary accounting. They also cover gaps/duplicates/reversal, missing/partial
  END, unobserved EOF, trailing bytes, browser context claims, valid/corrupt PNGs,
  and individual/aggregate quota boundaries before rejected payload reads.
- The 1x1 PNG fixture is independently checked for chunk CRCs and its decompressed
  filter/RGB scanline, then passed through FrameReader. This fixture-specific
  decompression test does not extend S0's arbitrary-PNG validation guarantee.
- No production Python module, bridge field/value, limit or ID rule was changed.
  No S1 code was imported or tested, and no actual S0/S1 integration was attempted.

### Reusable offline fixtures (INT-06)

`tests/isolation/wire_fixtures.py` contains in-memory-only header/packet/END and PNG
builders. `png_1x1()` returns a complete 1x1, 8-bit RGB red PNG with IHDR, a real
zlib-compressed filter byte + RGB scanline in IDAT, IEND, and correct chunk CRCs.
Future Integrator wire fixtures can use these bytes directly as SCREENSHOT_PNG
payloads. This test helper imports no S1 module, writes no file and is not a
production encoder or an integration adapter. Existing configurable `png()` and
`png_chunk()` helpers remain available for malformed-image boundary fixtures.

When unittest discovers `tests/isolation`, it puts that directory on its import
path, so the local tests use `from wire_fixtures import ...`. A future integration
test harness must explicitly make this test-helper module available; importing
it does not establish an S0/S1 connection. Do not copy a signature-only synthetic
PNG from S1 into a successful S0 wire fixture.

Production policy/default selection, S1 integration, authenticated transport,
record meaning/CheckReport validation, actual DNS/network limit enforcement,
complete arbitrary PNG decoding, OS/browser/process isolation, and
LOCAL-ISOLATION remain unimplemented or unverified by this batch.

## Connector Slice 1 — SITEPROOF-LOCAL-ISOLATION-CONNECTOR-01

This additive contract describes `src.isolation.connector.connect_pinned`.
The earlier Batch 01/02 statements about a future connector are historical;
this slice adds an injected connection boundary, tested only with memory fakes.
It does not supply a DNS resolver, socket dialer, browser, proxy, TLS layer,
budget integration, or OS isolation. **LOCAL-ISOLATION remains UNVERIFIED.**
The existing destination/budget APIs and `siteproof.bridge.v0.1` are unchanged.

### Entry point and pinning

```python
from src.isolation.connector import connect_pinned

result = connect_pinned(policy, hostname, 443, resolved_addresses,
                        dialer=trusted_dialer)
if result.allowed:
    handle = result.handle  # Caller now owns it and must eventually close it.
```

- `policy` is the existing `DestinationPolicy`; `hostname` and the complete DNS
  answer tuple/list have the same meaning as in `check_destination`. The trusted
  caller must supply all answers. The connector cannot prove their completeness
  or provenance and never resolves a hostname itself.
- Entry accepts only an exact `int` equal to 443, excluding bool, float and
  string. All other ports return `PORT_NOT_ALLOWED` before destination validation
  or dialer invocation, even if the destination policy allows that other port.
  `check_destination` itself retains its existing configurable port behavior.
- A plain answer list is copied to a tuple before invoking the unchanged
  `check_destination` exactly once. Invalid containers remain invalid. Every
  answer must pass; no approved subset is dialed when any answer is forbidden or
  malformed. Destination rejection reasons are passed through unchanged.
- The resulting frozen `DestinationDecision` holds the canonical, deduplicated
  immutable address tuple. Its first address, preserving answer order, is selected
  once. Subsequent mutations of the supplied list cannot change that pin.
- `dialer(selected_ip, 443)` is invoked once, with exactly those two positional
  arguments. `selected_ip` is a canonical numeric IP string, never a hostname,
  URL, address list, or policy object. There is no default dialer, retry, second
  address attempt, re-resolution, redirect handling, or direct-connect fallback.

### Trusted dialer/handle boundary and ownership

`ConnectionHandle` is a structural protocol with `getpeername() -> tuple[str,
int]` and `close() -> None`. The pair must contain the actual numeric peer IP and
port reported by the trusted adapter, not an echo of the requested destination.
Only an exact two-element tuple is accepted. A future IPv6 socket adapter must
explicitly expose this pair; raw four-element socket addresses are not accepted.
IP strings are parsed numerically without DNS. Equivalent native IPv6 spellings
compare equal after canonicalization; scoped strings and ambiguous/non-numeric
addresses are invalid. The peer port must be a strict integer in 1..65535.

The dialer/adapter is trusted code. It must connect only to the supplied numeric
IP and port, without DNS, proxies, retries, redirects, or fallback, and must not
send application data before returning the handle for verification. This slice
cannot constrain arbitrary injected code or authenticate a fabricated peer report.
Synchronous calls cannot be interrupted by a connector deadline; a future adapter
must provide bounded dial/peer/close operations and cancellation.

Resource ownership follows this sequence:

1. Before the dialer returns, it owns any partial resources and must close them
   if it raises. No returned handle exists for the connector to close on a dial
   exception. The connector records `DIAL_ERROR` and makes no further attempt.
2. Once a handle is returned, the connector owns it while calling `getpeername`
   and checking the actual peer against the **selected IP and 443**. Another IP
   in the approved answer tuple is still a `PEER_MISMATCH`.
3. Malformed peer pairs return `INVALID_PEER`; peer-read exceptions return
   `PEER_ERROR`. A missing handle or a matching-peer handle without a callable
   close method returns `DIAL_INVALID_HANDLE`. An acquired handle is closed once
   on failure; the failed result never contains that handle. Missing/broken close
   methods are recorded as cleanup failures.
4. Only `ConnectorResult.allowed == True` / reason `ALLOW` transfers the exact
   returned handle to the caller. The connector does not close it on success.
   The caller owns subsequent use and closure. A positive nested destination
   decision alone is insufficient: dial/peer verification can still have failed.

`ConnectorResult` is frozen and contains `allowed`, `reason`, `destination`,
`selected_ip`, `handle`, `error`, and `close_error`. Before destination validation,
`destination` is None; before selection, `selected_ip` is None. `error` records
the ordinary dial/peer exception's class name; `close_error` independently records
the cleanup exception's class name. Exception messages are not copied. A close
failure does not replace the primary rejection reason or establish that the
resource was released. No cleanup retry or successful ownership transfer follows.

Non-`Exception` interruptions during peer verification cause a close attempt,
then propagate the original interruption. If close fails, its exception class
is attached as an exception note (`connector close failed: <class>`). An
interruption from close is recorded as a cleanup failure rather than hiding the
original peer failure. Dialer interruptions propagate with partial-resource
ownership remaining in the dialer. These paths were tested on Python 3.15.1.

### Slice 1 offline verification

The 33 new memory-only tests cover IPv4/IPv6, canonicalization and first-address
selection, strict 443 entry, unchanged policy/hostname/full-answer rejection,
immutable pins and input mutation/rebinding, exact selected-peer/port checking,
malformed peers, dial/peer exceptions, cleanup failures, interruptions, ownership,
and validation/dial/peer/close ordering with no retries or alternate-IP attempts.

Verification uses the existing Python 3.15.1 installation with `-B`, without
package acquisition. The dedicated output directory was verified absent before
creation and empty before use:

```text
%TEMP%\siteproof-connector-01-74076deec13746438cbbf9d383179ed0
```

PowerShell sets TEMP/TMP there; the temporary `run_offline.py` runner sets
`tempfile.tempdir`, discovers core/storage/isolation/integration separately, asserts exactly 310
existing tests, and excludes only the newly added `test_connector` module from
that existing-test count. No existing tests are removed, skipped, or relaxed.
Python audit hooks reject socket/network calls, process launches, and observed
file/SQLite writes outside the dedicated directory. Existing storage/integration
fixtures retain their per-test temporary SQLite/artifact directories within it.
This is test containment evidence, not production OS isolation.

The initial baseline run had 0 FAIL, 21 ERROR, 0 SKIPPED because the temporary
audit runner misinterpreted read-only SQLite `file:` URIs as ordinary paths.
After correcting URI parsing in the temporary runner only, the unchanged baseline
passed all 310 tests (63 core + 112 storage + 94 isolation + 41 integration).
The final new-test run passed 33 tests with 0 FAIL, 0 ERROR, 0 SKIPPED.
After implementation, the final existing-test regression again passed all 310
tests with 0 FAIL, 0 ERROR, 0 SKIPPED. Together these runs verify 343 tests.

Actual test invocations (PowerShell; each run sets TEMP/TMP to the directory above):

```powershell
$testRoot = '%TEMP%\siteproof-connector-01-74076deec13746438cbbf9d383179ed0'
$env:TEMP = $testRoot
$env:TMP = $testRoot
& '<python-3.15>' -B (Join-Path $testRoot 'run_offline.py') existing
& '<python-3.15>' -B (Join-Path $testRoot 'run_offline.py') new
```

Actual runs redirect output to distinct log files under that directory. Neither
real DNS/socket/browser/VM/AWS execution nor production dialer/TLS/budget/bridge
integration is implemented or verified by this slice.

## CONNECT/DNS boundary — Slice 2 (offline only)

`src.isolation.connect_dns.open_connect_target` preauthorizes a CONNECT authority,
checks an explicitly injected trusted resolver report, and calls the unchanged
Slice 1 connector with its entire ordered address tuple. No resolver, socket
dialer, CONNECT listener, HTTP response, TLS, browser, VM, or budget integration
is supplied. **LOCAL-ISOLATION remains NOT VERIFIED.**

### Authority and shared preauthorization

`check_connect_authority(policy, authority)` accepts an exact `bytes` value
containing only ASCII `hostname:443`, not a request line, headers, or an HTTP
message. Its 257-byte cap is derived from the existing 253-character DNS hostname
limit plus `:443`. It checks size before decoding and requires exactly one colon
and the literal port spelling `443`. Missing ports, `0443`, `+443`, whitespace,
non-ASCII text, URLs, userinfo, paths, query/fragment/percent forms, IP literals,
and control characters are rejected, not repaired. The existing hostname rules
apply; only ASCII case folding is performed. There is no stripping, trailing-dot
removal, or IDNA conversion.

`src.isolation.destination.check_authority(policy, hostname, port)` is the shared
policy/hostname/port validator extracted from `check_destination`. Its frozen
`AuthorityDecision(allowed, reason, hostname, port)` has no IP addresses; ALLOW
permits resolution only. Every policy entry is validated, including unused ones.
`check_destination` reuses this helper and preserves its existing decision type,
validation priority, reasons, fields, configurable ports, and all-IP checks.
The new CONNECT entry alone restricts ports to 443. No IP classification logic
is duplicated in `connect_dns.py`; the original destination layer still owns it.

Malformed/non-allowlisted authorities and missing/malformed policies produce
neither resolver nor dialer calls. A future HTTP receiver must separately validate
CONNECT method, HTTP version, header sizes/Host consistency, body and trailing
data, authentication, cancellation, and response handling.

### Trusted resolver report and limits

The resolver is mandatory and provides
`resolve_complete(canonical_hostname) -> DnsResolution`. It is called once per
accepted request, after preauthorization. No default resolver, cache, retry,
re-resolution, alias-based authorization, or direct-connect fallback exists.

`DnsResolution` is frozen and has exactly these fields:

| Field | Meaning |
| --- | --- |
| query_hostname | Exact canonical hostname requested; an alias or differently spelled name is not accepted |
| status | Plain string: COMPLETE, TIMEOUT, ERROR, or INCOMPLETE |
| a_complete | Actual bool indicating terminal A resolution, including terminal NODATA |
| aaaa_complete | Actual bool indicating terminal AAAA resolution, including terminal NODATA |
| addresses | Exact tuple of plain strings: the entire ordered answer set from that resolution |

Only an exact `DnsResolution` with COMPLETE, both completion flags True, and a
nonempty tuple can reach the connector. A completed family with NODATA contributes
no address; the other family may supply all addresses. Empty combined answers,
partial/truncated results, unknown/malformed status, invalid flag/container/member
types, or query mismatch are rejected before dialing. Any reported non-COMPLETE
status fails closed even if some addresses were returned. Resolver TimeoutError
becomes DNS_TIMEOUT; other ordinary exceptions become DNS_ERROR. Only exception
class names are recorded, not messages. Non-Exception interruptions propagate.

The trusted resolver must obtain both A and AAAA terminal results, correctly
follow or reject bounded CNAME chains, check RR-family consistency, and report
all results without silently omitting errors or truncating/filtering answers.
"Complete" refers to its observed resolution operation, not every IP a rotating
DNS service could ever return. Completion flags and a matching query label are
trusted reports, not authentication or proof of completeness, freshness, or DNS
provenance. No TTL/cache/freshness assertion is introduced here. Synchronous
resolver calls cannot be interrupted by this wrapper; a real adapter needs its
own deadline and cancellation.

`DnsLimits(max_answers, max_answer_chars)` requires explicit positive strict
integers; no production defaults are selected. The count and sum of raw string
lengths are checked before connector/IP validation. Duplicate answers count
towards both limits. Exceeding either rejects the entire result without slicing,
deduplicating, sorting, or consuming an unbounded iterator. These checks bound
accepted input, not memory already allocated by a trusted resolver or total
process memory. Invalid limits at the entry fail before resolver invocation.

### Connector result, rebinding, and ownership

After all preceding checks, `connect_pinned(policy, canonical_hostname, 443,
resolution.addresses, dialer=dialer)` is called exactly once. Its unchanged
destination checks reject the whole tuple if any IP is malformed or forbidden;
no approved subset is dialed. Slice 1 selects the first canonical unique answer
in original order and verifies the selected IP and port, not merely membership
in the approved set. A new request reauthorizes and resolves anew. A later
forbidden set is rejected; a later complete, permitted public set may succeed.
No earlier approval or cross-request IP pin is cached.

`ConnectDnsResult(reason, authority, connector, error)` is frozen. Before connector
invocation, `connector` is None. Its `allowed` property derives solely from the
actual nested ConnectorResult; positive authority/DNS/destination decisions never
override a dial/peer failure. The original ConnectorResult, reason, error and
close_error remain unchanged. DNS exception class names occupy the wrapper's
error field; connector diagnostics stay on the nested result.

The wrapper does not acquire, close, repair, or replace connection handles.
Only successful connector completion transfers its handle to the caller, which
must eventually close it. Connector failure cleanup, cleanup failure reporting,
partial dial-resource ownership, and interrupt propagation are unchanged. Arbitrary
injected resolver/dialer code remains trusted and cannot be constrained by this
pure orchestration layer.

### Slice 2 evidence levels

The contracts above describe implemented offline orchestration. Fake-only tests
exercise parser/policy boundaries, resolution reports/limits, full-tuple delegation,
pinning, errors, ownership, and request-to-request changes. Actual test results
and commands are recorded separately in the dedicated Stage 2 temporary evidence
directory after execution. No prior count is promoted to a new test result.
Real DNS/socket/Proxy/Browser/VM behavior and resource/time guarantees remain
unverified. v0.7 remains NOT ADOPTED / NOT FROZEN; PF-05 OPEN, formal T01-T21
UNKNOWN, LOCAL-ISOLATION NOT VERIFIED, AWS LIVE NO-GO remain unchanged.

Stage 2 self-test on the Slice 2 worktree, based on
`48a65263a030f1f047136dbadd478c2e9edcb05b`:

- New fake-only `test_connect_dns` methods: **44 PASS**, 0 FAIL/ERROR/SKIPPED.
- Existing regression: **343 PASS** (core 63, storage 112, isolation 127 including
  the existing 33 connector tests, integration 41), 0 FAIL/ERROR/SKIPPED.
- Total: **387 PASS**, with each selected test method run once; no test failure,
  retry, existing-test edit, deletion, skip, or expectation relaxation.
- Both invocations used the existing local Python installation with `-B` from
  `<projects>\siteproof-connect-dns-01`, with TEMP/TMP and
  `tempfile.tempdir` directed to this newly created dedicated directory:

```text
%TEMP%\siteproof-connect-dns-01-0833ac6f67e8452d8685bf3952c3a537
```

The copied temporary audit runner was inspected and changed to require this
worktree/root. It rejects socket/network events, process launches, and observed
file/SQLite writes outside that directory; bytecode writing is disabled.
`new-01.stdout.log` and `existing-01.stdout.log` retain the complete test results,
with separate stderr logs and command/exit/count JSON records. No prior evidence
was overwritten. This audit is test containment, not production OS isolation.

Actual invocations after setting TEMP/TMP and PYTHONPATH to the paths above:

```powershell
& '<python-3.15>' -B (Join-Path $testRoot 'run_offline.py') new
& '<python-3.15>' -B (Join-Path $testRoot 'run_offline.py') existing
```

These results establish offline acceptance of this slice only. Real resolution,
CONNECT/HTTP interoperability, authenticated peers, deadlines, packet paths,
browser/VM isolation, and live budget enforcement have not been measured.

## Quota / admission — Slice 3A (offline only)

Task: `SITEPROOF-LOCAL-ISOLATION-QUOTA-3A-01`. This adds an explicitly owned
Job session and bounded synchronous fake I/O. `connector.py`, `connect_dns.py`
and `destination.py` are unchanged. Earlier statements about absent budget
integration remain historical: this slice integrates the injected boundaries,
without supplying a real resolver, dialer or transport.

### Shared budget and compatibility

One trusted Job owner constructs one `NetworkBudget(job_limits, tunnel_limits,
clock=...)` and one `QuotaSession(job_id, budget, IoLimits(max_chunk_bytes,
max_buffer_bytes))`. All quota, chunk and buffer values are mandatory trusted
configuration; there are no newly selected production defaults. The legacy
`attempt_limits` argument now serves as that Job owner's aggregate limit.
Multiple named tunnels and their connections consume the same aggregate.
The budget binds once to a nonempty Job ID; a second session owner is rejected.

Existing BudgetLimits, BudgetDecision, positional constructor arguments,
`open_tunnel`, `begin_connection`, `connected`, `transfer`, `close_connection`,
`poll` and the original five snapshot fields remain available. Legacy
accounting-only connections still release occupancy on scope termination, as
described above. New `begin_connection(..., retain_on_stop=True)` instead keeps
pending/established resource occupancy until the owner confirms closure with
`close_connection`. All session admissions use this retained path. That close
method returns `IN_FLIGHT` without releasing a connection with active byte
tokens. It does no real close itself and must not be used to assert release of
an unconfirmed resource.

New budget entry points:

| API | Meaning |
| --- | --- |
| `bind_job(job_id)` | Bind this budget to one Job; reject another Job |
| `reserve_bytes(connection_id, *, job_id, tunnel_id, direction, operation, requested)` | Return frozen ByteGrant with a bounded ByteReservation, WOULD_BLOCK, or terminal denial |
| `settle_bytes(token, *, job_id, tunnel_id, connection_id, direction, operation, actual)` | Consume the exact issued token once; actual is an integer in 0..amount, or None for unknown progress |
| `poll_bytes(connection_id)` | Detect committed byte exhaustion independently of buffer contention |
| `stop(reason)` | Keep the first Job termination; retain managed occupancy and all issued byte tokens |

The frozen token identifies Job, tunnel, connection, direction (`send` or
`receive`), operation and granted amount. Exact issued-object identity also
binds it to this budget. Copied/foreign tokens, duplicate live operation IDs,
double settlement, mismatched scopes and invalid/oversized actual reports raise
ValueError without consuming the original token. Settlement is permitted after
stop and does not recheck the deadline; the started operation must still be
accounted for. Unknown progress consumes the entire reservation as uncertain.

Snapshots append `confirmed_bytes`, `uncertain_bytes`, `reserved_bytes` and
`pending_connections`. `total_bytes = confirmed_bytes + uncertain_bytes`.
Under the single shared RLock, both Job and tunnel always satisfy:

```text
confirmed_bytes + uncertain_bytes + reserved_bytes <= configured total_bytes
```

`transfer` and reservations select mutually exclusive byte-accounting modes per
connection, preventing the same connection from using both paths. Different
connections may use different modes: legacy transfer includes all outstanding
reservations in its capacity check, with temporary contention returning
WOULD_BLOCK without charging or stopping. A committed hard breach in either
scope takes priority over temporary contention in another scope. Legacy-only
behavior and the original tests remain unchanged.

### Admission, ownership and result preservation

`session.open_tunnel(name)` opens a scope. `session.connect(tunnel, policy,
hostname, addresses, dialer=...)` delegates to the existing pinned connector.
`session.connect_target(tunnel, policy, authority, resolver=..., dialer=...,
limits=DnsLimits(...))` delegates to the existing CONNECT/DNS entry point.
Validation/resolution precede dial admission. Immediately before the injected
dialer is invoked, the session reserves a concurrency slot and cumulative
connection capacity and consumes an attempt. A failed attempt is not refunded.

```text
validation / DNS -> admitted DIALING (pending occupancy)
                -> returned handle / PEER_VERIFYING (cumulative establishment)
                -> CONNECT_READY, or REJECTED + connector cleanup
```

Every non-None returned handle consumes an establishment, even if its peer or
adapter is subsequently rejected, or if the Job stopped during dial. Peer
rejection never decrements cumulative establishments. Dial exceptions retain
the original connector ownership contract: the dialer owns partial resources
and must clean them before raising. An interruption without confirmed cleanup
conservatively keeps the pending slot.

A connector-facing facade observes peer cleanup while forwarding peer/close
calls to the exact raw resource. The unchanged connector owns this facade until
success, then transfers that exact facade to the session. Missing/non-callable
raw close methods still follow the connector's original invalid-handle path.
A non-None raw close return is treated as unconfirmed, with `_CloseUnconfirmed`
recorded in the connector's close_error field. This does not replace its primary
failure. The session alone owns subsequent raw I/O and cleanup; callers must not
use returned diagnostic handles or direct Budget calls to bypass that owner.

`SessionConnectResult(allowed, reason, connection_id, result)` wraps the original
ConnectorResult or ConnectDnsResult without reconstructing or dropping nested
destination/authority/selected-IP/error/close_error information. Session-level
denial is authoritative. Every original result is also retained verbatim in the
owner's private `_results` evidence list. A late original success contains an
owned handle, so it is retained privately and its public `result` is None; it is
never published as ready or reused. Public success publication is linearized
under the shared lock after the final stop check. CONNECT_READY only describes
this fake boundary, not a transmitted HTTP CONNECT response.

### Bounded fake I/O and stop transitions

The raw injected stream supplies `write(bytes)->int`, `read(n)->bytes` and
`close()->None`. `session.write(connection_id, nonempty_bytes)` passes only the
granted prefix, bounded by remaining Job/tunnel quota and max_chunk_bytes.
`session.read(connection_id, positive_size)` additionally bounds the requested
read by free Job-wide max_buffer_bytes, including space reserved for concurrent
reads. Pending client-delivery bytes remain bounded across all connections.
One connection serializes read/write/delivery; different connections can proceed
concurrently. Reservation marks an operation started under the lock; the actual
adapter call and all cleanup calls occur outside it.

Partial success confirms only the returned byte count and releases the unused
reservation. Reads append accepted bytes to the session's bounded undelivered
buffer. `session.deliver(connection_id, writer)` sends a bounded prefix of this
already charged buffer, retaining any undelivered suffix without charging it
again. Delivery can drain received bytes at the exact upstream byte limit;
further upstream I/O is rejected before calling the adapter. Buffer pressure,
another operation's temporary reservation, and an explicit no-progress
`IoWouldBlock` return WOULD_BLOCK without stopping. EOF reads and zero writes
consume no payload bytes. Generic exceptions, including BlockingIOError, do not
certify zero progress: they charge the full reservation as uncertain and stop.
Only the explicit trusted IoWouldBlock contract certifies zero progress.

Invalid write counts, oversized/non-bytes read results and invalid delivery
counts stop with ADAPTER_VIOLATION. An invalid upstream report consumes the full
token as uncertain and no oversized data is retained. Client delivery exceptions
stop without recharging previously received bytes or retrying an uncertain
delivery. Non-Exception interruptions settle upstream reservations, attempt
cleanup and propagate the original interruption.

Quota denial, adapter violation, explicit `stop(reason)`, and existing
poll/deadline/invalid-clock judgments record the first stop reason and prohibit
new admission and additional I/O. Any expired idle tunnel found by the existing
Budget poll also stops this Job owner. No new timer is introduced.

```text
RUNNING -> STOPPED (first reason retained)
started dial / I/O -> keep occupancy / tokens -> late result -> settle once
owned idle handle -> IN_PROGRESS close -> SUCCEEDED / FAILED / UNCONFIRMED
```

`connection_state(id)` exposes phase, cleanup, cleanup_error, in_flight and
buffered_bytes; `stop_reason` exposes the first reason. In-flight dial/peer/I/O
is not force-closed. Cleanup is attempted after the operation returns; a close
blocked in progress retains occupancy. A normal None close return confirms
release and frees the slot; exceptions are FAILED, and non-None returns are
UNCONFIRMED. Failed/unconfirmed closes are not retried or treated as released.
Connector-observed peer cleanup, including interruption cleanup, is not repeated.
Cleanup failure never replaces an earlier stop/connector/I/O reason. Stops
discard undelivered data when cleanup can safely proceed. `poll()` only applies
the existing clock checks when called; it is not a scheduler.

### Offline verification and limits

Final Slice 3A new fake tests: **83 PASS**. Existing regression: **387 PASS**
(core 63, storage 112, isolation 171, integration 41), counted separately.
Each final selection has 0 FAIL, 0 ERROR, 0 SKIPPED, 0 expectedFailures and
0 unexpectedSuccesses; total **470 distinct test methods**. Events/barriers
control delayed dial/I/O/close and concurrency without sleeps. The initial
66-test run and subsequent 80- and 81-test runs also passed; their outputs are retained
separately and are not added to the final distinct-test count.

Fresh dedicated temporary evidence directory (verified absent before creation):

```text
<scratch>\siteproof-quota-3a-01-d908b11129804fa5a186771e4c79ffb4
```

Actual final invocations from the authorized worktree, with TEMP/TMP set to that
directory and RUN_ID set to `04` for new and `03` for existing:

```powershell
& '<python-3.15>' -B (Join-Path $quotaEvidence 'run_offline.py') new
& '<python-3.15>' -B (Join-Path $quotaEvidence 'run_offline.py') existing
```

`new-04.stdout.log`, `existing-03.stdout.log`, matching stderr logs and JSON
records retain test identities, group counts, commands/interpreter and exits.
The dedicated runner asserts both suite counts and zero failures/errors/skips/
expectedFailures/unexpectedSuccesses. Its audit hook rejects socket/network
events, subprocess launches and observed file/SQLite writes outside this fresh
directory; bytecode writing is disabled. This audit is test containment evidence,
not a production isolation guarantee. Existing tests and prior evidence are
unchanged; no packages were obtained and no external communication was used.

All guarantees concern trusted injected fake adapters and I/O payload accounting.
They do not prove actual TCP/IP transfer volume, kernel-buffer memory, process
memory, DNS completeness/provenance or AWS charges. There is no actual socket,
TLS, proxy listener, Browser, VM, OS isolation, deadline enforcement, cancellation,
forced interruption or async relay. A synchronous dial/read/write/close may remain
blocked indefinitely, retaining its reservations/occupancy. Slice 3B monitoring
and real transport remain unimplemented/unverified. v0.7 remains NOT ADOPTED /
NOT FROZEN; PF-05 OPEN, formal T01-T21 UNKNOWN, LOCAL-ISOLATION NOT VERIFIED and
AWS LIVE NO-GO remain unchanged.

### Slice 3A bounded Major fix — FIX-01

`SITEPROOF-LOCAL-ISOLATION-QUOTA-3A-FIX-01` changes only the two reviewed
Major issues. No Connector/DNS implementation, public Result fields, production
defaults, transport, deadline monitor or cancellation behavior is added.

- Legacy transfer now selects its byte-accounting mode only after the shared
  capacity check allows the transfer. A WOULD_BLOCK rejection leaves modes,
  counters and live tokens unchanged. Releasing the blocking reservation permits
  a later reservation on that previously rejected connection. Successfully
  accepted legacy transfers still exclude reservation accounting on that same
  connection; existing quota/deadline denial reasons and stop behavior remain.
- The session explicitly retains Connector ownership from facade handoff until
  it receives a successful Result. The facade records close-attribute lookup
  errors, including BaseException, without executing the lookup under the lock.
  After a peer interruption, an unobserved Connector close outcome becomes
  UNCONFIRMED with its lookup diagnostic. Session cleanup excludes these
  Connector-owned resources; it neither re-fetches close nor retries it. Only
  directly observed successful cleanup releases occupancy. Exception notes are
  preserved on the original propagated interruption, never interpreted as proof
  of close success or physical resource termination. Successful Result handoff
  restores session cleanup responsibility, including stopped/late success. A raw
  handle acquired before facade handoff also remains the session's responsibility.

Four added test methods are selected independently of the unchanged original
83 Slice 3A tests and 387 earlier regression tests:

| Selection | Methods | Final result |
| --- | ---: | --- |
| major1 | 1 | PASS |
| major2 | 3 | PASS |
| slice3a | 83 | PASS |
| existing | 387 | PASS |

The 474 distinct final methods have 0 FAIL, ERROR, SKIPPED, expectedFailures and
unexpectedSuccesses. The Major 1 test compares modes, both scopes' snapshots,
tokens and operations before/after rejection, then verifies a later legal
reservation. Major 2 tests check the original interruption identity and note,
single close lookup, no raw retry, UNCONFIRMED/error state, held occupancy and
denied new admission. They also cover missing/non-callable close, SystemExit
during lookup, and session cleanup before facade handoff. The existing 83-test
source prefix is byte-for-byte preserved; original test IDs select both regression
suites without deletion, skip, relaxation or duplicate accounting.

The new tests were first run against the reviewed, unfixed production files.
That deliberate reproduction produced major1: 1 method / 1 failure entry, and
major2: 3 methods / 4 failure entries (one main failure plus three subtest
failures; the pre-handoff control passed). Both had 0 ERROR/SKIPPED/
expectedFailures/unexpectedSuccesses. These are actual pre-fix FAIL records,
separate from the all-PASS final runs; no expectedFailure annotation was used.
The implementation was then corrected once and all four final selections passed
on their first post-fix execution, with no intervening test expectation changes.

Fresh dedicated evidence root:

```text
<scratch>\siteproof-quota-3a-fix-01-1c43900a925a47b0a9f78c22c950f5cb
```

`start-gate.json`, `before/` and `before-tracked.diff` preserve the reviewed hashes,
four pre-fix sources and tracked diff. `*-before-01.*` retain the two reproduction
runs; `*-final-01.*` retain the four final selections. JSON records include test
IDs, source hashes at run time, interpreter, arguments and exit/counts. The runner
uses the existing Python 3.15 installation with -B and the same offline/file-write
audit policy as Slice 3A, with TEMP/TMP and tempfile.tempdir directed only here.
Actual invocations, also recorded in `final-commands.ps1`, are:

```powershell
$env:TEMP = $fixEvidence
$env:TMP = $fixEvidence
$env:RUN_ID = 'final-01'
& '<python-3.15>' -B (Join-Path $fixEvidence 'run_offline.py') major1
& '<python-3.15>' -B (Join-Path $fixEvidence 'run_offline.py') major2
& '<python-3.15>' -B (Join-Path $fixEvidence 'run_offline.py') slice3a
& '<python-3.15>' -B (Join-Path $fixEvidence 'run_offline.py') existing
```

Prior evidence is retained without overwrite/deletion. This fix does not promote
the earlier fake-only guarantees to real DNS/socket, bounded wall-clock cleanup,
deadline/cancel, Browser/VM isolation, TCP/IP/kernel-buffer or AWS-cost guarantees.

### Slice 3B cooperative termination

This section supersedes the historical Slice 3A statements that cooperative
deadline monitoring/cancellation remain unimplemented. It adds no real transport.

`QuotaSession(..., termination_limits=TerminationLimits(connection_timeout_seconds,
idle_timeout_seconds))` enables the two additional timeouts. Both values must be
explicit, positive and finite; there are no production timeout defaults. Omitting
this keyword preserves the legacy constructor and its Budget-only deadlines.
Job and tunnel absolute durations remain the explicit `BudgetLimits` values.
The Job origin is the original `NetworkBudget` construction time, never session
construction. The tunnel origin remains its original `open_tunnel` time.

The session shares the existing Budget lock and injected monotonic clock. It
uses Budget's private `_last_time` after its clock/deadline validation; no Budget
public API, independent clock or duplicate Job start is introduced. Invalid or
backwards clocks retain Budget's `INVALID_CLOCK` behavior. Every timeout expires
at equality (`elapsed >= limit`). In one check the order is existing Budget
termination/deadlines (including tunnel absolute lifetime), then connection
timeout, then idle timeout. The first stop reason committed under the shared
lock wins, including cancellation races, and stops the entire Job.

Connection timing starts before authorization/DNS and remains pending through
dial, peer verification and the final locked success-publication check. A late
DNS result must pass admission again before dial. Pending DNS is tracked even
before a connection reservation/ID exists. A delayed successful handle is
retained in internal diagnostics and cleaned by its owner, never published as a
successful session result after stop. Connector's existing validation/cleanup
protocol retains ownership until Result handoff; the session does not retry its
close or bypass its diagnostics.

Idle timing starts at successful publication and is per connection, shared by
both directions. Only confirmed positive read/write/deliver completion while
still RUNNING refreshes it. Completion first checks termination; an operation
returning at the expired boundary cannot rescue the connection. Reservations,
polls, zero-byte completions, EOF and WOULD_BLOCK never refresh idle. Late I/O
settles its original reservation exactly once, including uncertain accounting on
errors, but neither extends idle nor publishes a read buffer. Delivered bytes
are already charged and are never charged again.

| API | Return and responsibility |
| --- | --- |
| `request_cancel()` | `None`; records `CANCELLED` unless already stopped; no clock read, cleanup or adapter call |
| `check_termination()` | First reason or `None`; checks deadlines and records stop, without waiting for cleanup |
| `run_cleanup()` | `None`; attempts eligible session-owned closes outside the lock; synchronous close may block |
| `termination_snapshot()` | Frozen `TerminationSnapshot`; observational, no clock read, stop or cleanup |
| `stop(reason)` | Existing `None` return and synchronous eligible cleanup retained |
| `poll()` | Existing first-reason-or-`None` return and eligible cleanup retained; now also checks configured connection/idle timeouts |

Snapshots include state/reason, pending CONNECT count, in-flight I/O count,
reserved bytes, occupied connections, buffered bytes, unconfirmed handle count
and cleanup-in-progress count. Cleanup error/phase details remain available via
the unchanged `connection_state`; quota and original Result diagnostics remain
available through their existing paths.

| State | Meaning |
| --- | --- |
| RUNNING | No stop reason recorded; no claim about unobserved expiry |
| STOPPING | Stopped with pending CONNECT, I/O, close, unsettled token, buffer or otherwise outstanding occupancy/handle |
| CLOSE_UNCONFIRMED | No pending operation/token remains, but a failed/unconfirmed resource close retains occupancy |
| CLOSED | Stopped and all managed resources, reservations, buffers and occupancy confirmed released; does not mean Job success |

Pending operations take precedence over CLOSE_UNCONFIRMED in snapshots. Unknown
occupancy is never released by elapsed time. Each close is attempted at most
once, with existing Connector ownership and close-lookup failure rules intact.
In-flight I/O or any live reservation on that connection defers session close;
after settlement, cleanup may be explicitly run again without retrying a close.
Non-None close results, errors and interrupted/unknown dial outcomes retain
occupancy. Confirmed `None` close releases it. Buffered data is retained while
an operation still uses it and discarded when stopped cleanup can safely run.

No new connect/read/write/delivery is admitted after stop. While RUNNING,
existing EOF and buffer-drain behavior remains: EOF alone does not stop a Job or
turn it into successful bidirectional EOF completion. No half-close or relay loop
is added.

Offline verification uses injected clocks, fake resolvers/streams/handles and
Event/Barrier ordering. **51 distinct new 3B methods PASS**, separately from
**474 unchanged existing methods PASS**, including all four Major fix methods.
Final selections each have 0 FAIL, ERROR, SKIPPED, expectedFailures and
unexpectedSuccesses. No existing test was edited, removed, skipped or relaxed.
Distinct test IDs, hashes and complete outputs are retained in:

```text
<scratch>\siteproof-termination-3b-01-03ac68b47ad84dac9d86cc822bb60a4b
```

Final commands from this worktree (the runner directs TEMP/TMP/tempfile here):

```powershell
$terminationEvidence = '<scratch>\siteproof-termination-3b-01-03ac68b47ad84dac9d86cc822bb60a4b'
& '<python-3.15>' -B (Join-Path $terminationEvidence 'run_offline.py') new final-01
& '<python-3.15>' -B (Join-Path $terminationEvidence 'run_offline.py') existing final-01
```

`new-final-01` and `existing-final-01` stdout/stderr/JSON files are final evidence;
earlier attempts are not added to the distinct-test totals. Initial harness
discovery/import attempts did not execute tests; an initial existing run had
21 ERROR entries from the harness misclassifying SQLite file URIs. The harness
now resolves file URIs before enforcing the same fresh-directory restriction.
Those initial error logs are retained without overwrite. The audit hook denies
network/socket and subprocess operations and confines observed file/SQLite
writes to this fresh directory; bytecode writes are disabled. This is test
containment evidence, not a runtime sandbox guarantee.

Synchronous DNS/dial/read/write/close cannot be forcibly interrupted and may
block indefinitely. Expiry observation requires a check; no timer/scheduler or
physical completion deadline is promised. Real DNS/socket/TLS, transport,
bidirectional normal EOF completion and Docker/Windows/macOS/Linux/AWS Runtime
PASS remain unimplemented or unverified. Prior project isolation/adoption/AWS
status and evidence remain unchanged.

## Real TCP transport — SITEPROOF-LOCAL-TRANSPORT-01

`transport.py` adds an explicit, single-use `ConnectTransport` with a listener
bound only to `127.0.0.1:0`. It requires an existing Job `QuotaSession`, policy,
resolver, `DnsLimits`, `TransportLimits` and session `TerminationLimits`. All
limits are caller-supplied; no production byte/time/concurrency values are chosen.
`start()` returns the selected listener address. `cancel()` records Job cancel;
`stop()` waits up to the configured shutdown timeout and returns whether managed
threads and session resources have actually finished. A false return is not PASS.

The production opening path calls the unchanged `connect_target`: exact permitted
ASCII hostname:443, complete A/AAAA report, whole-answer address checks, numeric
IP pinning and actual peer verification. Loopback/private/link-local/reserved
denials remain unchanged. `SystemResolver` uses OS `getaddrinfo` for both families;
it makes no authenticity/freshness claim. `SocketHandle` adapts a nonblocking TCP
socket. The dialer accepts only numeric IPs and never retries another IP/path.

HTTP parsing accepts CONNECT HTTP/1.1 with exactly one matching Host. It rejects
duplicate/malformed headers, bodies, transfer encoding and early tunnel bytes.
Header bytes and total read time are bounded. A 200 response follows successful
upstream connection and peer validation only. The relay does not decrypt TLS.
Both upstream payload directions pass through shared QuotaSession reservations;
delivery of already charged bytes does not charge them twice. This counter does
not cover handshake bytes, TCP overhead, OS buffers, HTTP request counts or
individual HTTP response sizes. Incoming client buffering is bounded by the
configured chunk size per accepted worker. Accepted workers and outstanding DNS
workers are independently bounded by `max_clients`.

The additive `QuotaSession.finish_connection(cid)` retires a quiescent connection
without cancelling other tunnels. It preserves cumulative counts/bytes, releases
occupancy only after confirmed close and returns False while I/O is in flight or
close is unconfirmed. Existing API signatures and policy contracts are unchanged.
The transport closes both directions on the first EOF; graceful TCP half-close
draining is not implemented. Quota, idle/Job deadlines and cancellation stop
admission/forwarding and close owned sockets without direct-network fallback.
Nonblocking socket waits check deadlines/cancel at the configured polling cadence;
this is not a real-time scheduling guarantee.

**DNS limitation:** Python cannot forcibly interrupt a running OS `getaddrinfo`.
The caller stops waiting on timeout/cancel and never dials a late result, but a
bounded daemon resolver worker may remain until the OS call returns. Further DNS
work is refused when worker capacity is occupied. `stop()` reports False while a
resolver is still alive. No unconditional physical DNS cleanup deadline is claimed.

### Loopback evidence and boundary

`tests/isolation/transport_fixtures.py` contains the only loopback upstream
capability: an exact `fixture.invalid:<dynamic-port>` and `127.0.0.1` endpoint.
Its test subclass replaces target opening, reuses DNS-result validation, session
admission and the numeric peer check, and retains the real parser/waiter/dialer/
relay/cleanup. It does not forge a public peer or alter production destination
policy. No production flag or environment-variable bypass exists.

Final new transport selection: 25 PASS, 0 FAIL/ERROR/SKIPPED. Selected existing
QuotaSession/termination regressions: 138 PASS, 0 FAIL/ERROR/SKIPPED. These are
distinct methods, not additions to the historical 1,154 count. Task-local T01..T10
in `test_transport.py` are not the formal project T01-T21 acceptance cases.
Initial failed test-harness attempts are not included as successful executions.

The suite audit hook refuses real getaddrinfo and non-127.0.0.1 binds/connects.
DNS answers are controlled by fixtures; the OS-resolver adapter is tested with
getaddrinfo replaced. TCP forwarding uses actual loopback sockets. Connect timeout
uses a real socket with controlled nonprogress in connect/select; no external
blackhole is contacted. Refusal, peer mismatch, shared concurrent byte quota,
connection limits, idle/Job/header deadlines, cancel, EOF and fail-closed stopping
are checked. Each test joins managed workers and confirms listeners/sockets,
occupancy, buffers and reservations are released; the delayed-DNS case explicitly
observes incomplete shutdown, then releases the controlled resolver and verifies
cleanup. No real external DNS/public upstream or Chromium/VM behavior was tested.

LOCAL-ISOLATION NOT VERIFIED; formal T01-T21 UNKNOWN; AWS Worker Pilot NO-GO;
v0.7 NOT ADOPTED / NOT FROZEN; C-02 DEFERRED / OPEN. Search Fabric's existing
Gates are unchanged. No OS/network/Firewall/VM/AWS changes are made by this module.
