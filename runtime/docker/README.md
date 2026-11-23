# SiteProof M2 controlled runtime validation

This is a fixture-only launcher and validation harness. It is not an arbitrary URL
runner, a production isolation attestation, or formal T01–T21 acceptance.

## Distribution provenance

- Base: official `mcr.microsoft.com/playwright/python:v1.64.1-noble`, pinned to
  `sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031`.
- Python Playwright 1.64.1 and required wheels come from PyPI. Build retains wheel
  SHA256SUMS. The execution evidence separately compares all four wheel hashes
  against official PyPI release metadata. Docker validates the base content digest;
  this does not claim an independent image signature verification.
- iptables, iproute2 and NSS tools use the image's signed Ubuntu repositories.
- `seccomp-playwright.json` is the official Playwright v1.64.1 distribution file:
  https://raw.githubusercontent.com/microsoft/playwright/v1.64.1/utils/docker/seccomp_profile.json
  SHA256 `cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849`.
  It is an unmodified copy of Microsoft's file (Copyright (c) Microsoft Corporation,
  portions Copyright 2017 Google Inc.), licensed under the Apache License 2.0:
  https://github.com/microsoft/playwright/blob/v1.64.1/LICENSE. See the repository
  NOTICE file.
- `seccomp-siteproof.json` is a MODIFIED derivative of that file (same Apache License
  2.0 and Playwright copyright for the unmodified parts; see NOTICE). It adds only the
  Chromium namespace sandbox's `chroot`
  syscall to that profile. Default action stays ERRNO. No capability is added to
  Browser: CapEff/CapBnd remain zero. A separate no-network probe verifies parent
  chroot is EPERM while chroot inside its own new user namespace succeeds.

## Boundary

All resources have the exact task label and a unique `siteproof-m2-` name. The
launcher records IDs and refuses name collisions. It never deletes resources.
Only its recorded labelled container IDs can be stopped. An internal Docker
network is an extra guard, not the enforcement proof.

Trusted Worker UID1001 owns the CONNECT transport and one dedicated test volume.
Browser UID1000 and local UI Browser UID1003 have separate containers, no Docker
socket, no Worker volume, read-only root, no capabilities, no-new-privileges,
bounded tmpfs, CPU, memory, PID and file descriptor limits. Only generated public
fixture CA and resolver configuration files are mounted read-only into Browser.

A short-lived helper with NET_ADMIN installs rules only in the new anchor's
verified network namespace. OUTPUT defaults to DROP for IPv4/IPv6. UID1000 can
connect only to the owned loopback proxy; UID1003 only to the local BFF port.
UID1001 can access controlled loopback fixtures. The helper exits before Browser.
Browser receives neither NET_ADMIN nor any host/WSL-global rule modification.

Before Chromium, the same UID/caps/seccomp/cgroups are tested with plain socket
processes. All forbidden canaries must have positive controls and zero forbidden
receive deltas. Proxy stop/restart is tested at the same owned port. Chromium then
repeats direct TCP/DNS/UDP/IPv6 and host/LAN/metadata-model attempts: protocol DROP
counters must increase and forbidden canary deltas must remain zero.

Host/LAN/metadata addresses are controlled models within this private namespace.
This is not a scan of real LAN services or AWS metadata. Loopback proxy wiring is
measured in the shared namespace, not assumed to work across distinct namespaces.

## Fixture behavior and IPC

The HTTPS fixture has a generated temporary certificate imported into the
disposable Browser NSS trust store. No ignore-HTTPS-errors switch is used. A
test-only mixin permits exactly `GET http://fixture.invalid:80` to one fixed local
HTTP fixture using the same QuotaSession and peer validation. Production CONNECT
and destination policies remain unchanged and HTTPS-only.

The Windows trusted launcher forwards bounded Browser stdout frames to Worker
stdin over Docker exec control pipes. S1 performs its normal independent frame,
PNG, digest, manifest and write-once validation. Browser has no direct file access
to S1. Control lines, output size and waiting are bounded. Timeout/cancel stop the
whole dedicated Browser container and verify PID0/stopped state.

Only the trusted starter handles pairing information; it is sent via stdin, never
URL or persistent output. UI Browser retains HttpOnly/SameSite cookies. Raw
Playwright form exceptions are suppressed because they can contain form secrets.
Local HTTP cookie port separation and malicious same-user/host processes remain
outside the guarantee.

## Execution

From the repository root, use the already installed Python explicitly:

```
python -B -m tests.runtime.build_image --evidence <task-evidence-directory>
python -B -m tests.runtime.validate --evidence <new-validation-directory>
```

Building is an explicitly authorized official distribution download phase. Runtime
containers cannot reach external networks. A validation directory preserves
preflight, protocol counters, canary results, sandbox status, cgroup values,
Desktop/Mobile evidence, UI results, resource IDs and shutdown confirmation.
Failed attempts are preserved separately. No automatic resource pruning, DB
repair, Git staging/commit, deployment or canonical-document update occurs.

The real-capture source label remains `REAL_CHROMIUM_FIXTURE_UNATTESTED`;
PROFILE_UNATTESTED and quality UNKNOWN are not upgraded by successful capture.
