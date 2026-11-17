---
project: BuildTrace
slug: buildtrace
owner: shellghostt
status: mvp
version: 0.1.0
language: Go 1.26
license: Apache-2.0
rank: 5
focus: Software supply chain
depends_on:
  - No runtime dependency (single static binary)
  - git (subprocess, for repository metadata only)
  - Sigstore (signing, M4)
  - GitHub Actions (first CI integration, M5)
created: 2026-11-13
updated: 2026-11-17
---

# BuildTrace — Implementation Plan

> **This file is the specification.** Section 9 defines exactly what verification proves and what it does
> not. Overclaiming here is not a marketing problem, it is a security problem.

---

## 0. Machine context

M2 is merged into `main`. M3 is **implemented and verified locally and in CI** on
`feat/m3-implementation`, unreleased, with review pending.
[M3 validation](testing/m3-provenance.md) maps the phase's acceptance gates to executed checks.
[ADR 0005](adr/0005-m3-unsigned-recorder-contract.md) and the
[versioned recorder contract](build-types/record/v1.md) define the unsigned operation.
The [development-tool audit](DEVELOPMENT-TOOLS.md) records actual coverage and profiling limits.

```yaml
project: BuildTrace
status: mvp
version: 0.1.0
builds: true
functional: partial            # metadata, hashing, unsigned manifest checks and provenance inspection

implemented:
  - repository skeleton
  - cli binary with manifest, verify --manifest, record, inspect and version
  - git metadata collector: commit, dirty state, normalised remote uri
  - toolchain and platform collector: go version, git version, os, arch, host
  - manifest model and deterministic serialiser (internal/manifest)
  - artifact collection: name, path relative to the repository root, size
  - allowlisted environment for the git subprocess; remote credentials stripped
  - pinned build timestamp via --built-at and SOURCE_DATE_EPOCH
  - unit tests and golden-file tests
  - streaming sha256 for files and canonical directory/symlink hashing
  - verify --manifest with kind, byte count and digest checks, offline
  - strict manifest v1 reader, stable JSON reports and tamper tests
  - 1 GiB memory gate, portable directory golden and parser fuzzing
  - unsigned in-toto Statement v1 and SLSA provenance v1 recorder
  - explicit source/time assertions, deterministic recording IDs and relative subjects
  - bounded offline inspect with unsigned_statement / inspected scope
  - two synthetic goldens and isolated pinned upstream format validation
  - native Windows race validation with a 64-bit UCRT64 compiler
  - passing Windows/Ubuntu/macOS CI race, offline schema, image, lint and security jobs

not_implemented:
  - signed-attestation verification -- M4
  - signing, dsse envelopes, sigstore -- M4
  - identity policy -- M4
  - github actions integration -- M5
  - sbom generation -- M6
  - reproducibility checks -- M6
  - dependency tracking -- M6

source_of_truth:
  scope_and_trust_model: docs/PLAN.md     # this file, sections 9 and 10
  architecture: docs/ARCHITECTURE.md
  decisions: docs/adr/
  manifest_format: internal/manifest/
  formats: pkg/intoto/                     # implemented standard-library-only M3 wire types
  status: README.md#roadmap

forbidden_claims:
  - "SLSA compliant" / "SLSA level N" / "certified"
  - "proves the artifact is safe"
  - "guarantees reproducibility"
  - verification without checking the subject digest against the artifact
  - authenticated original build history or builder identity from unsigned metadata
  - provenance verification from inspect or schema validation
  - a digest field in an M1 manifest: M1 does not hash anything

if_uncertain:
  - every field must map to a defined observation or explicitly identified caller assertion
  - state what can be recomputed and what needs independent evidence
  - if the implementation does not do it, the README does not say it
```

---

## 1. What this is

A CLI that records existing artifacts, checkout observations and explicit caller claims in unsigned
in-toto-compatible statements. M2 verifies artifact bytes against an unsigned manifest; signing and
authenticated identity policy remain M4.

One-line description: *An open-source build provenance and artifact verification system.*

The hard part is not producing JSON. It is making the JSON mean something: the subject digest must match the
artifact, the signature must belong to a known builder identity, and the inputs must be recomputable.

---

## 2. Problem and users

**Problem.** "This binary was built from commit `abc123`" is an assertion, not evidence. Once an artifact
leaves CI, nobody can independently check what produced it, with which dependencies, or whether it was
modified afterwards.

**Users.**

| User | Need |
|---|---|
| Maintainer | Publish an artifact with verifiable provenance |
| Downstream consumer | Verify provenance offline before deploying |
| Security team | A policy gate: only artifacts from our builder identity may reach production |

**M4 success looks like.** A consumer downloads a binary and an attestation, runs one command with a pinned
builder identity, and gets a pass or a specific failure reason — with no network access required.

---

## 3. Non-goals

- **Not a build system.** It records existing artifacts and metadata; it does not run arbitrary builds.
- **Not an artifact registry.** Storage is somebody else's job (release assets, OCI registry, S3).
- **Not a vulnerability scanner.** SBOM generation is supported; CVE analysis is not.
- **Not a transparency log service.** Sigstore's log may be used; we do not run one.
- **Not a policy engine for clusters.** It emits a verdict; admission control belongs to Kyverno/Gatekeeper.
- **No custom attestation format.** in-toto Statement v1 and the SLSA provenance predicate v1, or nothing.

---

## 4. Scope contract

### v0.1 — MVP (M1–M4)

`record` produces an unsigned in-toto statement; `manifest` remains the separate unsigned M2 format.
`verify --manifest` checks digests offline; M4 adds
Sigstore keyless signing and signature verification with an identity policy.

### v1.0 (M5–M6)

GitHub Actions integration, SBOM generation, reproducibility checks, multi-artifact bundles, v1.0.0.

### Post-1.0

GitLab CI, OCI attestation storage, policy files (YAML), builder identity allowlists, transparency log
lookup.

---

## 5. Locked decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Go, single static binary | Runs in minimal CI containers, cross-compiles for every runner |
| 2 | in-toto Statement v1 + SLSA provenance predicate v1 | A custom format makes output unverifiable by existing tools |
| 3 | DSSE envelope for signing | The in-toto ecosystem has standardised on it |
| 4 | SHA-256 only | One algorithm, no negotiation, no downgrade |
| 5 | Sigstore keyless at M4, local keys supported | CI identity comes from OIDC; air-gapped builds still work |
| 6 | Verification is offline-first | A verifier that needs a service is a weaker verifier |
| 7 | No compliance claims anywhere | We produce compatible provenance, not a certification |
| 8 | Subject digest is mandatory | An attestation without a subject is a claim with no referent |

**Rejected alternatives:** a custom JSON schema (unverifiable by anyone else), signing the artifact itself
(changes the artifact; provenance must be separable), a server-side registry (adds trust in us), JWT-based
attestations (not the ecosystem standard).

---

## 6. Architecture

This is the target architecture through M6; signing and identity policy are not implemented in M3.
The current unsigned data path is in [ARCHITECTURE.md](ARCHITECTURE.md).

```mermaid
flowchart LR
    SRC[Source repository] --> RUN[Build runner]
    RUN --> META[Metadata collector]
    META --> ART[Artifact set]
    ART --> HASH[SHA-256 hashing]
    META --> PROV[Provenance generator]
    HASH --> PROV
    PROV --> SIGN[Signing: keyless or local key]
    SIGN --> OUT[attestation.intoto.jsonl]
    OUT --> VER[Verifier]
    ART --> VER
    VER --> POLICY[Identity and digest policy]
    POLICY --> RESULT[Pass or specific failure]
```

### Components

| Component | Responsibility | Must never |
|---|---|---|
| Metadata collector | Checkout commit/dirty state/remote and current recorder tool versions | Infer original build tools, source or authenticated identity |
| Hasher | SHA-256 of each artifact, streamed | Load whole artifacts into memory |
| Provenance generator | Build the unsigned statement with defined observations and explicit assertions | Invent original build history or present caller claims as observations |
| Signer | DSSE envelope, keyless or local | Sign a payload it did not construct |
| Verifier | Signature, identity, subject digest, dependency commit | Trust the attestation's self-description |
| SBOM generator | CycloneDX from detected dependencies (M6) | Claim completeness |

---

## 7. Data formats

**Manifest** (`buildtrace.json`, produced at M1, human-readable, unsigned):

```json
{
  "schemaVersion": 1,
  "builtAt": "2026-11-13T10:00:00Z",
  "source": { "uri": "git+https://github.com/shellghostt/eventrelay", "commit": "9f3c2ab...", "dirty": false },
  "builder": { "id": "local", "host": "workstation", "os": "windows", "arch": "amd64" },
  "toolchain": { "go": "1.23.4", "git": "2.45.1" },
  "artifacts": [
    { "name": "eventrelay-linux-amd64", "path": "dist/eventrelay-linux-amd64", "size": 18432112 }
  ]
}
```

Two differences from the sketch above are deliberate, and both are M1 decisions rather than accidents:

- **`commit` is the full 40-character SHA**, not the 7-character abbreviation. An abbreviation is
  ambiguous: it can collide, and a consumer cannot check it against a repository without looking it up.
- **There is no `digest` field in M1.** Hashing is BT-006 and BT-007, which are M2. The field is
  omitted rather than emitted empty, so that an M1 manifest cannot be mistaken for a manifest whose
  artifacts were hashed. M2 adds the field and starts enforcing `schemaVersion`.

The `toolchain.git` field is also an M1 addition: knowing which git produced the commit matters when
the commit is the thing being attested to.

**Attestation** (in-toto Statement v1, SLSA provenance v1 predicate):

M3 construction follows [ADR 0005](adr/0005-m3-unsigned-recorder-contract.md) and the
[versioned recorder contract](build-types/record/v1.md). It records artifact observations, an observed
checkout and explicitly labeled optional caller assertions. Original build times, dependencies and
byproducts are not invented. The committed
[observation-only golden](../tests/fixtures/m3/observed.intoto.jsonl) and
[explicit-claims golden](../tests/fixtures/m3/claimed.intoto.jsonl) are complete, schema-checked examples.
Their metadata is [synthetic test input](../tests/fixtures/m3/README.md), not actual project build history.
The recorder build type and field evidence are defined in ADR 0005; unobserved
byproducts/dependencies are omitted.
The SLSA specification is 1.2 but its predicate URI
remains `/v1`. See [M3 requirements](phases/M3.md) for the input/claim mapping and pinned schema checks.

**DSSE envelope** (M4):

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the statement>",
  "signatures": [{ "keyid": "", "sig": "<base64>" }]
}
```

M3 stores one compact unsigned statement per artifact set as `<artifact>.intoto.jsonl`, ending in LF.
Its bounded reader also accepts CRLF. DSSE envelopes remain M4.

---

## 8. Command surface and exit codes

```
buildtrace record --artifact dist/app --out app.intoto.jsonl [--repo .] [--sign none]
                  [--builder-id <public-uri>] [--invocation-id <public-id>]
                  [--source-uri <uri> --source-commit <full-commit>]
                  [--started-on <RFC3339> --finished-on <RFC3339>]
buildtrace inspect --attestation dist/app.intoto.jsonl [--json]
buildtrace manifest --artifact dist/app --out buildtrace.json
buildtrace verify --manifest buildtrace.json [--root <dir>] [--json]
buildtrace version
```

The following signed-attestation command is planned for M4 and is currently rejected:

```
buildtrace verify --artifact dist/app --attestation dist/app.intoto.jsonl
                   [--identity <workflow-ref>] [--issuer <oidc-issuer>] [--allow-unsigned]
```

| Exit code | Meaning |
|---|---|
| 0 | Manifest/unsigned statement generated, unsigned statement inspected, or artifacts match M2 manifest; M4 adds signed verification |
| 1 | Verification failed: specific reason printed |
| 2 | Invalid input, malformed/bounded-out JSONL, missing artifact, unsupported format or M3 signing mode |
| 3 | Tool or I/O error; unsupported manifest versions specifically exit 2 in M2 |

Verification output is line-oriented and machine-readable with `--json`; the human form names the exact check
that failed.

---

## 9. Core contracts

### 9.1 What verification proves

M2 unsigned mode checks each artifact's kind, digest and byte count against a supplied v1 manifest.
Success declares `scope: unsigned_manifest` and `status: matched`. Source metadata, builder labels,
signatures and dependencies are not authenticated. The full signed pipeline below remains M4.

M3 generation recomputes subject digests while recording. M3 inspection performs only bounded format
parsing, with `scope: unsigned_statement`, `status: inspected`. It neither opens artifacts nor checks
content digests, signatures or source/identity claims. Schema checks establish format compatibility only.

Given an artifact `A`, an attestation `S`, and a policy `P(identity, issuer)`:

1. `S` is well formed and `predicateType` is a known provenance type.
2. The DSSE signature is valid and the signing identity satisfies `P`.
3. `S.subject[i].digest.sha256 == sha256(A)` for the matching subject name.
4. `S.predicate.buildDefinition.buildType` is a type the verifier understands.
5. `S.predicate.runDetails.builder.id` satisfies `P` when the policy constrains the builder.
6. `resolvedDependencies` contains a commit digest, and it is the commit the user expects (if supplied).

### 9.2 What verification does **not** prove

- **Manifests and M3 statements are unsigned.** Anyone can edit artifacts and their expected digests.
  Matching a manifest or inspecting a statement does not authenticate the build or its source.
- **Recording does not witness the original build.** Checkout state and tool versions are observed
  during recording. Explicit source and original-build time inputs remain caller assertions.
- **Inspection does not verify artifacts or signatures.** It parses bounded JSONL and reports
  `scope: unsigned_statement`, `status: inspected`; it does not open subjects or compare their bytes.
- **A builder label is not an authenticated identity.** `builder.id` is a public recorder label.
  Signing and identity policy remain M4.
- **Artifact safety is not established.** No vulnerability or malware analysis is performed.
- **Reproducibility is not established.** No two-build comparison is performed; that verdict remains M6.
- **Dependency completeness is not established.** M3 can record one explicitly asserted source
  dependency; it does not discover the module graph, generate an SBOM or infer a workflow.
- **Format compatibility is not a SLSA level.** Schema checks and deterministic output do not
  authenticate build honesty, builder identity or compliance.

This list belongs in the README, not only in the plan. It is the single most important text in the project.

### 9.3 Signed verification order (M4)

```
1. parse envelope        -> invalid_input
2. verify signature      -> signature_invalid
3. check identity policy -> identity_mismatch
4. match subject name    -> subject_missing
5. compare digest        -> digest_mismatch
6. check build type      -> unsupported_build_type
7. check dependency commit (if provided) -> dependency_mismatch
```

Each failure has a stable machine-readable reason string and a one-line explanation.

### 9.4 Hashing rules

- Streaming SHA-256, 1 MiB buffer, never load the artifact into memory.
- Hash the artifact **after** the build finishes and **before** it is uploaded. Record size as well.
- Symlinks are not followed; they are recorded as entries.
- Directories are hashed deterministically by sorted relative path.

M2 canonical bytes and version compatibility are specified in ADR 0004. Files stream with a 1 MiB
buffer. Directory path metadata is globally sorted and bounded to 100,000 entries; empty directories
and symlink target strings participate in the digest. Metadata such as timestamps and permissions
does not. Stop writers during hashing; it is not a filesystem snapshot. Manifest output must be
outside selected directory artifacts and cannot replace a selected file.

### 9.5 Signing rules (M4)

- Keyless: OIDC token → Fulcio certificate → sign DSSE → optional Rekor upload.
- Local key: Ed25519 or ECDSA P-256, PEM-encoded, path from `BUILDTRACE_SIGNING_KEY`.
- The signing payload is the DSSE PAE (`DSSEv1 <len(type)> <type> <len(body)> <body>`), never the raw JSON.
- The private key is never logged, never written to the attestation, never passed as a CLI argument.

---

## 10. Trust model

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Builder identity in policy | That this builder produced this artifact | That the builder behaved correctly |
| Sigstore/Fulcio | Binding an OIDC identity at a point in time | Artifact contents |
| Source repository | Commit contents | Build reproducibility |
| The verifier | Nothing beyond the checks in 9.1 | Anything it did not check |

The design principle: **the verifier never trusts the attestation's claims about itself.** It recomputes the
digest and compares bytes.

---

## 11. Repository layout

```
buildtrace/
├── cmd/buildtrace/          CLI entry point
├── internal/cli/            command implementations and exit codes (added in M1)
├── internal/metadata/       git, environment, toolchain capture
├── internal/manifest/       manifest model, serialiser, artifact collection (added in M1)
├── internal/testrepo/       throwaway git repositories for the tests (added in M1)
├── internal/hashing/        streaming sha256, directory determinism
├── internal/attestation/    statement and predicate construction
├── internal/signing/        dsse, keyless, local key
├── internal/verify/         verification pipeline and policy
├── internal/sbom/           cyclonedx (M6)
├── pkg/intoto/              statement types, no external dependency to read them
├── tests/fixtures/          committed artifacts for offline tests
├── tests/e2e/               record -> verify round trips
└── docs/                    plan, architecture, formats, ADRs
```

The three packages marked "added in M1" are not in the original layout, and the reason is worth
recording. `internal/manifest` holds the `buildtrace.json` format, which the plan's section 7 does not
give a home to; the alternative was to put it in `internal/hashing`, which does not exist until M2 and
whose job is hashing, not serialisation. `internal/cli` exists so that the exit codes and the output
of every command can be tested: a test that cannot call `main` cannot check them. `internal/testrepo`
creates a throwaway git repository in a temporary directory; the tests read a real `git` binary rather
than a mock of it, because the collector's job is to talk to git correctly, and a mock only proves that
the mock agrees with the test.

---

## 12. Milestones

### M1 — Metadata collection and manifest

**Deliverable:** `manifest` command producing `buildtrace.json` with source, builder and artifact metadata.

**Acceptance criteria**

- [x] Git commit, dirty state and remote URI captured; dirty tree sets `dirty: true` and a warning
- [x] Builds outside a git repository fail with exit 2 and a clear message
- [x] Toolchain and OS information captured without reading arbitrary environment variables
- [x] Manifest is deterministic for identical inputs (no timestamps inside the digest input)
- [x] No secret ever appears in the manifest (test feeds a fake token through every field)

Status note (M1, 2026-11-13): all five criteria are implemented and covered by tests. What "captured"
means in M1 is deliberately narrow, because the next milestone is the one that makes the claim strong:

- The commit is the **full 40-character SHA** of `HEAD`, not a short SHA.
- The remote URI is normalised to the `git+` form (`git+https://github.com/owner/repo`) and any
  credentials in it are stripped. A remote like `https://user:token@example.com/repo.git` never reaches
  a manifest.
- The dirty flag covers modified, deleted and untracked files, because `git status --porcelain`
  reports all three.
- The manifest contains **no digest**. Hashing is BT-006 and BT-007, which are M2. The `digest` field
  is omitted rather than left empty, so that an M1 manifest cannot be mistaken for a verified one.
- The build timestamp is the only value that changes between two runs over the same inputs, and it can
  be pinned with `--built-at` or `SOURCE_DATE_EPOCH`, which makes the manifest byte-for-byte
  reproducible.
- The environment reaches the `git` subprocess through an allowlist. `GIT_DIR` and `GIT_WORK_TREE` are
  deliberately excluded, because they would point the collector at a different repository than the one
  the user named.

At the M1 tag, `record`, `verify` and `inspect` were unimplemented. M2 implements
`verify --manifest`; M3 adds unsigned `record` and `inspect`. Signed-attestation verification remains M4.

### M2 — Artifact hashing and manifest verification

**Deliverable:** streaming SHA-256 for files and directories, `verify --manifest`, tamper detection.

**Acceptance criteria**

- [x] 1 GB artifact hashed with constant memory (< 64 MB RSS)
- [x] A single flipped byte produces `digest_mismatch` naming the artifact
- [x] Directory hashing is stable across OSes and file ordering
- [x] Missing artifact exits 2, not 0
- [x] Manifest schema version is enforced; unknown version is rejected, not guessed

M2 evidence: [validation report](testing/m1-m2-validation.md). A 1 GiB (1,073,741,824 byte)
file measured 44.04 MiB peak working set for capture and 7.61 MiB for verify on Windows, with an
independent SHA-256 comparison, one-byte tamper exit 1 and missing-artifact exit 2. The same directory
golden passes on Windows and Linux/WSL with reversed creation order and differing metadata. Native
macOS execution remains CI validation; cross-platform builds are checked separately.

### M3 — Provenance generation

**Deliverable:** unsigned `record`, in-toto Statement v1 with SLSA provenance predicate v1 and offline `inspect`.

Status: **Implemented and verified locally and in CI**, unreleased on `feat/m3-implementation`.
[M3 validation](testing/m3-provenance.md) records the exact source commit and test mapping;
GitHub CI passed; review remains pending. Arbitrary build execution and signing are excluded.

**Acceptance criteria**

- [x] Output validates against the in-toto statement schema and the SLSA predicate schema
- [x] Every predicate field maps to observed input or a clearly identified caller assertion, with no guesses
- [x] `inspect` prints subject, builder, dependencies and build type
- [x] Golden-file tests for two fixtures
- [x] Statement is byte-identical for identical inputs including pinned timestamps and invocation IDs
- [x] Unsigned `record`/`inspect` and malformed JSONL/signing requests have explicit offline CLI tests

### M4 — Signing and verification

**Deliverable:** DSSE envelopes, Sigstore keyless signing, local key signing, full verification pipeline with
identity policy.

**Acceptance criteria**

- [ ] `record --sign keyless` produces a valid DSSE envelope in a GitHub Actions runner
- [ ] Verification fails with `identity_mismatch` when the workflow ref differs
- [ ] Verification fails with `digest_mismatch` when the artifact is modified after signing
- [ ] Local key signing and verification work with no network
- [ ] Tampered payload inside the envelope fails signature verification
- [ ] Each failure reason in section 9.3 has a test

### M5 — GitHub Actions integration

**Deliverable:** reusable action, release workflow, attestation uploaded next to artifacts.

**Acceptance criteria**

- [ ] Action records, signs and uploads for a matrix build
- [ ] Consumers can verify with one documented command
- [ ] No long-lived secret required for keyless mode
- [ ] Unsigned mode is possible but warns loudly
- [ ] Documentation includes a copy-paste verification snippet

### M6 — SBOM and reproducibility

**Deliverable:** CycloneDX SBOM, reproducibility check (build twice, compare digests), v1.0.0.

**Acceptance criteria**

- [ ] SBOM attached as a subject or byproduct with its own digest
- [ ] Two clean rebuilds produce identical artifact digests for the reference project, or the difference is
      documented and explained
- [ ] `verify --reproducible` reports `reproducible | not_reproducible | inconclusive`
- [ ] README states plainly what is and is not proven
- [ ] `CHANGELOG.md` and roadmap complete

---

## 13. Backlog

| ID | Task | Depends | Milestone | Status |
|---|---|---|---|---|
| BT-001 | CLI skeleton, config, exit codes | — | M1 | Done |
| BT-002 | Git metadata collector | BT-001 | M1 | Done |
| BT-003 | Toolchain and platform collector | BT-001 | M1 | Done |
| BT-004 | Manifest model and serialiser | BT-002, BT-003 | M1 | Done |
| BT-005 | Secret-exclusion tests | BT-004 | M1 | Done |
| BT-006 | Streaming SHA-256 hasher | — | M2 | Done |
| BT-007 | Directory hashing with deterministic order | BT-006 | M2 | Done |
| BT-008 | Manifest verification | BT-004, BT-006 | M2 | Done |
| BT-009 | Tamper tests | BT-008 | M2 | Done |
| BT-010 | in-toto statement types in `pkg/intoto` | — | M3 | Done; CI passed |
| BT-011 | SLSA predicate builder | BT-010 | M3 | Done; CI passed |
| BT-011A | Unsigned `record` command and field/input mapping | BT-011, BT-007 | M3 | Done; CI passed |
| BT-012 | `inspect` command | BT-011 | M3 | Done; CI passed |
| BT-013 | Schema validation against upstream | BT-011 | M3 | Done; CI passed |
| BT-014 | DSSE encoding and PAE | BT-010 | M4 | Not started |
| BT-015 | Local key signer and verifier | BT-014 | M4 | Not started |
| BT-016 | Sigstore keyless signer | BT-014 | M4 | Not started |
| BT-017 | Verification pipeline with stable reasons | BT-014 | M4 | Not started |
| BT-018 | Identity policy matcher | BT-017 | M4 | Not started |
| BT-019 | Offline verification tests with fixtures | BT-017 | M4 | Not started |
| BT-020 | Reusable GitHub Action | BT-016 | M5 | Not started |
| BT-021 | Release workflow and artifact upload | BT-020 | M5 | Not started |
| BT-022 | Consumer verification docs | BT-021 | M5 | Not started |
| BT-023 | CycloneDX SBOM generator | BT-011 | M6 | Not started |
| BT-024 | SBOM as byproduct with digest | BT-023 | M6 | Not started |
| BT-025 | Reproducibility checker | BT-017 | M6 | Not started |
| BT-026 | Reference project double-build test | BT-025 | M6 | Not started |
| BT-027 | v1.0.0 release and trust-model doc review | BT-022 | M6 | Not started |

---

## 14. Testing strategy

- **Golden formats:** two synthetic M3 statements are compared byte for byte with committed fixtures.
- **Tamper matrix:** M2 detects artifact byte/kind/size mismatch. Payload/signature/replay checks belong
  to the future M4 signed verifier; unsigned M3 inspection does not claim to perform them.
- **Cross-implementation check:** M3 fixtures pass the isolated pinned upstream Protobuf JSON
  validators via `make schemas`. `cosign`/`slsa-verifier` signature/identity checks require M4 inputs.
- **Offline test:** packaged M2 verification and M3 record/inspect execute with network disabled.
  Schema validation uses cached dependencies with module/schema fetching disabled after setup.
- **Determinism:** equal bytes, metadata, IDs and declared times yield the same statement.
- **Bounds and mutation:** malformed/duplicate/oversized JSONL fails, and hashing retains M2 mutation
  guards. Windows file identity is captured eagerly; a deterministic replacement regression passes.

---

## 15. Security and threat model

Signing/identity mitigations below describe M4 controls. M3 statements remain mutable unsigned data;
recording and inspection do not enforce signer policy.

| Threat | Mitigation |
|---|---|
| Forged attestation | Signature over DSSE PAE, identity policy |
| Replay of attestation onto another artifact | Subject digest comparison is mandatory; unsigned mode is opt-in and warns |
| Substituted builder | Builder identity checked against policy, not merely present |
| TOCTOU between hash and upload | Hash immediately before signing; upload the exact hashed bytes |
| Key compromise | Keyless short-lived certificates preferred; local keys documented as higher risk; revocation post-1.0 |
| Secret leakage into output | Allowlisted capture; M3 URI credentials/query/fragment removal and fake-token tests |
| Malicious artifact path traversal | Paths normalised; symlinks not followed |
| Malicious unsigned JSONL | 16 MiB, 64 nesting levels, 200,000 tokens and bounded resource lists; duplicate keys rejected |
| False assurance | Section 9.2 is reproduced verbatim in the README |

---

## 16. Risks and open questions

| Risk | Impact | Mitigation |
|---|---|---|
| Ecosystem churn in SLSA predicate | Breaking change | Pin v1, version the builder type, document migration |
| Users read "verified" as "safe" | False assurance | Non-claims in README and CLI output |
| Keyless requires network | Air-gapped builds blocked | Local key path from M4 |
| Reproducibility is often impossible | Bad v1.0 claim | Report `inconclusive`, document causes |

**Open questions:**

1. Should `record` fail when the working tree is dirty? *Current: warn, set observed `dirty: true`, continue.*
2. Where do attestations live for OCI images? *Current: post-1.0.*
3. Do we embed Rekor inclusion proofs in v1.0? *Current: no, documented as a gap.*

---

## 17. Anti-hallucination contract

**Facts:** the binary builds a `buildtrace.json` that records the commit, the dirty state, the normalised
remote, builder and toolchain, plus artifact kind, size and SHA-256. M2 verification checks artifacts
against an unsigned v1 manifest offline. It does not sign or authenticate metadata. `record`, `inspect`
now generate/parse unsigned in-toto/SLSA statements with defined observations and caller assertions.
Signed-attestation verification remains unimplemented; M3 inspection is not a verification verdict.

**Rules:**

1. Never write "SLSA compliant", "SLSA level 3" or "certified". We produce compatible provenance and claim
   nothing about compliance.
2. Never say verification proves an artifact is safe, trustworthy or unmodified **by a human attacker**. It
   checks digests against the supplied unsigned manifest in M2. Signer policy arrives in M4.
3. Never claim reproducibility without the M6 test that produced it.
4. Every attestation claim needs traceable evidence. Caller assertions must be labeled as such;
   an observation of a checkout/toolchain does not authenticate the original build. Never fabricate fields.
5. Update the README non-claims section whenever section 9.2 changes.
6. Update status fields, roadmap and CHANGELOG in the same pull request.
7. **Never describe the M1 manifest as proof of anything about the artifact.** It records a name, a path
   and a size. Without a digest it says nothing about the bytes, and a manifest that looks like a
   verified one is worse than no manifest.
8. Never add a field to the manifest that the collector did not read from a real input. A derived or
   guessed field is a hallucination.

**Glossary:**

| Term | Meaning |
|---|---|
| Artifact | A file produced by a build, identified by SHA-256. |
| Subject | The artifact entry inside an in-toto statement. |
| Statement | in-toto Statement v1: subjects + predicate type + predicate. |
| Predicate | The SLSA provenance body describing the build. |
| Envelope | DSSE wrapper carrying the payload and signatures. |
| Builder identity | The OIDC identity or key that signed. |
| Verification | M2 unsigned artifact comparison; the signed checks in section 9.3 remain M4. |
| Inspection | M3 offline format parsing and display with explicitly unsigned scope. |

---

## 18. Handoff protocol

1. Read sections 0, 3, 9 and 10. The trust model is the design.
2. `make build && ./bin/buildtrace version`.
3. M1/M2 are merged into `main`; M3 is complete with passing CI on its feature branch. Read
   [M3 validation](testing/m3-provenance.md) and preserve ADR 0004/0005 contracts. Review remains pending.
4. Before adding a predicate field, define its input and whether it is observed or asserted.
5. Never merge a verification path without a negative test for each failure reason.
6. Manifest `schemaVersion: 1` is enforced. M2 emits digest/kind and rejects unknown versions.
   Changing the shape of
   an existing field needs an ADR and a version bump.
7. The repository layout in section 11 is the plan; `internal/manifest` and `internal/cli` were added in
   M1 and are now part of it. M2 uses `internal/hashing` and `internal/verify`.
   M3 implements `internal/attestation` and `pkg/intoto`.
   `internal/signing` and `internal/sbom` remain later milestones; do not scaffold them early.
