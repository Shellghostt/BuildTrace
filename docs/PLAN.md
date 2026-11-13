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
updated: 2026-11-13
---

# BuildTrace — Implementation Plan

> **This file is the specification.** Section 9 defines exactly what verification proves and what it does
> not. Overclaiming here is not a marketing problem, it is a security problem.

---

## 0. Machine context

```yaml
project: BuildTrace
status: mvp
version: 0.1.0
builds: true
functional: partial            # metadata and manifest work; nothing is hashed, signed or verified

implemented:
  - repository skeleton
  - cli binary with the manifest and version commands
  - git metadata collector: commit, dirty state, normalised remote uri
  - toolchain and platform collector: go version, git version, os, arch, host
  - manifest model and deterministic serialiser (internal/manifest)
  - artifact collection: name, path relative to the repository root, size
  - allowlisted environment for the git subprocess; remote credentials stripped
  - pinned build timestamp via --built-at and SOURCE_DATE_EPOCH
  - unit tests and golden-file tests

not_implemented:
  - artifact hashing (sha256) -- M2
  - manifest verification and tamper detection -- M2
  - in-toto statement and slsa predicate -- M3
  - the record, verify and inspect commands -- M3 and M4
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
  formats: pkg/intoto/                     # M3; still empty in M1
  status: README.md#roadmap

forbidden_claims:
  - "SLSA compliant" / "SLSA level N" / "certified"
  - "proves the artifact is safe"
  - "guarantees reproducibility"
  - verification without checking the subject digest against the artifact
  - any signature or provenance claim before M4
  - a digest field in an M1 manifest: M1 does not hash anything

if_uncertain:
  - every attestation field must map to an input a third party can recompute
  - if a claim cannot be verified offline, it does not belong in the attestation
  - if the implementation does not do it, the README does not say it
```

---

## 1. What this is

A CLI that records how an artifact was built and produces a signed, in-toto-compatible attestation — and,
more importantly, verifies one.

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

**Success looks like.** A consumer downloads a binary and an attestation, runs one command with a pinned
builder identity, and gets a pass or a specific failure reason — with no network access required.

---

## 3. Non-goals

- **Not a build system.** It records builds; it does not run them.
- **Not an artifact registry.** Storage is somebody else's job (release assets, OCI registry, S3).
- **Not a vulnerability scanner.** SBOM generation is supported; CVE analysis is not.
- **Not a transparency log service.** Sigstore's log may be used; we do not run one.
- **Not a policy engine for clusters.** It emits a verdict; admission control belongs to Kyverno/Gatekeeper.
- **No custom attestation format.** in-toto Statement v1 and the SLSA provenance predicate v1, or nothing.

---

## 4. Scope contract

### v0.1 — MVP (M1–M4)

`record` produces an unsigned in-toto statement plus a manifest; `verify` checks digests offline; M4 adds
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
| Metadata collector | Git commit, dirty state, builder identity, toolchain versions, timestamps | Read secrets or environment values that are not explicitly allowlisted |
| Hasher | SHA-256 of each artifact, streamed | Load whole artifacts into memory |
| Provenance generator | Build the statement and predicate | Invent fields that cannot be recomputed |
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

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "eventrelay-linux-amd64", "digest": { "sha256": "b1946ac92492..." } }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://buildtrace.dev/build/v1",
      "externalParameters": { "source": { "uri": "git+https://...", "commit": "9f3c2ab" } },
      "internalParameters": { "goVersion": "1.23.4" },
      "resolvedDependencies": [
        { "uri": "git+https://github.com/shellghostt/eventrelay", "digest": { "gitCommit": "9f3c2ab" } }
      ]
    },
    "runDetails": {
      "builder": { "id": "https://github.com/shellghostt/buildtrace/.github/workflows/release.yml@refs/tags/v1.0.0" },
      "metadata": { "invocationId": "01J8Z8Q9K3", "startedOn": "2026-11-13T09:58:00Z", "finishedOn": "2026-11-13T10:00:00Z" },
      "byproducts": [{ "name": "buildtrace.json", "digest": { "sha256": "..." } }]
    }
  }
}
```

**DSSE envelope** (M4):

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the statement>",
  "signatures": [{ "keyid": "", "sig": "<base64>" }]
}
```

Stored as one JSON file per artifact set: `<artifact>.intoto.jsonl`.

---

## 8. Command surface and exit codes

```
buildtrace record --artifact dist/app --out dist/app.intoto.jsonl [--commit auto] [--sign keyless|none]
buildtrace verify --artifact dist/app --attestation dist/app.intoto.jsonl
                   [--identity <workflow-ref>] [--issuer <oidc-issuer>] [--allow-unsigned]
buildtrace inspect --attestation dist/app.intoto.jsonl [--json]
buildtrace manifest --artifact dist/app --out buildtrace.json
buildtrace version
```

| Exit code | Meaning |
|---|---|
| 0 | Verified: digest, signature and identity policy all pass |
| 1 | Verification failed: specific reason printed |
| 2 | Invalid input: malformed attestation, missing artifact |
| 3 | Tool error: I/O, unsupported statement version |

Verification output is line-oriented and machine-readable with `--json`; the human form names the exact check
that failed.

---

## 9. Core contracts

### 9.1 What verification proves

Given an artifact `A`, an attestation `S`, and a policy `P(identity, issuer)`:

1. `S` is well formed and `predicateType` is a known provenance type.
2. The DSSE signature is valid and the signing identity satisfies `P`.
3. `S.subject[i].digest.sha256 == sha256(A)` for the matching subject name.
4. `S.predicate.buildDefinition.buildType` is a type the verifier understands.
5. `S.predicate.runDetails.builder.id` satisfies `P` when the policy constrains the builder.
6. `resolvedDependencies` contains a commit digest, and it is the commit the user expects (if supplied).

### 9.2 What verification does **not** prove

- That the build was honest. A compromised builder can sign a lie. Provenance shifts trust to the builder
  identity, it does not eliminate it.
- That the artifact is safe. No vulnerability or malware analysis is performed.
- That the source commit is the one that was reviewed. Branch protection is a separate control.
- That the artifact is the only one built. Reproducibility checking is M6 and is a separate verdict.
- That the signature is still valid after key revocation, unless a timestamp/transparency proof is checked
  (post-1.0).

This list belongs in the README, not only in the plan. It is the single most important text in the project.

### 9.3 Verification order (fail fast, fail specifically)

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

The M1 criteria do **not** include "the artifact is verified", because nothing is hashed yet. The
`record`, `verify` and `inspect` commands exist in the command surface of section 8 but are not
implemented: they exit 3 and say so.

### M2 — Artifact hashing and manifest verification

**Deliverable:** streaming SHA-256 for files and directories, `verify --manifest`, tamper detection.

**Acceptance criteria**

- [ ] 1 GB artifact hashed with constant memory (< 64 MB RSS)
- [ ] A single flipped byte produces `digest_mismatch` naming the artifact
- [ ] Directory hashing is stable across OSes and file ordering
- [ ] Missing artifact exits 2, not 0
- [ ] Manifest schema version is enforced; unknown version is rejected, not guessed

### M3 — Provenance generation

**Deliverable:** in-toto statement v1 with SLSA provenance v1 predicate, unsigned, `inspect` command.

**Acceptance criteria**

- [ ] Output validates against the in-toto statement schema and the SLSA predicate schema
- [ ] Every predicate field maps to a captured input (no derived guesses)
- [ ] `inspect` prints subject, builder, dependencies and build type
- [ ] Golden-file tests for two fixtures
- [ ] Statement is byte-identical for identical inputs apart from declared timestamps

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
| BT-006 | Streaming SHA-256 hasher | — | M2 | Not started |
| BT-007 | Directory hashing with deterministic order | BT-006 | M2 | Not started |
| BT-008 | Manifest verification | BT-004, BT-006 | M2 | Not started |
| BT-009 | Tamper tests | BT-008 | M2 | Not started |
| BT-010 | in-toto statement types in `pkg/intoto` | — | M3 | Not started |
| BT-011 | SLSA predicate builder | BT-010 | M3 | Not started |
| BT-012 | `inspect` command | BT-011 | M3 | Not started |
| BT-013 | Schema validation against upstream | BT-011 | M3 | Not started |
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

- **Golden formats:** every produced statement is compared against a committed expected file.
- **Tamper matrix:** modify artifact, modify payload, swap signature, swap subject, replay a valid envelope
  onto a different artifact. Each must fail with the documented reason.
- **Cross-implementation check:** verify our attestation with `cosign`/`slsa-verifier` where possible.
  If another tool rejects our output, our output is wrong.
- **Offline test:** verification runs with the network disabled in CI.
- **Determinism:** same inputs, same statement, except declared timestamps.

---

## 15. Security and threat model

| Threat | Mitigation |
|---|---|
| Forged attestation | Signature over DSSE PAE, identity policy |
| Replay of attestation onto another artifact | Subject digest comparison is mandatory; unsigned mode is opt-in and warns |
| Substituted builder | Builder identity checked against policy, not merely present |
| TOCTOU between hash and upload | Hash immediately before signing; upload the exact hashed bytes |
| Key compromise | Keyless short-lived certificates preferred; local keys documented as higher risk; revocation post-1.0 |
| Secret leakage into manifest | Allowlist-based field capture, tests with fake tokens |
| Malicious artifact path traversal | Paths normalised; symlinks not followed |
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

1. Should `record` fail when the working tree is dirty? *Current: warn, set `dirty: true`, allow override.*
2. Where do attestations live for OCI images? *Current: post-1.0.*
3. Do we embed Rekor inclusion proofs in v1.0? *Current: no, documented as a gap.*

---

## 17. Anti-hallucination contract

**Facts:** the binary builds a `buildtrace.json` that records the commit, the dirty state, the normalised
remote, the builder, the toolchain and the size of each artifact. It hashes nothing, signs nothing and
verifies nothing. The `record`, `verify` and `inspect` commands are not implemented and exit 3.

**Rules:**

1. Never write "SLSA compliant", "SLSA level 3" or "certified". We produce compatible provenance and claim
   nothing about compliance.
2. Never say verification proves an artifact is safe, trustworthy or unmodified **by a human attacker**. It
   proves the digest matches and the signer matches policy.
3. Never claim reproducibility without the M6 test that produced it.
4. An attestation claim that cannot be recomputed by a third party must be removed, not documented.
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
| Verification | The ordered checks in section 9.3. |

---

## 18. Handoff protocol

1. Read sections 0, 3, 9 and 10. The trust model is the design.
2. `make build && ./bin/buildtrace version`.
3. M1 is done and tagged. The next milestone is **M2, artifact hashing and manifest verification**:
   start at BT-006 (the streaming SHA-256 hasher), then BT-007 (deterministic directory hashing), then
   BT-008 and BT-009. BT-006 is the first task in the whole backlog that is not M1 work, and it is the
   one that turns the manifest from a description into evidence.
4. Before adding any predicate field, answer: how would a third party recompute this?
5. Never merge a verification path without a negative test for each failure reason.
6. The manifest format is versioned by `schemaVersion` (currently 1). M2 adds the `digest` field and
   starts enforcing the version: an unknown version must be rejected, not guessed. Changing the shape of
   an existing field needs an ADR and a version bump.
7. The repository layout in section 11 is the plan; `internal/manifest` and `internal/cli` were added in
   M1 and are now part of it. `internal/hashing`, `internal/attestation`, `internal/signing`,
   `internal/verify`, `internal/sbom` and `pkg/intoto` are still empty and are not to be scaffolded
   before the milestone that needs them.
