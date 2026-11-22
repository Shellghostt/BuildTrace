# Changelog

All notable changes to BuildTrace are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- M4 exact-byte DSSE/PAE, local Ed25519/P-256 keys, standard Sigstore v0.3 keyless bundles,
  external key/root/identity policy and selected rooted artifact verification under accepted ADRs 0006-0008.
- Historical synthetic certificate/CT/Rekor fixtures, strict bounds/negative scope/reason tests,
  separate unsigned opt-in and scoped signer/checked/unselected reports. M2/M3 default bytes/contracts remain compatible.
- Independent signed fixtures, patched module/license inventory and focused live GitHub OIDC CI job.
  [Local validation](docs/testing/m4-signing.md) and [resource measurements](docs/benchmarks/m4-signing.md)
  preserve source `6ef2dd9`; corrected source `91a11df` passed all eight cross-platform/live signing CI jobs.
  [Structured CI evidence](docs/testing/m4-ci-results.json) records actual results; PR #3 is published/unmerged.
- [M3 requirements](docs/phases/M3.md) with phase boundaries, failure cases, ADR prerequisites and
  acceptance gates, plus a [development-tool audit](docs/DEVELOPMENT-TOOLS.md).
- M3 unsigned `record` and offline `inspect`, using in-toto Statement v1/SLSA provenance v1 and
  the versioned artifact-recorder contract in ADR 0005. Observed artifacts/checkout metadata and
  explicit caller assertions have defined meanings; original build history and identity are not inferred.
- Deterministic recorder IDs, paired optional source/time claims, unique relative subject names,
  URI credential/query/fragment removal and atomic output protection using M2 canonical digests.
- A bounded JSONL reader with exact key matching, duplicate-key rejection and compatible unknown
  fields retained in its explicitly unsigned inspection report.
- Two synthetic goldens, an isolated pinned upstream Protobuf JSON validator with source/license
  checksums, a schema CI job and a separate validator vulnerability scan.
- Extended 1 GiB and packaged-container checks for M3, parser fuzzing and Go allocation/heap profiles.
  [Validation](docs/testing/m3-provenance.md) passed locally and in Windows/Ubuntu/macOS CI on
  2026-11-17; M3 is merged through PR #2.

- M2 streaming file SHA-256, canonical directory hashing and symlink entries without following targets.
- `verify --manifest` with offline recomputation of kind, digest and size, stable JSON reports and
  exit codes. The v1 reader rejects missing digests, unsupported versions and ambiguous/malformed JSON.
- Portable directory golden tests, actual CLI round trips/tampering, parser fuzzing and a 1 GiB
  memory/tamper gate. ADR 0004 specifies canonical bytes and the unsigned verification scope.

- The repository tracks CodeGraph's index ignore rules and documents it as an optional local tool
  for code navigation. Nothing in the build or in CI depends on it.

### Changed

- M4 adds statically linked signing dependencies with explicit compatible pins and runtime/test audits.
- The 1 GiB/64 MiB memory gate now uses production Make/Docker `-trimpath -ldflags '-s -w'` flags;
  its artifact workload, independent digest and memory threshold are unchanged. Initial debug-build failure is recorded.
- The Make image target passes its version to the binary; Docker copies committed go.mod/go.sum and builds read-only modules.

- The repository is published at https://github.com/Shellghostt/BuildTrace and the CI workflow has
  executed. The first run on 2026-11-13 passed the Windows, Ubuntu and macOS matrix, the lint job and
  the vulnerability scan, including `go test -race`, which could not be run on the machine that
  produced M1.
- The Go floor moves from 1.23 to 1.26. `go.mod` declares `go 1.26.0` and `toolchain go1.26.11`, so
  CI installs the patched toolchain and not the exact patch named by the `go` directive. Go 1.23 is
  past its support window and receives no security fixes. See ADR 0003.
- The builder image is pinned to `golang:1.26.11-alpine`.
- The linter is golangci-lint v2.15.0, pinned by version, run by `golangci/golangci-lint-action@v9`.
  The findings it produced were fixed in the code rather than excluded.

### Fixed

- Required certificate issuer evidence, authenticated SET/checkpoint/tree consistency and explicit trust-root key handling
  reject incomplete/forged keyless material. Shared standard roots keep unused Rekor v2 entries without enabling v2 verification.
- TUF setup retains typed root-rotation HTTP/size errors; signing diagnostics exclude token/key/service response material.
- Rekor v1 global SET indexes and shard-local inclusion indexes are verified separately; authenticated
  sharded fixtures and live signing pass. The POSIX encrypted-key test now creates a private file with correct permissions.
- The signing dependency audit's six vulnerabilities were addressed through compatible patched modules and maintained OpenPGP.

- Manifest output cannot replace an artifact or live inside a selected directory. Temporary sibling
  writes avoid truncating destination symlink/hardlink targets.
- Directory mutation checks use rooted stat metadata on Windows, avoiding false changes from cached
  directory-entry information.
- The shared hasher captures Windows file identity during its initial observation. A replacement
  with equal size/timestamp can no longer make a lazily resolved identity compare with the replacement.
  The regression passes on Windows and Linux; canonical hashing formats and M2 CLI contracts are unchanged.

- The writes whose error return was discarded now say so explicitly with `_, _ =`.

### Planned

- M5 reusable action/release integration and M6 dependency/SBOM/reproducibility remain future work.

## [0.1.0] - 2026-11-13

### Added

- The `manifest` command: it writes a deterministic `buildtrace.json` describing the source, the
  builder, the toolchain and the artifacts of a build.
- A git metadata collector (`internal/metadata`): the full 40-character SHA of `HEAD`, the dirty state
  of the working tree, and the remote URI normalised to the `git+` form.
- Credential stripping. A remote such as `https://user:token@example.com/repo.git` is recorded as
  `git+https://example.com/repo`; the userinfo is removed, not masked.
- A toolchain and platform collector: the Go version the binary was built with, the git version, the
  operating system, the architecture and the host name.
- An allowlisted environment for the git subprocess. The collector replaces the environment entirely, so
  no credential in the environment of BuildTrace is reachable from git.
- The manifest model and serialiser (`internal/manifest`), with a golden file test. The artifacts are
  sorted by path, the field order is stable, and the same inputs produce the same bytes.
- A pinned build timestamp: `--built-at` takes an RFC 3339 timestamp and `SOURCE_DATE_EPOCH` takes a
  Unix timestamp. With the timestamp pinned, two runs over the same inputs are byte-identical.
- The command layer (`internal/cli`), so that the exit codes and the output of every command are
  tested rather than assumed.
- Unit tests that use a real `git` binary against a throwaway repository, including a secret-exclusion
  test that plants a fake token in the remote URL, in three well-known environment variables and in the
  builder id, and asserts that it appears nowhere in the manifest, in stdout or in stderr.
- ADR 0002, recording the M1 decisions.

### Known limitations

- **Nothing is hashed.** The manifest records the name, path and size of each artifact and no digest,
  so it is not evidence about the bytes. Hashing is M2.
- **Nothing is signed and nothing is verified.** The `record`, `verify` and `inspect` commands are not
  implemented; they exit 3 and say so.
- **The manifest is not an attestation.** It is plain JSON that anyone can edit, and it is not an
  in-toto statement.
- **Directory artifacts are rejected.** The message names the milestone that adds them.
- **`builder.id` is a label**, not an identity. It is whatever the caller passed on the command line.
- **No dependencies are recorded**, and there is no SBOM and no reproducibility check.
- The race detector could not be run locally: the only C compiler on that machine is MinGW GCC 6.3.0,
  which cannot build a 64-bit race-enabled binary. CI runs `go test -race` on ubuntu-latest.
- The CI workflow had not executed when this tag was created: the repository had no remote yet. It has
  since run on GitHub; see [Unreleased].

## [0.0.0] - 2026-11-13

- Initial skeleton. No functionality.
