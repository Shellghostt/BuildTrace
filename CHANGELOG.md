# Changelog

All notable changes to BuildTrace are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The repository is published at https://github.com/Shellghostt/BuildTrace and the CI workflow has
  executed. The first run on 2026-11-13 passed the Windows, Ubuntu and macOS matrix, the lint job and
  the vulnerability scan, including `go test -race`, which could not be run on the machine that
  produced M1.
- The Go floor moves from 1.23 to 1.26. `go.mod` declares `go 1.26.0` and `toolchain go1.26.11`, so
  CI installs the patched toolchain and not the exact patch named by the `go` directive. Go 1.23 is
  past its support window and receives no security fixes. See ADR 0003.
- The builder image moves to `golang:1.26-alpine`.
- The linter is golangci-lint v2.15.0, pinned by version, run by `golangci/golangci-lint-action@v9`.
  The findings it produced were fixed in the code rather than excluded.

### Fixed

- The writes whose error return was discarded now say so explicitly with `_, _ =`.

### Planned

- M2: streaming SHA-256 hashing, deterministic directory hashing, manifest verification and tamper
  detection.

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
- The CI workflow has never executed: the repository has no remote yet.

## [0.0.0] - 2026-11-13

- Initial skeleton. No functionality.
