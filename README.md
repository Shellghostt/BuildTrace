# BuildTrace

> An open-source build provenance and artifact verification system.

![status](https://img.shields.io/badge/status-M3_complete-green)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)

**Status: M1–M3 complete and merged into main.** Windows, Ubuntu and macOS CI
passed; no new release is claimed. `record` writes unsigned in-toto Statement v1/SLSA provenance v1
for existing artifacts, with checkout observations and explicit caller assertions.
`inspect` parses that statement offline. M2 `manifest` and `verify --manifest` still record and
recompute artifact kinds, SHA-256 digests and sizes.

## Why this exists

"We built this binary from that commit" is a claim. BuildTrace records recomputable artifact digests
and identifies which metadata was observed and which was supplied by the caller. M2 compares artifact
bytes with an unsigned manifest; signing and signer authentication remain M4.

## What it does today

| Capability | Milestone | Status |
|---|---|---|
| Capture source commit, dirty state and remote URI | M1 | **Done** |
| Record the build environment (builder, OS, toolchain) | M1 | **Done** |
| Write a deterministic `buildtrace.json` | M1 | **Done** |
| Strip credentials from the recorded remote | M1 | **Done** |
| Generate and verify artifact hashes | M2 | **Done (merged)** |
| Record and inspect unsigned in-toto/SLSA provenance | M3 | **Done (merged)** |
| Verify artifact signatures | M4 | Not started |
| CI/CD integration | M5 | Not started |
| Track dependencies | M6 | Not started |
| SBOM support | M6 | Not started |
| Reproducibility checks | M6 | Not started |

## What this release does **not** prove

This section is the most important one in this README, and it is reproduced from
[docs/PLAN.md](docs/PLAN.md) section 9.2. It changes only when that section changes.

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

## Architecture

```mermaid
flowchart LR
    REPO[Existing checkout] --> META[Observed metadata]
    ART[Existing artifacts] --> HASH[M2 canonical hashing]
    META --> REC[Unsigned recorder]
    HASH --> REC
    CLAIMS[Explicit caller assertions] --> REC
    REC --> OUT[Statement v1 / SLSA provenance v1 JSONL]
    OUT --> INSPECT[Offline parser and formatter]
    INSPECT --> REPORT[Unsigned inspection report]
```

Full reasoning, data model, API surface and failure behaviour are in [docs/PLAN.md](docs/PLAN.md).
The shape of what exists today is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Engineering challenge

Each field must map to a defined input. Artifact digests can be independently recomputed; checkout
observations can be compared with a checkout; caller assertions need separate evidence.

## Quickstart

Use Go 1.26.11 and `git`. The repository pins the patched toolchain.

```bash
make build
./bin/buildtrace version
```

Write a manifest for the artifacts of the current repository:

```bash
./bin/buildtrace manifest \
  --artifact dist/app \
  --artifact dist/app.sig \
  --out buildtrace.json
```

Historical M1 output, before hashing was implemented:

```json
{
  "schemaVersion": 1,
  "builtAt": "2026-11-13T05:10:21Z",
  "source": {
    "uri": "",
    "commit": "0e515c049e50c27cd85a388e2809c5df737fafee",
    "dirty": false
  },
  "builder": {
    "id": "local",
    "host": "Buddy",
    "os": "windows",
    "arch": "amd64"
  },
  "toolchain": {
    "go": "1.27.4",
    "git": "2.53.0.windows.2"
  },
  "artifacts": [
    {
      "name": "app",
      "path": "dist/app",
      "size": 18432112
    }
  ]
}
```

The empty `uri` is honest: this manifest was produced before the repository was published, so there
was no remote to record. A repository with a remote records it in the `git+` form, for example
`git+https://github.com/shellghostt/buildtrace`, with any credentials removed.

M2 adds `kind` and `digest` to each artifact. For a file containing exactly `hello`:

```json
{"kind":"file","name":"app","path":"dist/app","size":5,"digest":{"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}
```

Verify from the repository root, or specify the artifact base directory:

```sh
./bin/buildtrace verify --manifest buildtrace.json --root . --json
```

```json
{"scope":"unsigned_manifest","status":"matched","verified":2}
```

Verification needs neither git nor network access. Relative artifact paths resolve from `--root`
(default current directory), regardless of where the manifest is saved. Paths outside the source
repository remain absolute and host-specific. M1 manifests without digests are rejected; regenerate
them with M2. Keep manifest output outside selected directory artifacts and stop writers during hashing.
The [canonical hashing contract](docs/adr/0004-m2-canonical-hashing-and-verification.md) defines directory
and symlink bytes, including empty directories and a 100,000-entry bound.

### Unsigned recording and inspection

```sh
./bin/buildtrace record --artifact dist/app --out app.intoto.jsonl --sign none
./bin/buildtrace inspect --attestation app.intoto.jsonl
./bin/buildtrace inspect --attestation app.intoto.jsonl --json
```

The unsigned default is `--sign none`; other signing modes exit 2. Recording needs git and existing
artifacts within the repository root, but does not run a build or fetch anything from the network.
Subjects use unique repository-relative names and M2 digests. Keep output outside selected artifacts
and stop writers during hashing.

Inspection needs neither git nor the original artifacts. Its JSON report includes
`scope: unsigned_statement`, `status: inspected`, the parsed summary and the original `statement`,
including compatible unknown fields. Unknown statement/predicate URIs fail; an unknown build type is
displayed without interpreting its semantics.

| Record flag | Default or requirement | Meaning |
|---|---|---|
| `--artifact` | required, repeatable; 1–1,000 | Existing file, directory or terminal symlink within the checkout root. |
| `--repo` / `--out` | `.` / stdout | Checkout to observe and atomic JSONL destination. |
| `--sign` | `none` | Only unsigned generation is supported in M3. |
| `--builder-id` | BuildTrace `#local-recorder` URI | Public recorder label; HTTP(S) URI or opaque URN. |
| `--invocation-id` | Canonical statement SHA-256 | Public explicit ID, or `sha256:<hex>` derived with that field omitted. |
| `--source-uri` / `--source-commit` | paired optional inputs | Asserted original source and full 40- or 64-digit commit, labeled `caller_assertion`. |
| `--started-on` / `--finished-on` | paired optional RFC 3339 inputs | Asserted original-build times, normalized to UTC with precision preserved. |

Original build times are omitted unless explicitly supplied. Neither the clock nor `SOURCE_DATE_EPOCH`
populates them. Equal artifact bytes, checkout/recorder metadata, IDs and time claims yield identical
compact JSONL; pinning times alone does not make different hosts or toolchains identical.
URI credentials, queries and fragments are removed; no hostname, host root or environment dump is
emitted. Explicit IDs and URI paths must contain public metadata.

The [versioned recorder contract](docs/build-types/record/v1.md) defines every field and parsing limit.
The two [synthetic fixtures](tests/fixtures/m3/README.md) show observations alone and explicit claims.

### Container image

`docker build -t buildtrace:local .` builds the static CLI in an Alpine runtime that includes `git`
for manifest capture and runs as UID/GID 65532. Files used for capture must be readable by that user,
and an output directory must be writable. For verification, mount the manifest and artifacts read-only:

```bash
docker run --rm --network none --read-only \
  --mount "type=bind,src=$(pwd),target=/work,readonly" \
  buildtrace:local verify --manifest /work/buildtrace.json --root /work --json
```

`bash tests/container/smoke.sh buildtrace:local` checks M2 hashing/verification and M3 unsigned
record/inspect, deterministic output, parsing bounds, output protection and negative exit codes.
The test uses temporary container memory, with network disabled and a read-only root filesystem.
The CI workflow defines the same check.

### Manifest flags

| Flag | Default | Meaning |
|---|---|---|
| `--artifact` | required, repeatable | A file, directory or terminal symlink the build produced. |
| `--out` | stdout | Where to write the manifest. |
| `--repo` | `.` | The repository the build came from. Must be inside a git repository. |
| `--built-at` | now | The build timestamp, RFC 3339. Overrides `SOURCE_DATE_EPOCH`. |
| `--builder-id` | `local` | A builder label; no identity is authenticated. |

The M2 manifest timestamp can also be pinned with `SOURCE_DATE_EPOCH`. With all metadata and artifact
inputs equal, including that timestamp, two runs produce byte-identical manifests. M3 uses the
separate original-build time claim policy described above.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Manifest/unsigned statement written, unsigned statement inspected, or artifacts match the M2 manifest. |
| 1 | Verification mismatch: `digest_mismatch`, `kind_mismatch` or `size_mismatch`. |
| 2 | Invalid input, missing artifact, unsupported format/signing mode or malformed/bounded-out JSONL. |
| 3 | Tool or I/O error, including unreadable input and unwritable output. |

Verification of signed attestations remains M4. M3 generation and inspection do not return a
provenance verification verdict.

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/buildtrace` | The entry point: a thin wrapper around `internal/cli` |
| `internal/cli` | The commands and their exit codes |
| `internal/metadata` | Git state, toolchain and platform capture |
| `internal/manifest` | The `buildtrace.json` model, serialiser and artifact collection |
| `internal/testrepo` | Throwaway git repositories for the tests |
| `internal/hashing` | Artifact hashing and directory determinism (M2) |
| `internal/attestation` | M3 artifact observations, statement construction and bounded offline inspection |
| `internal/signing` | Sigstore keyless and local key signing (M4) |
| `internal/verify` | Unsigned manifest comparison (M2); signature and policy checks remain M4 |
| `internal/sbom` | CycloneDX generation (M6) |
| `pkg/intoto` | in-toto statement types, no external dependency needed to read them (M3) |
| `tests/fixtures/m3` | Two synthetic unsigned provenance goldens |
| `tests/schemas` | Isolated pinned upstream validators; no CLI runtime dependency |

## Roadmap

M3 is **complete and merged** through [PR #2](https://github.com/Shellghostt/BuildTrace/pull/2), with successful
[main CI](https://github.com/Shellghostt/BuildTrace/actions/runs/44006031195). Read the
[acceptance evidence](docs/testing/m3-provenance.md) and [phase contract](docs/phases/M3.md).
[M4 requirements](docs/phases/M4.md) and [proposed signing/offline-verification ADR](docs/adr/0006-m4-signing-and-offline-verification.md)
prepare the next phase; M4 implementation has not started.

| Milestone | Deliverable | Status |
|---|---|---|
| M1 | Build metadata collection and manifest generation | **Done** (v0.1.0) |
| M2 | Artifact hashing and manifest verification | **Done (merged)** |
| M3 | Unsigned in-toto/SLSA record and inspect | **Done (merged)** |
| M4 | Signing and verification | Not started; documents prepared |
| M5 | GitHub Actions integration | Not started |
| M6 | SBOM support and reproducibility checks | Not started |

This roadmap mirrors [docs/PLAN.md](docs/PLAN.md) section 12. If the two disagree, the plan is correct and
the README is a bug.

## Testing

```bash
make test
make race
make lint
make memory-gate  # Windows/PowerShell: 1 GiB manifest, verify, record and memory gate
make schema-setup
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off make schemas
```

The unit tests use a real `git` binary against a throwaway repository in a temporary directory, so
they exercise the actual behaviour of the collector rather than a mock of it. The legacy M1 manifest
format is covered by a golden file, which can be regenerated explicitly:

```bash
BUILDTRACE_WRITE_GOLDEN=1 go test ./internal/manifest -run TestWriteTheGoldenFile
```

M2 adds the same independently computed directory golden on Windows and Linux, actual CLI offline
verification, malformed-input and tamper tests. The 1 GiB run measured 44.04 MiB peak working set
for capture and 7.61 MiB for verification. Method and limits are in the
[validation report](docs/testing/m1-m2-validation.md).

M3 adds two byte-for-byte goldens, isolated offline upstream format checks, strict bounded JSONL
tests and real CLI/container record/inspect checks. Native Windows `make race` now passes with a
64-bit MSYS2 UCRT64 compiler. The final 1 GiB recording run used 9.09 MiB peak working set, below the
64 MiB gate. Commands, test mapping, schema pins and limitations are in
[M3 validation](docs/testing/m3-provenance.md) and [memory/profiling evidence](docs/benchmarks/m3-provenance.md).
On Windows, use `VERSION=m3-local` with Make targets to bypass the existing Unix version-discovery
expression, and use the pinned compiler/offline setup documented in those reports.

## Project standards

- Conventional Commits, Semantic Versioning, `main` is always green.
- Every release is produced by CI, never by a laptop.
- Status claims must match reality. Unbuilt features are marked "Not started", not "coming soon".
- Decisions are recorded as ADRs in [docs/adr/](docs/adr/).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/PLAN.md](docs/PLAN.md) first. Issues labelled
`good first issue` are scoped for a first pull request.

## Using an AI assistant on this repository

Read [docs/PLAN.md](docs/PLAN.md) end to end, including the machine context block at the top. It states
what exists, what does not, and which claims are forbidden. Do not describe planned behaviour as
implemented behaviour.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
