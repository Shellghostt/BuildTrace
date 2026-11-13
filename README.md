# BuildTrace

> An open-source build provenance and artifact verification system.

![status](https://img.shields.io/badge/status-M1_manifest-orange)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)

**Status: M1 (v0.1.0).** BuildTrace reads the facts about a build — the commit, the dirty state, the
remote, the builder, the toolchain — and writes them to a deterministic `buildtrace.json`.

**It hashes nothing, signs nothing and verifies nothing.** The manifest records the *name*, *path* and
*size* of each artifact. It says nothing about the bytes. Nothing in this release lets you verify
anything, and nothing in this release claims to.

## Why this exists

"We built this binary from that commit" is a claim, not evidence. Provenance only means anything
if someone else can verify it independently: the artifact digest, the inputs, and the identity that
attested to them. BuildTrace generates that evidence and, more importantly, verifies it.

## What it does today

| Capability | Milestone | Status |
|---|---|---|
| Capture source commit, dirty state and remote URI | M1 | **Done** |
| Record the build environment (builder, OS, toolchain) | M1 | **Done** |
| Write a deterministic `buildtrace.json` | M1 | **Done** |
| Strip credentials from the recorded remote | M1 | **Done** |
| Generate and verify artifact hashes | M2 | Not started |
| Generate provenance attestations (in-toto, SLSA) | M3 | Not started |
| Verify artifact signatures | M4 | Not started |
| CI/CD integration | M5 | Not started |
| Track dependencies | M6 | Not started |
| SBOM support | M6 | Not started |
| Reproducibility checks | M6 | Not started |

## What this release does **not** prove

This section is the most important one in this README, and it is reproduced from
[docs/PLAN.md](docs/PLAN.md) section 9.2. It changes only when that section changes.

- **It does not prove the artifact is the one that was built.** There is no digest in an M1 manifest.
- **It does not prove the artifact is safe, trustworthy or unmodified.** Nothing here analyses the
  artifact's contents.
- **It does not prove the build was reproducible.** Two builds of the same commit may differ, and
  nothing in this release compares them.
- **It does not attest to who built it.** The `builder.id` is whatever the caller passed on the command
  line. It is a label, not an identity.
- **It does not attest to the build's dependencies.** Nothing is recorded about the module graph.
- **It is not a signature.** The manifest is plain JSON and can be edited by anyone.

## Architecture

```mermaid
flowchart LR
    SRC[Source repository] --> RUN[Build runner]
    RUN --> META[Build metadata collector]
    META --> ART[Artifact generator]
    ART --> HASH[Artifact hashing]
    HASH --> PROV[Provenance generator]
    PROV --> SIGN[Signed attestation]
    SIGN --> VER[Verification engine]
    VER --> CLI[CLI verification]
    VER --> CICD[CI/CD integration]
    VER --> REP[Verification report]
```

Full reasoning, data model, API surface and failure behaviour are in [docs/PLAN.md](docs/PLAN.md).
The shape of what exists today is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Engineering challenge

Making build provenance verifiable and trustworthy, not just generating a JSON file that
claims an artifact is authentic. Every field in an attestation must map to an input someone else can
recompute.

## Quickstart

Requires Go 1.26+ and `git`.

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

Real output from a local run:

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

Note what is **not** in there: a `digest` field. It arrives with M2, when the artifacts are actually
hashed.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--artifact` | required, repeatable | A file the build produced. Directories are rejected until M2. |
| `--out` | stdout | Where to write the manifest. |
| `--repo` | `.` | The repository the build came from. Must be inside a git repository. |
| `--built-at` | now | The build timestamp, RFC 3339. Overrides `SOURCE_DATE_EPOCH`. |
| `--builder-id` | `local` | The identity of the builder. This is a label, not an attestation. |

The build timestamp can also be pinned with the `SOURCE_DATE_EPOCH` environment variable, which is the
convention reproducible-build tooling uses. With the timestamp pinned, two runs over the same inputs
produce byte-identical manifests.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The manifest was written. |
| 1 | Verification failed. No verification exists in M1, so this code is never returned yet. |
| 2 | Invalid input: outside a git repository, a missing artifact, a directory artifact, a malformed timestamp. |
| 3 | Tool error: an unwritable output file, or a command that is not implemented yet. |

`record`, `verify` and `inspect` are not implemented. They exit 3 and say so.

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/buildtrace` | The entry point: a thin wrapper around `internal/cli` |
| `internal/cli` | The commands and their exit codes |
| `internal/metadata` | Git state, toolchain and platform capture |
| `internal/manifest` | The `buildtrace.json` model, serialiser and artifact collection |
| `internal/testrepo` | Throwaway git repositories for the tests |
| `internal/hashing` | Artifact hashing and directory determinism (M2) |
| `internal/attestation` | Statement and predicate construction (M3) |
| `internal/signing` | Sigstore keyless and local key signing (M4) |
| `internal/verify` | Signature and digest verification, policy checks (M4) |
| `internal/sbom` | CycloneDX generation (M6) |
| `pkg/intoto` | in-toto statement types, no external dependency needed to read them (M3) |
| `tests/fixtures` | Committed artifacts for offline verification tests (M4) |

## Roadmap

| Milestone | Deliverable | Status |
|---|---|---|
| M1 | Build metadata collection and manifest generation | **Done** (v0.1.0) |
| M2 | Artifact hashing and manifest verification | Not started |
| M3 | in-toto provenance generation | Not started |
| M4 | Signing and verification | Not started |
| M5 | GitHub Actions integration | Not started |
| M6 | SBOM support and reproducibility checks | Not started |

This roadmap mirrors [docs/PLAN.md](docs/PLAN.md) section 12. If the two disagree, the plan is correct and
the README is a bug.

## Testing

```bash
make test
```

The unit tests use a real `git` binary against a throwaway repository in a temporary directory, so
they exercise the actual behaviour of the collector rather than a mock of it. The manifest format is
covered by a golden file:

```bash
BUILDTRACE_WRITE_GOLDEN=1 go test ./internal/manifest -run TestWriteTheGoldenFile
```

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
