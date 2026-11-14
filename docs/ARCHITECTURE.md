# BuildTrace Architecture

**Status: M2 implemented, unreleased.** Metadata collectors, deterministic manifests, file/directory/
symlink hashing and offline unsigned manifest verification exist. Tests use real git and the actual
CLI. Provenance generation, signing, identity policy and SBOM generation remain later milestones.
The authoritative specification is
[PLAN.md](PLAN.md), and section 0 there is the current truth.

## Context

An open-source build provenance and artifact verification system.

"We built this binary from that commit" is a claim, not evidence. Provenance only means anything
if someone else can verify it independently: the artifact digest, the inputs, and the identity that
attested to them. BuildTrace generates that evidence and, more importantly, verifies it.

## Shape

```mermaid
flowchart LR
    SRC[Source repository] --> RUN[Build runner]
    RUN --> META[Build metadata collector]
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

## What exists today

```mermaid
flowchart LR
    REPO[(Git repository)] --> GC[git metadata collector]
    GC --> SRC[source: uri, commit, dirty]
    FS[(Built files)] --> AC[artifact collection]
    AC --> HASH[streaming / canonical SHA-256]
    HASH --> ART[kind, name, path, size, digest]
    SRC --> MAN[manifest model]
    ART --> MAN
    TC[toolchain collector] --> MAN
    MAN --> JSON[buildtrace.json]
    JSON --> VERIFY[unsigned manifest verifier]
    FS --> VERIFY
```

| Package | Responsibility |
|---|---|
| `internal/metadata` | The facts about a build: the commit, the dirty state, the normalised remote, the Go and git versions, the platform. An allowlist decides what is read; the environment is never dumped. |
| `internal/manifest` | Format v1, deterministic serialization, hashed artifact collection and bounded strict reader. |
| `internal/hashing` | Raw file SHA-256 with a 1 MiB buffer; sorted canonical directory/symlink digests. |
| `internal/verify` | Recompute kinds, sizes and digests, with stable failure reasons and unsigned scope. |
| `internal/cli` | The commands and their exit codes. It exists so that the exit codes and the output can be tested. |
| `cmd/buildtrace` | A thin entry point that wires the standard streams into `internal/cli` and turns the returned code into a process exit code. |

## Data path

1. The caller names the artifacts and the repository.
2. The git collector asks `git` for the top level, for `HEAD`, for the working tree status and for the
   remote. It runs `git` with an allowlisted environment and no shell.
3. The remote is normalised to a `git+` URI and its credentials are removed.
4. The artifact collector resolves each path relative to the repository root and records its name, its
   relative path, kind, byte count and digest. Terminal symlinks and directory links are recorded
   without following them. Directory reads use `os.Root` and common concurrent changes are checked.
5. The manifest is serialised: the artifacts are sorted by path, the field order is the struct order,
   the indentation is two spaces, and the timestamp is truncated to the second in UTC.

The manifest is deterministic: the same repository, the same artifacts and the same declared timestamp
produce the same bytes.

Verification reads one manifest up to 16 MiB and rejects duplicate fields/paths, unknown fields and
unsupported versions. Relative paths resolve from `--root` (current directory by default). Digests and
declared sizes/kinds are recomputed; metadata labels are not authenticated. Directory contents stream,
while sorting keeps at most 100,000 entries. The byte format is specified in ADR 0004.

## Failure behaviour

| Failure | What happens |
|---|---|
| The directory is not inside a git repository | Exit 2, with a message that names the directory. |
| The repository has no commits yet | Exit 2, with a message that says so. |
| An artifact does not exist | Exit 2, naming the artifact. |
| Artifact bytes, kind or size disagree | Exit 1, naming the artifact and exact mismatch. |
| Malformed manifest or unsupported schema version | Exit 2; no guessed interpretation. |
| Artifact cannot be read during verification | Exit 3; missing artifacts specifically exit 2. |
| The build timestamp is not RFC 3339 | Exit 2, explaining the expected format. |
| The output file cannot be written | Exit 3. |
| `record` or `inspect` is called | Exit 3, saying the command is planned for a later milestone. |
| The working tree is dirty | Not a failure. `dirty: true` is recorded and a warning goes to stderr. |
| `git` is not installed | The source is unavailable, so the command fails. The Go version is still known. |

## Secret handling

A manifest gets uploaded, committed and attached to releases. Three rules follow from that:

- The collector reads named fields. It never dumps the environment.
- The `git` subprocess gets an allowlisted environment, so a credential in the environment of
  BuildTrace is not reachable from git.
- The one input where a credential can appear by accident is the remote URL, and its userinfo is
  removed before the URI is recorded.

The secret-exclusion test plants a fake token in the remote URL, in `GITHUB_TOKEN`, in `NPM_TOKEN`, in
`AWS_SECRET_ACCESS_KEY` and in the builder id, and asserts that it appears nowhere in the manifest, in
stdout or in stderr.

## Component responsibilities

See [PLAN.md](PLAN.md) section 6 for the responsibility of each box, the request and event flows, and the
failure behaviour of each stage.

## What is deliberately absent

See [PLAN.md](PLAN.md) section 4 (non-goals). If a component is not on that diagram, it is not part of the
design.
