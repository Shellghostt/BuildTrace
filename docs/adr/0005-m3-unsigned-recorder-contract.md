# ADR 0005 - M3 unsigned artifact recorder and inspection

- Status: accepted
- Date: 2026-11-17
- Supersedes: ADR 0002 decision 1 for `record` and `inspect` only

## Context

M3 records existing artifacts. It does not execute or witness their original build. The phase
requirements distinguish byte observations, checkout observations and caller assertions. The
illustrative PLAN mapping included guessed dependencies/byproducts and an unowned build-type URI;
those are not an implementation contract. M2 hashing, manifests and verification remain unchanged.

## Decisions

1. Use in-toto Statement v1 and SLSA provenance predicate v1. The build type is
   `https://github.com/Shellghostt/BuildTrace/blob/main/docs/build-types/record/v1.md`.
   This repository controls that namespace. Its versioned document defines an artifact observation
   operation, not an original build execution. Future incompatible semantics require a new version.
2. `record` defaults to `--sign none`; every other signing request exits 2 before collecting inputs.
   It emits one compact unsigned statement followed by LF, to stdout or an atomic sibling-file rename.
   It does not generate a manifest byproduct. `manifest` remains the separate M2 command.
3. Select one to 1,000 artifacts inside the repository root. Terminal symlinks are hashed without
   following their targets; a parent symlink may not escape the root. Subject names are canonical
   repository-relative paths, not basenames. Reject duplicate/colliding selections and output inside
   or replacing an artifact. M2 canonical bytes, bounds and mutation checks are reused unchanged.
4. External parameters contain artifact selections and, only when both `--source-uri` and
   `--source-commit` are supplied, a source assertion explicitly labeled `caller_assertion`.
   Internal parameters contain the observed checkout commit/dirty state/sanitized remote, recorder
   version and Go/git versions, OS/architecture, and observed artifact kinds/byte counts. No hostname,
   absolute host path, environment dump, workflow inference or original toolchain inference is emitted.
5. A source assertion may also appear as one resolved dependency annotated `caller_assertion`.
   Checkout observation alone produces no resolved dependencies. Byproducts and builder dependencies
   are omitted because this operation does not capture any. Full 40- or 64-digit commit IDs are required.
6. `builder.id` is the explicit `--builder-id` label, defaulting to
   `https://github.com/Shellghostt/BuildTrace#local-recorder`. It does not authenticate an identity.
   Network URI inputs have userinfo, query and fragment removed; local source remotes are omitted.
   The builder flag also accepts an opaque URN. Explicit labels must contain public metadata only.
7. An explicit `--invocation-id` is a bounded public identifier. Otherwise derive `sha256:<hex>`
   from the compact canonical statement with invocationId omitted. The hash includes all remaining
   inputs, including recorder versions and any declared timestamps. There is no random default.
8. Original build times are omitted unless both `--started-on` and `--finished-on` are explicitly
   supplied. These are caller assertions, not observation times. Normalize to UTC, preserve precision
   and reject reversed/out-of-range times. `SOURCE_DATE_EPOCH` and the current clock do not populate them.
9. `inspect --attestation <file> [--json]` reads offline without git or any command execution. Its result
   is `scope: unsigned_statement`, `status: inspected`. It never recomputes artifacts or checks signatures.
   Reject unsupported statement/predicate URIs, DSSE, malformed types and duplicate JSON keys. Accept
   unknown compatible fields with case-sensitive matching and preserve them in the JSON report's raw
   statement. An unknown build-type URI is displayed without interpreting its semantics.
10. Bound input to 16 MiB, 64 nesting levels and 200,000 JSON tokens; bound subject/resource arrays to
    1,000. Accept exactly one physical JSON line ending in LF or CRLF. Empty, unterminated, pretty-printed,
    multi-record and trailing-record input fails explicitly. Invalid input exits 2; I/O/tool failures
    exit 3. Existing M2 mismatch exit 1 and unsigned-manifest reports are unchanged.
11. The CLI remains standard-library-only. An isolated test module uses the official in-toto generated
    Protobuf JSON types and validators pinned to commit `50bf01716982189898823e90586075f37cd9bb7d`
    (`v1.2.1-0.20261021134056-50bf01716982`). Pin the SLSA v1.2 schema/specification at release commit
    `19e4e2f005f871270c4f555fc47afecfb37f3efe`. Commit source/checksum/license records. Download test
    dependencies during setup; execute fixture validation with module/schema network access disabled.
    These are format checks, not evidence of a SLSA level or honest build.

## Consequences

Equal artifact bytes and equal metadata, identifiers and declared times yield byte-identical statements.
Changing the checkout, recorder version or claims can change the statement even if artifact bytes do not.
Independent consumers can recompute subject digests and compare checkout observations; assertions remain
assertions. Neither generation nor inspection establishes artifact safety, build honesty, reproducibility
or builder identity. Stop writers during hashing; the inherited checks do not create a filesystem snapshot.

The runtime has no new dependencies. The upstream validation module is a development dependency with
its own pinned module checksums and audit. Accepted ADRs 0001–0004 are preserved.
