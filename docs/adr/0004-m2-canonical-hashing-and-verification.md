# ADR 0004 - M2 canonical hashing and manifest verification

- Status: accepted
- Date: 2026-11-14
- Supersedes: ADR 0002 decisions 1, 13 and 15 for the implemented M2 scope

## Context

M2 adds artifact hashing, directories and unsigned manifest verification. A portable directory
digest needs a defined byte format; hashing concatenated file contents loses names and boundaries.
Verification must enforce the format version and distinguish a byte match from authenticated provenance.

## Decisions

1. Keep `schemaVersion: 1`. The existing digest field now contains SHA-256; new manifests also
   record `kind` as `file`, `directory` or `symlink`. An omitted kind means file for v1 compatibility.
   M1 manifests remain serializable but verification refuses artifacts without a digest.
2. File SHA-256 is the ordinary digest of raw bytes, read with a reusable 1 MiB buffer.
3. Directory SHA-256 starts with ASCII `buildtrace-directory-v1` followed by NUL. Entries are
   globally sorted by UTF-8 relative path bytes, with forward slash separators. The root itself
   is omitted. Each record starts with one byte `f`, `d` or `l`, then a length-prefixed path.
   Lengths and file byte counts are unsigned 64-bit big-endian integers. A file record then
   contains its byte count and the 32 raw SHA-256 bytes. A directory record has no further fields.
   A symlink record contains a length-prefixed target string with platform separators converted
   to forward slashes. Empty directories are entries. Timestamps, permissions, owner and host
   path are excluded. Literal backslashes and invalid UTF-8 in entry names are rejected.
4. A terminal symlink digest starts with `buildtrace-symlink-v1` followed by NUL, then its
   length-prefixed target string. Links, including dangling links and directory links, are never
   followed as artifacts or directory entries. Absolute targets remain host-specific strings.
5. File size is bytes read; symlink size is normalized target byte length. Directory size sums
   regular file bytes and normalized link target bytes. Contents stream, while sorted path metadata
   uses O(entry count) memory, bounded at 100,000 directory entries. This bound is independent
   of file byte size. Unsupported devices/sockets are rejected. Directory reads use `os.Root`
   to contain access if a child is replaced, and common concurrent changes are checked via metadata.
   Callers stop writers during capture and verification; this is not a filesystem snapshot.
6. `verify --manifest <file> [--root <dir>] [--json]` recomputes all artifact kinds, digests and sizes,
   stopping at the first failure. Relative paths resolve from the explicit root (default current
   directory), independent of the manifest's location. Absolute paths preserve M1 behavior and
   are host-specific. Verification needs neither git nor network access.
7. The reader accepts one JSON document up to 16 MiB, bounded to 64 nesting levels. It rejects
   duplicate keys/paths, unknown fields, malformed sizes/kinds/digests and unsupported versions.
   Reports declare `scope: unsigned_manifest`; success is `matched`. Mismatch reasons are
   `digest_mismatch`, `kind_mismatch` and `size_mismatch` (exit 1). Missing artifact is
   `artifact_missing` (exit 2); malformed manifest/version is exit 2; unreadable I/O is exit 3.
8. Manifest output cannot replace an artifact or live inside a selected directory artifact, including
   through a parent symlink. Output uses a temporary sibling and rename, avoiding destination
   symlink/hardlink truncation. The format remains deterministic for pinned metadata.

## Consequences

A successful M2 check establishes consistency with the supplied unsigned manifest. An attacker can
edit both the artifact and manifest. Source commit, builder identity, signature, dependencies and
artifact safety are not verified. Provenance and signing remain M3/M4. A change to canonical hashing
or version semantics requires a new ADR and an explicit compatibility decision.
