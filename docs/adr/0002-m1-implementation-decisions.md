# ADR 0002 - M1 implementation decisions

- Status: accepted
- Date: 2026-11-13
- Deciders: Aditya

## Context

M1 delivers the first usable thing BuildTrace can do: describe a build. The decisions below were made
while building it, are expensive to change later, and are not fully determined by PLAN sections 7 to
10.

The theme of every decision here is the same one that runs through the whole plan: **a manifest is a
document that gets uploaded, committed and attached to releases. Anything in it is public.** The
conservative choice is always the one that can be defended.

## Decisions

1. **The M1 command is `manifest`, and the others say they do not exist yet.** `record`, `verify` and
   `inspect` appear in the command surface of PLAN section 8, but they arrive in M3 and M4. They exit 3
   and print "planned for a later milestone and is not implemented yet". A stub that exits 0 would be
   worse than a command that is missing, because a CI pipeline would treat it as a pass.
2. **The commit is the full 40-character SHA.** A short SHA is ambiguous and cannot be checked against
   a repository without a lookup. The plan's sketch shows an abbreviation; the implementation does not.
3. **The remote URI is normalised to the `git+` form, and credentials are stripped.** Git produces
   several remote spellings (`https://`, `ssh://`, `git://` and the scp-like `git@host:owner/repo`).
   They all become one canonical `git+` URI so that a consumer can compare a manifest against a
   repository without knowing which spelling the developer happened to use.
4. **Credentials in the remote are removed, not masked.** `https://user:token@example.com/repo.git`
   becomes `git+https://example.com/repo`. A `[redacted]` marker would still have shown the URL shape
   and could still have leaked a partial token; removing the userinfo removes it entirely.
5. **A repository without a remote is not an error.** A local build of an unpublished project has no
   remote, and that is a legitimate state. The manifest records an empty `uri`.
6. **`origin` is preferred, but the first other remote is used when there is no `origin`.** A
   repository with only an `upstream` remote is still a repository with a known source.
7. **The `git` subprocess gets an allowlisted environment.** The collector replaces the environment
   entirely: `PATH`, `HOME`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `USER`, `USERNAME`, `SYSTEMROOT`,
   `TEMP`, `TMP` and `GIT_CEILING_DIRECTORIES`, plus `GIT_TERMINAL_PROMPT=0` and
   `GIT_OPTIONAL_LOCKS=0`. Every other variable, and in particular every credential, is left out. The
   two `GIT_` settings mean that a missing object or a locked index cannot hang a build waiting for a
   password.
8. **`GIT_DIR` and `GIT_WORK_TREE` are deliberately excluded.** They would point the collector at a
   different repository than the one the user named on the command line.
9. **`GIT_CEILING_DIRECTORIES` is allowed through.** It is not a credential but a deliberate
   instruction about where repository discovery may stop. A user who sets it expects git to honour it,
   and BuildTrace runs git.
10. **The "no commits yet" case is detected without parsing git's error message.** Git says "unknown
    revision" in one version and "does not have any commits yet" in another, and the wording is not an
    interface. The repository is asked whether it holds any ref at all instead.
11. **The Go version comes from `runtime.Version()`, not from a `go version` subprocess.** It is the
    version the binary was actually built with, which is the thing worth recording, and it costs
    nothing.
12. **The git version is recorded but optional.** When git is not installed the field is absent. An
    empty string would be indistinguishable from a broken git.
13. **The manifest has no `digest` field in M1.** Hashing is BT-006 and BT-007, which are M2. The
    field is omitted rather than emitted empty, so that an M1 manifest cannot be mistaken for a
    manifest whose artifacts were hashed. `internal/manifest` already has the field in the model, as a
    pointer with `omitempty`, so M2 is a small change rather than a format break.
14. **The artifact path is relative to the repository root, with forward slashes.** A manifest that
    records `C:\Users\someone\build\dist\app` leaks the layout of the machine that produced it and
    differs on every other machine. A file outside the repository keeps its absolute path, because
    pretending it is relative would point at the wrong file.
15. **Directory artifacts are rejected with a message that names M2.** Recording the size of a
    directory would be a number that means something else entirely, and a deterministic directory
    digest does not exist yet.
16. **The manifest is deterministic.** The artifacts are sorted by path, the field order is the struct
    order, the indentation is two spaces, the output ends with a newline and HTML escaping is off. The
    same inputs produce the same bytes.
17. **The build timestamp is the only value that changes between two runs, and it can be pinned.**
    `--built-at` takes an RFC 3339 timestamp and `SOURCE_DATE_EPOCH` takes a Unix timestamp. The flag
    wins over the environment variable. The timestamp is truncated to the second and converted to UTC.
18. **`internal/manifest` and `internal/cli` are new packages.** The plan's layout has no home for the
    `buildtrace.json` format, and `internal/hashing` does not exist until M2 and is about hashing, not
    serialisation. `internal/cli` exists so that the exit codes and the output of every command can be
    tested: a test that cannot call `main` cannot check them.
19. **The exit codes are the plan's codes.** 0 is success, 2 is invalid input (outside a repository, a
    missing artifact, a directory artifact, a malformed timestamp), 3 is a tool error (an unwritable
    output file) or a command that is not implemented yet. Exit 1, "verification failed", has no path
    in M1 because nothing is verified yet.
20. **A dirty working tree is a warning, not an error.** The manifest records `dirty: true` and the
    command prints a warning to stderr. It does not refuse to run: PLAN section 16 asks the same
    question and records the answer, "warn, set `dirty: true`, allow override".
21. **The Go floor is 1.23 and the tool has no third-party dependencies.** The whole M1 tool is the
    standard library and `git`. A supply-chain tool that pulls in dependencies to read a git commit is
    making the problem worse.

## Consequences

- The manifest describes a build. It does not prove anything about the artifact, because it contains
  no digest. The README says so, and the M1 milestone note in PLAN section 12 says so.
- The secret-exclusion test plants a fake token in the remote URL, in three well-known environment
  variables and in the builder id, and asserts that the token appears nowhere in the manifest, in
  stdout or in stderr.
- The unit tests use a real `git` binary against a throwaway repository in a temporary directory.
  Repository discovery is stopped at the parent of that directory with `GIT_CEILING_DIRECTORIES`,
  because a machine may well have a repository further up the tree.
- M2 starts at BT-006. The manifest format is versioned by `schemaVersion` (currently 1); M2 adds the
  digest field and starts enforcing the version.
- The race detector could not be run on the machine that produced this release: the only C compiler
  there is MinGW GCC 6.3.0, which cannot build a 64-bit race-enabled binary
  (`cc1.exe: sorry, unimplemented: 64-bit mode not compiled in`). The unit suite passes without it and
  CI runs `go test -race` on ubuntu-latest, but that workflow has never executed because the
  repository has no remote yet.
