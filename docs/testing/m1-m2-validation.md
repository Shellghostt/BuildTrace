# BuildTrace M1/M2 validation - 2026-11-14

Implementation is on `feat/m2-implementation`, unreleased. Main remains
`a7be484a890517becf5a14685c4d63c4295b9e6e`.

## Executed checks

- Native Go 1.26.11 tests, vet and golangci-lint 2.15.0 pass (zero lint issues).
  govulncheck reports no vulnerabilities. The runtime has no third-party dependencies.
- Linux/Ubuntu WSL race suite passes, using the same pinned Go toolchain and a 64-bit GCC compiler.
- Windows and Linux pass the same independently computed directory golden
  `af7be037cf7f2ef0beef5b69314747e532b6ce13738578a8f8f362c105f98727`.
  Tests vary creation order and metadata, include UTF-8 names and empty directories, and verify
  symlink targets are not followed, including dangling links and links outside the artifact tree.
- Actual compiled CLI runs `verify --manifest` with git removed from PATH, matches the manifest,
  rejects version 99 with exit 2 and detects a one-bit `hello` to `jello` change as
  `digest_mismatch` naming `app`, exit 1. Missing artifacts exit 2.
- Other regressions cover directory additions, kind/size mismatch, missing digests, malformed sizes,
  duplicate keys/paths, unknown fields, non-integer versions and oversized/trailing JSON.
- Manifest output is protected from artifact replacement and self-inclusion. A destination symlink
  is replaced without truncating its target. Mutation checks use rooted stat information on Windows;
  cached directory-entry info produced a false change and was corrected.
- CLI builds pass for Linux, macOS and Windows, on amd64 and arm64.

- Parser fuzzing passed 286,855 executions in the initial 10-second run. After final UTF-8 and
  case-variant key checks, another run passed 8,167 executions with a valid-document seed and the
  retained corpus. Full native tests, Linux race tests, lint, vet, audit and six target builds passed
  again after those changes.
- Aggregate statement coverage measured during validation is 83.0% with `-coverpkg=./...`.
  CI YAML parses and `git diff --check` is clean.

## 1 GiB memory and tamper gate

`tests/bench/large-artifact.ps1` writes 1,024 one-MiB blocks to a real file under ignored `bin/`,
computes an independent .NET SHA-256 while writing, then invokes the actual Go CLI. The file is
1,073,741,824 bytes and its digest is
`49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14`.

| Check | Exit | Peak working set | Elapsed |
|---|---:|---:|---:|
| Capture manifest and hash artifact | 0 | 46,178,304 bytes / 44.04 MiB | 1.3683 s |
| Verify manifest and rehash artifact | 0 | 7,979,008 bytes / 7.61 MiB | 0.7755 s |
| Flip one byte at offset 512 MiB | 1 (`digest_mismatch`) | — | — |
| Remove the generated artifact | 2 (`artifact_missing`) | — | — |

Both measured CLI runs stay below the 64 MiB gate. The method reads Windows' OS-reported peak working
set every 10 ms while the process runs. This is resident memory for the CLI process, not combined
memory of its git subprocesses or the filesystem cache. The generated file was cached locally;
elapsed times do not establish cold-disk or production throughput. File contents stream through one
reused 1 MiB buffer. Directory sorting uses O(entry count) metadata, capped at 100,000 entries;
the single-file constant-memory result does not imply constant memory for unlimited directory entries.

Reproduce with `make memory-gate` on Windows/PowerShell. Each run creates its own ignored directory,
stores the report and removes only its generated large artifact after the missing-file test.
CI now defines this gate on Windows, portable tests on three OSes, and a Linux parser fuzz smoke test.

## Verification scope and remaining validation

M2 checks artifact bytes, kind and size against a supplied unsigned manifest. A successful result
does not authenticate the source metadata, builder label or manifest. Signing and identity policy
remain M4, provenance generation remains M3. Callers stop writers during hashing; metadata checks
detect common changes but do not provide a filesystem snapshot. See ADR 0004 for canonical bytes.

Native macOS execution and the updated remote CI have not run locally. Docker Desktop was unavailable
during final validation, so a fresh container image was not built; Linux tests use WSL instead.
The existing Dockerfile builds a static CLI, and six native target builds passed. No release or push
is part of this implementation.
