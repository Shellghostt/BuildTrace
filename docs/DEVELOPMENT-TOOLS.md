# Development tools and memory validation

Audit date: 2026-11-17. These are development aids, not product features or substitutes for tests.
Read [PLAN.md](PLAN.md), the [M3 requirements](phases/M3.md) and accepted [ADRs](adr/) first.

## CodeGraph

CodeGraph 1.6.2 is installed. The existing index was refreshed after M3 source changes; generated
data remains ignored. Check freshness when switching branches or pulling changes:

```bash
codegraph status
codegraph sync
```

For indexed code, use the CodeGraph MCP exploration tool with this repository's absolute
`projectPath` and the symbol/flow you need. Read its returned source and callers before edits;
use direct source/config searches for areas the graph does not capture. Unresolved references remain,
so the graph does not prove complete dependency coverage, correctness or test coverage.
Builds and CI do not require the local index. Generated databases/transient files stay ignored through
`.codegraph/.gitignore`; do not commit them. Initialize a new index only when intentionally enabling it.

## MemGuard and runtime profiling

MemGuard is JavaScript/TypeScript static resource analysis. It does not analyze Go/Python, inspect a
running process, or prove there are no leaks. Pin its version, check the reported file count and
diagnostics, and inspect resource findings rather than suppressing them to get a green result.

Use Go heap/allocation profiles plus process RSS for repeated hashing, recording, parsing and failed/cancelled writes. Retain the [M2 memory gate](testing/m1-m2-validation.md) and independent digest checks; a single 1 GiB run establishes a workload bound, not lifetime leak freedom. MemGuard has no current Go coverage.

The [M3 report](benchmarks/m3-provenance.md) records a real 1 GiB manifest/verify/record gate and a
synthetic repeated `Build`/`Read` allocation/heap profile. The latter excludes artifact hashing,
git subprocesses and output writes. Native Windows race now passes with 64-bit GCC 16.2.0 UCRT64;
the former 32-bit compiler limitation is not a current M3 skip.

For runtime changes, reproduce the suspected workload, record a baseline, repeat the same lifecycle,
then compare live/retained memory after cleanup. Capture allocation rate, heap/RSS, goroutines or
active handles as applicable, and latency/drop metrics. Go benchmarks can collect `-benchmem` and
`-memprofile` for a specific package/workload; inspect profiles with `go tool pprof`. Node supports
heap snapshots/inspector; Python supports `tracemalloc`. Choose the native tool for the process.
Record versions, duration, inputs, commands and limitations in a validation report.
Profile only when the change or suspected fault justifies it; a documentation edit needs link/diff checks.

## Memory Analyzer

The locally installed analyzer is Eclipse MAT 1.17.0, configured with Java 21 and a 4 GiB analyzer heap.
It reads Java/HPROF heap dumps. This repository has no Java runtime workload; MAT is therefore not an
appropriate gate for it. MAT's own heap setting is not this project's memory budget.
Heap dumps/profiles can contain secrets and user data; keep them local/ignored and use synthetic inputs.

## Handoff between editors or assistants

State the branch and commit, read the phase/ADRs, refresh the graph after source changes, and provide
the exact failing command, output and minimal synthetic fixture. Keep implementation on a feature
branch. A skipped integration test must be reported as skipped, with its missing dependency; it is not
a passing check. Preserve local Docker volumes and use disposable databases for migration tests.
