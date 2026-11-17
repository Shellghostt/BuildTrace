# M3 memory and recording/inspection profile — 2026-11-17

Verified source: `0981a57cfc76c5f7a5064507d9833e4bdaae31ce`, on `feat/m3-implementation`.
These local measurements accompany [M3 validation](../testing/m3-provenance.md).
They are resource evidence for the tested workloads, not a release benchmark or throughput claim.

## Real 1 GiB artifact gate

`make memory-gate VERSION=m3-local` runs [large-artifact.ps1](../../tests/bench/large-artifact.ps1)
on Windows using Go 1.26.11. The script writes 1,024 one-MiB zero-filled blocks, computing an
independent .NET SHA-256 as it writes. It then invokes the actual CLI for manifest, verify and record,
checking the digest and declared byte count against that independent result.

Artifact size: 1,073,741,824 bytes. SHA-256:
`49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14`.

| Process | Exit | Peak working set | Elapsed |
|---|---:|---:|---:|
| M2 manifest and hash | 0 | 46,227,456 bytes / 44.09 MiB | 0.9478079 s |
| M2 verify and rehash | 0 | 7,995,392 bytes / 7.625 MiB | 0.7482685 s |
| M3 unsigned record and hash | 0 | 9,527,296 bytes / 9.09 MiB | 0.9762075 s |

All three measured processes remain below the unchanged **64 MiB** gate.
Inspection exited 0 with unsigned scope, then still exited 0 after artifact removal.
A byte flipped at offset 512 MiB caused M2 `digest_mismatch`, exit 1; removing the file caused exit 2.
The M3 statement omitted original build times, and its subject digest/observed byte count agreed.

The script polls Windows' OS-reported peak working set every 10 ms during each long-running CLI
process. This excludes git subprocesses and filesystem cache. Quick inspection has no sampled RSS
gate. The generated file was just written and may be cached; elapsed times do not establish cold-disk
or production throughput. The recording observed the current dirty development checkout.
The tested working-tree source was subsequently committed as `0981a57`; the statement's observed
checkout was its then-current parent `d7b0ab3` with `dirty: true`. This observation does not claim
that the zero-filled test artifact was built from that checkout.

Each run uses a unique ignored `bin/m2-memory-*` directory, preserves its JSON report and removes only
its generated large artifact after the missing-file check. Docker volumes/data are unaffected.
The final local report is in `bin/m2-memory-de1bdd2666ce49bcbeef6d18a7e42890/result.json`.
Earlier successful runs had different working sets; this table records the final source run.

The subsequent [PR CI run](https://github.com/Shellghostt/BuildTrace/actions/runs/44004248904) also passed
the unchanged gate on Windows/amd64: manifest 9,084,928 bytes, verify 7,622,656 bytes and record
8,900,608 bytes peak working set. CI again observed tamper exit 1, missing exit 2 and successful
inspection after artifact removal. These are separate runner measurements, not a speed comparison.

File bytes use the inherited reusable 1 MiB hashing buffer. Directory sorting retains bounded
O(entry count) metadata, capped at 100,000 entries. The single-file result does not imply constant
memory for arbitrary directory populations or prove that no concurrent writer can evade metadata checks.

## Repeated synthetic construction and parsing

[BenchmarkRecordInspect](../../internal/attestation/bench_test.go) repeats
`Build(fixtureOptions(true))` then `Read(bytes.NewReader(line))`.
The fixed synthetic fixture has two artifact observations, an explicit ID, source assertion and
paired time claims. It does not perform artifact hashing, git collection, default-ID derivation or
filesystem writes. Those costs are outside this profile.

```sh
GOMAXPROCS=4 go test ./internal/attestation -run '^$' \
  -bench '^BenchmarkRecordInspect$' -benchtime=2s -benchmem \
  -cpuprofile cpu.pprof -memprofile heap.pprof -o attestation.test
go tool pprof -top cpu.pprof
go tool pprof -sample_index=inuse_space -top heap.pprof
```

Run profiles with synthetic inputs and save binaries/profiles outside tracked source.
The final native Windows run used an AMD Ryzen 5 5600H (6 cores/12 threads), Windows 11 Home
Single Language 10.0.26300 and about 15.34 GiB usable RAM, with Go 1.26.11 and GOMAXPROCS 4.

| Measurement | Observed value |
|---|---:|
| Iterations | 12,894 |
| Instrumented benchmark | 184,224 ns/op |
| Allocation volume | 59,235 B/op |
| Allocation count | 1,085 allocs/op |
| Package time | 3.163 s |
| Sampled in-use heap at profile end | 1,025.01 KiB |

The CPU profile was dominated by standard-library JSON scanning/validation/compaction; its sampled
duration was 2.37 s. The sampled retained heap was attributed to runtime threads/scavenger timers,
with no sampled retained attestation allocations. Heap sampling is not complete accounting: this
does not prove zero retained bytes or lifetime leak freedom. CPU/heap instrumentation affects timing.

This is a bounded repeated lifecycle observation, not a latency SLA, allocation threshold or
end-to-end CLI benchmark. Failed output/reader paths are covered separately by tests; the benchmark
does not profile cancellation or long-lived external handles.
