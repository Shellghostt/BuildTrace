# M4 signing/parser/resource measurements — 2026-11-22

Source: `6ef2dd9`, Go 1.26.11, Windows/amd64, AMD Ryzen 5 5600H. Structured actual data:
[m4-signing-results.json](m4-signing-results.json). [M4 validation](../testing/m4-signing.md) identifies
the commands, negative cases, fixes and subsequently passed live/cross-platform evidence.

## Bounded small-fixture lifecycle

The compiled Go signing test harness ran 300 local sign/decode/verify, historical keyless decode/verify,
failed parser and cancelled signer cycles with synthetic files/keys. It then ran three one-second
benchmarks. It excludes artifact hashing, git subprocesses, real OIDC/Fulcio/Rekor calls and output writes.

| Benchmark | Latency/op | Bytes/op | Allocations/op |
|---|---:|---:|---:|
| Envelope parse | 42.379 us | 15,048 | 126 |
| Ed25519 local signing | 33.111 us | 7,173 | 34 |
| Historical offline keyless decode/full crypto verification | 2.090669 ms | 424,206 | 3,303 |

After forced cleanup, complete `runtime.MemStats` heap values were 1,451,440 B before and 1,631,544 B
after (+180,104 B), with goroutine delta **0**. The resource test's retained-heap ceiling is 8 MiB,
with at most two background goroutines; neither threshold was relaxed. The process's OS-reported
peak working set was 78,798,848 B over 4.4392045 seconds, sampled every 10 ms. This is the **test harness
with benchmarks**, not the shipped CLI's 1 GiB memory gate.

The separate sampled in-use profile total was 3,100.39 KiB, dominated by runtime threads (2,052 KiB),
the OpenAPI country map (536.37 KiB) and ProtonMail curve initialization (512.02 KiB). Sampling is
not a complete heap census; it complements the complete lifecycle values. A bounded stable run does
not prove unlimited lifetime leak freedom or platform-wide latency.

Reproduce with the pinned compiler:

```text
go test ./internal/signing -run TestRepeatedSigningParsingAndCancellationReleaseHeapAndGoroutines -v
go test ./internal/signing -run '^$' -bench '^BenchmarkM4' -benchtime=1s -benchmem -memprofile <local-profile>
go tool pprof -top -sample_index=inuse_space <local-profile>
```

## Preserved large-artifact gate

`make VERSION=m4-local memory-gate` independently hashed one GiB of zeros with .NET SHA-256,
then checked M2 manifest/verification and M3 unsigned record/inspect, one-byte tamper and missing artifact.
The digest is `49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14`.

| Process | Peak working set | Duration | Exit |
|---|---:|---:|---:|
| Manifest capture | 18,997,248 B | 1.1073525 s | 0 |
| Unsigned manifest verification | 17,678,336 B | 0.7508048 s | 0 |
| Unsigned statement recording | 19,251,200 B | 0.9904037 s | 0 |

All remain below the unchanged **64 MiB** gate. Tamper returned 1, missing artifact 2, and inspection
still succeeded after deleting the artifact. The harness now uses production Make/Docker flags
`-trimpath -ldflags '-s -w'`; its initial unstripped build exceeded the gate. This is a documented
compiler/method correction, not an increased memory threshold or a promise about debug builds.

## Parser smoke and limits

Ten-second native fuzz smokes used four workers and a one-MiB cap on generated fuzz inputs:
86,969 envelope and 198 bundle executions passed. Low bundle throughput is not exhaustive work-bound
evidence. Explicit tests separately exercise decoded 16 MiB, outer 32 MiB, depth 64, 200,000 tokens,
signature selection/count, certificate/proof/root limits and malformed/tampered security input.
These local measurements predate publication. Subsequent source `91a11df` passed all eight
Windows/Ubuntu/macOS and real keyless signing/offline CI jobs; [the separate CI receipt](../testing/m4-ci-results.json)
records hosted memory and real signer/artifact evidence. No live signing performance benchmark is claimed.
