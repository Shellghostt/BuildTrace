# M3 unsigned provenance validation — 2026-11-17

M3 is implemented and locally verified on `feat/m3-implementation`, unreleased.
The verified runtime/tests are committed at `0981a57cfc76c5f7a5064507d9833e4bdaae31ce`.
The M2 baseline remains `e133687faa9c48b466ccdaf0b83ef8a31cc5893f`; no merge or main push occurred.
GitHub CI has not run for M3 at this local-validation checkpoint.

The [phase contract](../phases/M3.md), accepted
[ADR 0005](../adr/0005-m3-unsigned-recorder-contract.md) and
[versioned build type](../build-types/record/v1.md) define the behavior.
Read [memory/profile evidence](../benchmarks/m3-provenance.md) for measurement methods and limits.

## Executed gates

| Command/check | Observed result |
|---|---|
| `make test VERSION=m3-local` | Passed all packages, including real-git/CLI tests, both M3 goldens and unchanged M2 goldens. |
| `make lint VERSION=m3-local` | gofmt/vet/golangci-lint 2.15.0 passed; `0 issues.` |
| `make race VERSION=m3-local` | Passed all packages natively on Windows using 64-bit GCC 16.2.0 UCRT64. |
| `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off make schemas VERSION=m3-local` | Passed the isolated pinned upstream validator; final package run 1.317 s. Dependencies were installed during setup. |
| `make memory-gate VERSION=m3-local` | Passed real 1 GiB manifest/verify/record, independent digest/count comparison, tamper/missing exits and the unchanged 64 MiB gate. |
| `make docker VERSION=m3-local` and `bash tests/container/smoke.sh buildtrace:m3-local` | Image built and packaged M2/M3 checks passed offline as UID/GID 65532, with read-only root, all capabilities dropped and temporary `/work`. |
| Linux `golang:1.26.11` hashing tests | Passed all hashing tests, including canonical directory/symlink goldens and the file-replacement regression, with network disabled and a read-only source mount. |
| Six `CGO_ENABLED=0 go build -trimpath` targets | Passed Linux, macOS and Windows builds for amd64/arm64. Cross-builds are not native execution. |
| `GOMAXPROCS=4 go test ./internal/attestation -run '^$' -fuzz FuzzRead -fuzztime=10s -parallel=4` | Passed; final run 12,769 executions, 11 retained baseline inputs, 11.755 s package time. Earlier bounded run passed 143,994 executions. |
| `govulncheck ./...` in root and `tests/schemas` | Both reported `No vulnerabilities found.` The CLI has no new third-party runtime dependency. |
| Explicit native symlink/mutation tests with `go test -json` | Passed; no skips for terminal-link containment, output-symlink replacement, M2 link hashing or file mutation/replacement. |
| Git/schema archive integrity | All six staged archive blobs matched the original working-copy bytes; the validator independently checked their recorded SHA-256 values. |
| Documentation and graph | 12 changed Markdown documents, 86 relative links and 41 named-test references checked; 8 phase/6 PLAN M3 gates complete, M4–M6 unchecked, README/PLAN non-claims identical. Existing CodeGraph index refreshed: 40 files, 516 nodes, 1,285 edges; `Index is up to date`. |

Final ordinary tests reported attestation 1.152 s, CLI 16.460 s, hashing 0.658 s, manifest 0.872 s
and metadata 5.722 s. Final native race reported attestation 2.447 s, CLI 17.905 s, hashing 1.368 s,
manifest 1.731 s and metadata 6.518 s. These package timings describe these runs, not throughput gates.
The final memory run measured 9.09 MiB for recording; all three measured processes passed.

## Acceptance mapping

These rows cover the phase's eight local gates and all six PLAN M3 acceptance criteria.
Test declarations live in [attestation](../../internal/attestation/),
[CLI M3 tests](../../internal/cli/m3_test.go), [hashing regression](../../internal/hashing/m3_regression_test.go)
and the [isolated validator](../../tests/schemas/schema_test.go).

| Phase gate | Named evidence |
|---|---|
| Offline unsigned record/inspect and exits | `TestUnsignedRecordInspectRoundTripDoesNotUseOriginalBuildClock`, `TestRecordExplicitClaimsHaveInputLabelsAndOfflineInspection`, `TestInspectFailureCodesAndUnknownBuildTypeScope`, `TestM3StdoutFailuresExitAsToolErrors`; packaged smoke with network disabled and inspection PATH without tools. |
| Upstream formats and unknown required versions | `TestFixturesValidateWithPinnedUpstreamTypes`, `TestUpstreamValidationRejectsMalformedRequiredFields`, `TestPinnedSchemaSourcesAndLicensesMatchChecksums`, `TestInspectRejectsMalformedFramingVersionsAndTypes`. |
| Field evidence without invented history/identity | `TestRecordDoesNotInventOriginalBuildHistory`, `TestRecordRedactsURIInputsAndDoesNotInferWorkflowOrDependencies`, `TestRecordExplicitClaimsHaveInputLabelsAndOfflineInspection`, `TestRecordAcceptsFullSHA256GitCommitAsAnExplicitClaim`. |
| Two goldens and determinism | `TestRecordGoldenFixtures`, `TestDefaultRecordingIDIsCanonicalAndExplicitIDPreservesBytes`, `TestRecordingOrderingAndAllInputsAffectDeterminism`; independently recomputed default ID and packaged byte equality with reversed selections. |
| JSONL bounds, name collisions and signing rejection | `TestInspectRejectsMalformedFramingVersionsAndTypes`, `TestInspectBoundsDepthTokenWorkAndResourceArrays`, `TestArtifactSelectionsUseUniqueRelativeNamesAndM2Digests`, `TestRecordRejectsInvalidInputsWithoutEchoingThem`, `TestUnsupportedSigningAndBuildExecutionFailBeforeCollecting`. |
| Output/mutation/link/directory/privacy guards | `TestRecordOutputCannotReplaceOrIncludeArtifactsAndWritesAtomically`, `TestRecordOutputSymlinkDoesNotTruncateTarget`, `TestTerminalSymlinkIsHashedAndParentEscapeIsRejected`, `TestRecordingRejectsFileChangesAfterObservation`, `TestURIInputsRemoveCredentialQueryAndFragment`; independent directory golden and packaged checks. |
| M2 manifest/verify regression | `TestManifestVerificationRoundTripAndSingleByteTamper`, `TestDirectoryVerificationAndOutputProtection`, `TestActualBinaryVerifiesOfflineAndRejectsVersions`, `TestVerificationChecksKindAndDeclaredSize`, `TestDirectoryGoldenIgnoresCreationOrderAndMetadata`, `TestFileUsesRawSHA256`. Existing manifest readers/goldens and accepted ADRs 0001–0004 are unchanged. |
| Canonical local gates and resource/image evidence | The commands/results above and the [1 GiB/profile report](../benchmarks/m3-provenance.md); no performance threshold was relaxed. |

## Format, evidence and interoperability

The two [synthetic fixtures](../../tests/fixtures/m3/README.md) distinguish observations alone from
explicit source/time claims. Their repeated commit IDs, recorder version, platform and timestamps
are test inputs, not the project's actual build history. File/directory digests are independently known.
Default-ID recomputation with .NET SHA-256 confirmed
`sha256:68c6ccfc73cf66bab84329326c180c6ea4b6f5d9b0a954f6365976fa6d8f4f15`
for the observation-only golden.

The schema tools use official generated Protobuf JSON types and their validators, not fetched JSON
Schema documents. Pins and all six source/license SHA-256 values are recorded in
[UPSTREAM.json](../../tests/schemas/UPSTREAM.json), with separate module checksums in `go.sum`:

| Source | Pin | License |
|---|---|---|
| in-toto Attestation | `50bf01716982189898823e90586075f37cd9bb7d`; module `v1.2.1-0.20261021134056-50bf01716982` | Apache-2.0 |
| SLSA specification 1.2 | release commit `19e4e2f005f871270c4f555fc47afecfb37f3efe` | Community Specification License 1.0 |
| Protobuf validator runtime | `google.golang.org/protobuf v1.36.12` | BSD-3-Clause |

The SLSA predicate URI remains `https://slsa.dev/provenance/v1`.
Unknown compatible fields survive the inspection report and exact standard keys match
case-sensitively, covered by `TestInspectPreservesCompatibleFieldsAndMatchesKeysExactly`.
`TestInspectAcceptsUpstreamBase64FormsWithoutCheckingContentDigest` and
`TestUpstreamCompatibleBase64FormsAndFullGitCommit` cover standard/URL-safe Base64 with/without padding
and 64-digit source commit claims. Deliberately inconsistent inline content/digests still inspect:
format inspection is not digest verification.

## Reproduction and environment

Native execution used Go 1.26.11, GNU Make 4.4.1, golangci-lint 2.15.0 and MSYS2 GCC
`16.2.0 (Rev7)`, target `x86_64-w64-mingw32`, on Windows 11/AMD Ryzen 5 5600H.
Git was `2.53.0.windows.2`; the Docker daemon was 29.9.2.
The linter binary was compiled with Go 1.27.4; the application/test compiler was pinned to 1.26.11.
Docker used the pinned `golang:1.26.11-alpine` builder and Alpine 3.23 runtime.
`VERSION=m3-local` sets the local image tag; that Make target does not pass the VERSION build argument,
so the packaged CLI correctly reported `buildtrace dev`. CI does pass its version argument.

On PowerShell, prepend the installed 64-bit UCRT64 compiler's `bin` directory to PATH, then:

```powershell
$env:GOTOOLCHAIN = 'go1.26.11'
$env:CC = 'gcc'
$env:CXX = 'g++'
$env:CGO_ENABLED = '1'
gcc -dumpmachine  # must identify the 64-bit compiler
make lint VERSION=m3-local
make test VERSION=m3-local
make race VERSION=m3-local
make memory-gate VERSION=m3-local
make schema-setup VERSION=m3-local
$taskPinnedGoRoot = go env GOROOT
$env:Path = "$taskPinnedGoRoot\bin;$env:Path"
$env:GOTOOLCHAIN = 'local'
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
make schemas VERSION=m3-local
```

The installed pinned compiler must be first on PATH before selecting `local`; verify `go version`.
The `VERSION` override bypasses the existing Makefile's Unix `/dev/null` version discovery on Windows.
For the Git Bash image smoke on Windows, set `MSYS_NO_PATHCONV=1` and `MSYS2_ARG_CONV_EXCL=*`
before invoking the script. The test uses disposable container storage and does not reset Docker data.
Logs/profiles remain local under the workspace scratch directory `.codex-temp/buildtrace-m3/`,
outside this Git repository.

## Failed checks and resolutions

- The first offline schema invocation tried authenticating a downloaded Go toolchain with
  `GOSUMDB=off`. Using the installed pinned binary with `GOTOOLCHAIN=local` resolved it; schema tests
  remain offline after dependency setup.
- Lint flagged QF1001 in identifier validation. A switch resolved the finding without a suppression.
- The first extended memory harness selected `predicate.internalParameters` instead of
  `predicate.buildDefinition.internalParameters`. Correcting the selector resolved that harness error;
  independent artifact digest/count data had agreed. Only the verified generated large file was removed.
- Interoperability review found the reader initially accepted only padded standard Base64. The parser
  now accepts all four upstream forms, with tests against both implementations.
- The mutation regression exposed Windows' lazy `Lstat` identity lookup: a replacement with matching
  size/time could compare as the same file. The shared hasher now loads identity during observation.
  Deterministic size, same-size write and replacement cases pass on Windows and Linux. This strengthens
  the existing guard without changing canonical bytes, manifest shapes or verification reasons/exits.
- The original pinned SLSA license contains trailing whitespace. Git's staged diff check initially
  flagged it. A license-only whitespace attribute preserves the upstream bytes; checksum validation and
  explicit staged-blob comparisons still pass. Runtime/test formatting checks remain active.

Final runtime gates were rerun after the Base64 and file-identity fixes. Status docs were updated
after those checks, rather than treating earlier failures as passing evidence.

## Recorded limits and remaining merge gates

GitHub M3 CI is pending publication at this checkpoint. Local Windows execution, Linux hashing tests
and the Linux packaged image passed; native macOS and arm64 execution were not performed locally.
Six target builds establish compilation only. The CI workflow defines Windows/Ubuntu/macOS race tests,
Windows memory checks, Linux fuzzing, offline schemas, packaged smoke, lint and vulnerability scans.

Signing/DSSE, identity policy and signed-attestation verification are M4 work, not skipped M3 gates.
Dependency discovery, SBOM and reproducibility remain later milestones. Finite passing tests do not
establish lifetime leak freedom, build honesty, artifact safety or any SLSA level.
