# M4 signing and offline verification validation — 2026-11-22

Status: **Implemented and verified locally on `feat/m4-implementation`, source `6ef2dd9`.**
The original local baseline is source `6ef2dd9`; subsequent published CI corrections are recorded below.
The feature branch is published in [PR #3](https://github.com/Shellghostt/BuildTrace/pull/3), unmerged.
Final GitHub Windows/Ubuntu/macOS CI and real authorized keyless signing remain **pending successful CI**,
so M4's live/CI acceptance boxes remain open. No release or merge is claimed.
Accepted [ADR 0006](../adr/0006-m4-signing-and-offline-verification.md) preceded signing code;
[0007](../adr/0007-m4-audited-dependency-pins.md) and [0008](../adr/0008-m4-resolved-protobuf-patch.md)
record the audited compatible dependency graph without rewriting prior decisions.

## Implemented scope

BT-014–BT-019 provide bounded exact-byte DSSE/PAE, local Ed25519/P-256 software signing, a standard
Sigstore v0.3 keyless signer, external public-key/root policy and offline artifact verification.
The unchanged M3 canonical payload/LF/invocation ID is inside the envelope. `record --sign none`
remains the default, M3 `inspect` retains unsigned inspection scope, and M2 manifest/reasons/exits
remain compatible. Signed capture/verification use the M2 canonical hash policy through `os.Root`.

Keyless verification requires an external standard trusted-root v0.1 snapshot, exact certificate
SAN/issuer, SET-authenticated signing time, bound Rekor v1 entry, signed checkpoint/inclusion proof
and CT signature. It constructs no network client, TUF updater or subprocess runner. It opens only
explicit selected rooted artifacts and reports unselected names. Builder/source assertion filters
remain separate from signer evidence and prove no original build history or artifact safety.

## Executed local gates

All Go gates used **Go 1.26.11**. Native race used x64 UCRT GCC at
`C:\Users\Aditya\AppData\Local\Programs\MSYS2-Go-x64\msys64\ucrt64\bin\gcc.exe`.

| Command / check | Actual result |
|---|---|
| `make VERSION=m4-local test` | All packages passed; final CLI package 32.816s |
| `make VERSION=m4-local race` | All packages passed natively on Windows; final CLI package 32.707s |
| `make VERSION=m4-local lint` | gofmt/vet/golangci-lint v2.15.0, **0 issues** |
| `make VERSION=m4-local build` | Production native CLI built with the expected version |
| `make VERSION=m4-local docker` | Static Go 1.26.11 Alpine image built; packaged `version` returned `m4-local` |
| `bash tests/container/smoke.sh buildtrace:m4-local` | M2/M3 contracts plus local/historical keyless verification, exact identity/tamper/unsigned cases passed with **network disabled**, no tool PATH, nonroot/read-only filesystem |
| `make schema-setup`, then `make schemas` with exact local Go and `GOPROXY=off GOSUMDB=off` | Existing upstream formats and eight public M4 fixture pins, independent DSSE/Sigstore signature/artifact/time/identity checks passed |
| `govulncheck -test ./...` | **0 called vulnerabilities**, exit 0; one imported-package advisory not called remains reported by the scanner |
| Isolated `tests/schemas` runtime/test vulnerability scan | **No vulnerabilities found**, exit 0 |
| `go -C tests/schemas mod verify` and selected module checksum inventory | All reference modules verified; 81 actually imported module/version records have module/go.mod and license-file checksums |
| `make VERSION=m4-local memory-gate` | Independently hashed 1 GiB; same **64 MiB** gate passed: manifest 18,997,248 B, verify 17,678,336 B, unsigned record 19,251,200 B peak working set; tamper exit 1, missing exit 2 |
| `FuzzDecodeEnvelope`, 10s, 4 workers | Passed; 86,969 executions |
| `FuzzDecodeKeylessBundle`, 10s, 4 workers | Passed; 198 executions; this short smoke is not exhaustive parser/resource evidence |
| Repeated lifecycle test and native benchmark/heap profile | 300 local/offline/failed/cancelled cycles; retained heap +180,104 B, goroutine delta 0; three measured benchmarks and sampled profile saved |
| `make VERSION=m4-local trust-setup` | Authenticated public-good TUF snapshot provisioned; SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |
| Documentation and workflow review | Local links/named tests resolve; structured receipts match measured logs; inventory parses and pins match go.sum; README/PLAN non-claims agree; CI YAML parses as eight jobs with signing authority only on the keyless job; `git diff --check` passes |

The [measurement record](../benchmarks/m4-signing.md) and [raw structured results](../benchmarks/m4-signing-results.json)
describe workload/method limitations. The [dependency inventory](../dependencies/m4-signing.json) contains
actual module versions, Go checksums, licenses and license text hashes. Root setup is a networked preparation
step, not evidence that a signing operation occurred. Offline tests consume prepared local files.

## Acceptance mapping

| Requirement | Actual tests/evidence |
|---|---|
| Independent PAE, UTF-8 byte lengths, exact payload LF | `TestPAEIndependentVectors`, `TestLocalAlgorithmsAuthenticateExactPayloadAndIndependentVerifier`, `TestM4LocalRecordPreservesM3PayloadAndVerifiesWithoutGitClockOrEnvironment` |
| Duplicate/case/unknown fields, base64, signatures, bytes/depth/tokens | `TestEnvelopeSecurityFieldsAndSignatureSelection`, `TestEnvelopeDecodedAndOuterBounds`, `TestBundleAndRootRejectDuplicateUnknownAliasesAndUnsupportedAlternatives`, parser fuzz seeds/smokes |
| External Ed25519/P-256 trust, PEM/algorithm and file handling | `TestPrivateAndPinnedPublicPEMFormats`, `TestKeysRejectUnsupportedAlgorithmsMaterialAndPrivateFileModes`, `TestPinnedPublicKeysRejectPrivateMalformedAndUnsupportedInputs`, wrong-key DSSE tests |
| Keyless signer packaging and no unsigned fallback | Compiled standard signer; `TestOIDCAndCancelledTransportExcludeSecretsAndBoundResponses`, `TestM4SigningFailureCancellationAndOutputNeverPublishPartialOrPrivateMaterial`; real GitHub/Fulcio/Rekor signing still pending |
| Historical certificate/time/SET/proof/CT/root/identity | `TestKeylessHistoricalOfflineAndIndependentSigstoreVerification`, `TestKeylessTamperTrustTimeIdentityAndProofMatrix`, `TestMissingSCTIssuerAndOutOfLeafTimeFailWithAuthenticLogBinding`, `TestTrustRootLogKeyAndCertificateBounds` |
| Artifact/subject/kind/size/type/source failure reasons | `TestSignedRecorderContractAndStableFailureReasons`, `TestExactRecorderLabelAndDeclaredDependencyPolicy`, `TestM4SignedCLIReasonsExitsAndExactlyOneReport`, `TestM4KeylessCLIHistoricalIdentityTrustAndTamperExits` |
| Selected rooted reads, relocation and unselected scope | `TestSignedVerificationChecksScopeSelectedBytesAndRelocation`, `TestSelectedSubjectsDoNotOpenUnselectedArtifactPaths`, `TestArtifactMappingRejectsTraversalAbsoluteAndDuplicatePaths`, `TestRootedHashPreservesM2CanonicalBytesAndPreventsParentEscape` |
| No git/clock/environment or network verification dependency | Forbidden Git/environment/clock test doubles; actual packaged `--network none` verification with PATH `/no-tools`; bundle URLs are never fetched |
| Signed, unsigned opt-in, inspect and manifest distinction | `TestUnsignedOptInCannotSatisfySignerPolicy`, `TestM4UnsignedOptInAndManifestScopesRemainDistinct`, unchanged M3/M2 suites; signed reports carry version 1, checked/unselected scope and actual signer evidence |
| Private material excluded; failure/cancellation/output | `TestSigningKeysAndOIDCTokensNeverEnterGitEnvironment`, malformed secret/key diagnostics, `TestM4SigningFailureCancellationAndOutputNeverPublishPartialOrPrivateMaterial`, `TestM4SignedReportOutputFailureIsToolError`, `TestM4LocalSignedStdoutFailureNeverReportsSuccess` |
| Independent signed interoperability | Eight public fixture checksums plus `TestM4IndependentDSSESignaturesAndUnsignedPayloadSchema` / `TestM4IndependentHistoricalSigstoreArtifactTimeAndIdentity` in the isolated reference module |
| M2/M3 regression, native race, image and memory | Canonical gates above, existing goldens/mutation/parser suites and unchanged artifact workload/64 MiB budget |
| Runtime resources | `TestRepeatedSigningParsingAndCancellationReleaseHeapAndGoroutines`, native OS peak-working-set and Go allocation/heap measurements; input/resource limits separately tested |
| Final cross-platform and real keyless CI | Prepared eight-job workflow, including narrowly scoped OIDC job and network-disabled consumer verification; **not run before publication** |

The isolated reference module does not import BuildTrace internals. Its DSSE verifier is a separate
implementation; keyless checks call Sigstore-Go directly, which is also the production cryptographic
library. This provides independent pipeline/format checks without claiming a second keyless crypto stack.

Every planned reason (`invalid_input`, `signature_invalid`, `identity_mismatch`, `subject_missing`,
`digest_mismatch`, `unsupported_build_type`, `dependency_mismatch`) has a test. Additional accepted reasons
for missing/ambiguous signatures, key/trust/certificate/time/proof, selected file I/O, kind/size, recorder
label and output failure have targeted negatives and fixed messages. No failure selects unsigned mode.

## Diagnosed failures and corrections

- The first dependency setup lacked the DSSE package's transitive SSH checksum; setup fetched the pinned
  graph before offline checks. The initial runtime/test audit then found six vulnerabilities. ADRs 0007/0008
  select compatible patched x/crypto/x/net/gRPC plus Rekor's maintained ProtonMail implementation, with no
  vulnerability suppression, security fork or Go floor increase.
- Negative fixtures exposed missing issuer-extension validation and root key-ID checks. Required extension
  checks were added; v1/CT fingerprints remain checked while standard unused Rekor v2 Ed25519 root entries
  retain their distinct origin IDs. SET-authenticated time controls historical leaf validity. An intermediate
  lookup used raw log-ID bytes against a hex-keyed map; it was corrected and the matrix rerun.
- The TUF setup wrapper initially hid the expected 404 ending root rotation. It now returns the library's
  typed HTTP/length errors, with an explicit 404 regression test. Shared public-good root snapshot handling
  was verified, rather than inventing a custom root/bundle format.
- The initial 1 GiB gate failed with the harness's unstripped debug executable. The harness now matches
  production Make/Docker `-trimpath -ldflags '-s -w'`; the artifact workload, independent digest and **64 MiB
  threshold are unchanged**. The production gate was rerun and passed; do not cite it as an unstripped-build
  memory result. The Make image target also now passes its version build argument to the binary.
- Lint flagged deprecated raw ECDSA coordinates/scalars and two style findings. Validation now uses Go's
  supported key `Bytes` APIs; no lint exclusions were added.
- Offline schema execution from a newer launcher with `GOTOOLCHAIN=go1.26.11` and `GOSUMDB=off` failed
  toolchain verification. Use the cached exact compiler in PATH and `GOTOOLCHAIN=local` for offline setup.

## Published CI corrections

The first [PR CI](https://github.com/Shellghostt/BuildTrace/actions/runs/45050471040) on `5f6842e`
passed Windows race/memory, container, reference schemas, lint and security, but failed Ubuntu/macOS
on a fixture permission assertion and rejected the real keyless bundle during pinned-root validation.

- `TestPinnedPublicKeysRejectPrivateMalformedAndUnsupportedInputs` reused a public file created with
  mode 0644. Writing it again with mode 0600 did not change the existing permissions, so the private
  permission guard correctly fired before the encrypted-key reason. The encrypted fixture now uses
  a fresh private file; production permission enforcement is unchanged.
- Rekor v1 SETs sign the cumulative index across shards, while inclusion proofs use the leaf index
  within their signed shard checkpoint. The verifier incorrectly required those indexes to be equal.
  It now preserves separate authenticated SET/proof checks, local-index/tree bounds and checkpoint
  size/root/signature binding. `TestKeylessShardedGlobalIndexAndLocalProofRemainAuthenticated` first
  reproduces the old rejection after independent Sigstore verification succeeds, then validates the
  correction and rejects a modified global index without a new SET. No signature/proof check is skipped.
- Signing failures include only the verifier's fixed internal description; raw remote/library errors
  remain generic and no failed signing output is published.

After these corrections, native Windows race passed for signing (28.070s) and CLI (40.716s),
vet/lint reported 0 issues, and the complete signing package passed in Go 1.26.11 Linux (2.340s)
with network disabled and prepared modules. Full published CI/live signing remains a separate gate.

## Reproduction and pending evidence

In PowerShell, pin `GOTOOLCHAIN=go1.26.11` for networked setup/build and prepend the x64 GCC directory for
race. Run `make VERSION=m4-local` with the relevant target. Before `make schemas`, provision dependencies
and locate the actual compiler using `go env GOROOT`, prepend its `bin`, then set `GOTOOLCHAIN=local`,
`GOPROXY=off` and `GOSUMDB=off`. No global compiler/environment setting was changed for these measurements.

The focused GitHub job alone has `id-token: write`. It signs disposable public data with the actual workflow
identity, consumes the explicit root in a network-disabled container and checks wrong identity/artifact.
It does not publish a release or implement M5's reusable action. Feature-branch publication requires the
user's applicable authorization. Final CI/live success remains required before M4 merge readiness.

Windows ACL secrecy is the caller's responsibility; Go permission bits do not establish Windows ACLs.
Offline verification cannot discover later root/log compromise or revocation and does not prove global
log consistency. Signer authentication and assertion comparison prove no original build, source honesty,
dependency completeness, artifact safety, reproducibility or SLSA level.

## Local resources

Docker Desktop was started for this task. Tests used disposable `--rm` containers and tmpfs, with no volumes,
data reset, Compose project or unrelated service shutdown. `buildtrace:m4-local` is the task-owned image.
Local `.tmp/` holds logs, prepared public-good roots and profiles; `bin/` holds binaries and memory receipts.
These remain ignored and are not release/customer artifacts. Public committed fixtures contain no private
keys; test keys are synthetic temporary inputs. Preserve sources/evidence before optional task-image cleanup.
