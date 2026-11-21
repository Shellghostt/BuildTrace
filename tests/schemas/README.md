# Offline upstream format checks

This isolated module is a test dependency. It is not imported by the CLI or its release binary.
The two [M3 fixtures](../fixtures/m3/) pass the official in-toto generated Protobuf JSON types and
`Validate` methods for Statement v1 and SLSA provenance v1. Malformed required fields have negative
tests. These checks do not authenticate artifacts or establish any SLSA level/build honesty.

M4 adds eight pinned public [signed fixtures](../fixtures/m4/README.md). The isolated tests bypass
BuildTrace's internal packages: go-securesystemslib verifies local DSSE with external Ed25519/P-256
keys, and direct Sigstore-Go verifies the historical bundle with external roots, exact signer policy,
authenticated signing time and artifact digest. Negative signature/identity/artifact cases fail.
Sigstore-Go is also the production keyless cryptographic library; this checks independent pipeline
usage and format compatibility, rather than a second cryptographic implementation. These synthetic
fixtures do not constitute live Fulcio/Rekor signing or proof of original build history.

## Pins and attribution

- in-toto Attestation, commit `50bf01716982189898823e90586075f37cd9bb7d`, module
  `v1.2.1-0.20261021134056-50bf01716982`, Apache-2.0. The in-toto community's Statement v1,
  ResourceDescriptor v1 and provenance v1 schema sources are archived unmodified under `upstream/`.
- Supply-chain Levels for Software Artifacts (SLSA), specification 1.2, release `v1.2`, commit
  `19e4e2f005f871270c4f555fc47afecfb37f3efe`, Community Specification License 1.0. The SLSA Working
  Group's provenance v1 Protobuf schema is archived from
  [docs/spec/v1.2/schema/provenance.proto](https://github.com/slsa-framework/slsa/blob/19e4e2f005f871270c4f555fc47afecfb37f3efe/docs/spec/v1.2/schema/provenance.proto).
- The validator uses `google.golang.org/protobuf v1.36.12` (BSD-3-Clause). Module content checksums
  are pinned in `go.sum`; source/license SHA-256 values and original paths are in [UPSTREAM.json](UPSTREAM.json).
  Original licenses remain alongside the source snapshots. Git preserves their exact bytes.
- M4 reference dependencies include go-securesystemslib v0.11.1 (MIT) and Sigstore-Go v1.3.0
  (Apache-2.0), with compatible graph pins in go.mod/go.sum. The
  [dependency inventory](../../docs/dependencies/m4-signing.json) records checksums and license hashes;
  accepted [ADRs 0006–0008](../../docs/adr/README.md) document the versions and policy.

The archived SLSA license contains upstream trailing spaces. A narrowly scoped Git whitespace
attribute preserves that license unchanged; source/license SHA-256 checks still cover every byte.
It does not exempt runtime/test source from formatting or whitespace checks.

The upstream schemas use Protobuf with its JSON representation, not fetched JSON Schema documents.
The official validators check structure and required fields; optional original build times remain
optional. Compatible unknown fields are discarded by the reference validator and retained by the
CLI's inspection report. The CLI additionally enforces exact v1 URIs and its bounded JSONL framing.

## Reproduction

Use Go 1.26.11. Fetch test dependencies during setup, then disable module/network schema access:

```sh
make schema-setup
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off make schemas
```

On PowerShell, put the installed Go 1.26.11 binary directory first on PATH, verify `go version`, and
set `$env:GOTOOLCHAIN='local'`, `$env:GOPROXY='off'` and `$env:GOSUMDB='off'` for `make schemas` after setup.
The local setting prevents the host's Go launcher from trying to authenticate a downloaded toolchain
through a disabled checksum database. It does not change the pinned compiler version.
Fixture validation itself never fetches a schema or runs a build. CI performs the same separate
setup and offline test steps. `make test` covers the CLI implementation; `make schemas` covers the
isolated upstream format/signature checks. M3 wire types remain standard-library-only; M4 uses the
explicitly pinned signing dependencies.
