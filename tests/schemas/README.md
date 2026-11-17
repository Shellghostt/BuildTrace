# Offline upstream format checks

This isolated module is a test dependency. It is not imported by the CLI or its release binary.
The two [M3 fixtures](../fixtures/m3/) pass the official in-toto generated Protobuf JSON types and
`Validate` methods for Statement v1 and SLSA provenance v1. Malformed required fields have negative
tests. These checks do not authenticate artifacts or establish any SLSA level/build honesty.

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
setup and offline test steps. `make test` covers the CLI's own standard-library-only implementation;
`make schemas` covers the separate upstream implementation.
