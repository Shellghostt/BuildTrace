# ADR 0007 — M4 audited signing dependency pins

- Status: accepted
- Date: 2026-11-22
- Supersedes: ADR 0006's initial Rekor/signature dependency pins only
- Preserves: Go 1.26.0/toolchain 1.26.11, DSSE/bundle/trust/policy/output contracts in ADR 0006,
  all M2/M3 formats and accepted earlier decisions

## Context

The first M4 `govulncheck -test ./...` identified six called vulnerabilities in three transitive
modules. `golang.org/x/net v0.57.0` has four HTTP/2 advisories (GO-2026-6617, -6612, -6611, -6603),
`google.golang.org/grpc v1.82.1` has GO-2026-6348, and the unmaintained `x/crypto/openpgp` imported
through Rekor v1.5.3 has GO-2026-5932. Removing that package in a newer x/crypto also requires
Rekor's maintained OpenPGP implementation. No vulnerability exclusion or local security fork is chosen.

The newest Rekor/Sigstore-Go/signature releases require Go 1.27. Released Rekor v1.5.4 already
uses ProtonMail's maintained implementation and supports Go 1.25.11, allowing the accepted floor
to remain intact. Go support and wire-format compatibility are independent of a green audit.

## Decisions and verified module pins

Keep Sigstore-Go v1.3.0, protobuf-specs v0.5.1 and protobuf v1.36.12. Update the compatible graph:

| Module | Version | Module checksum | License |
|---|---|---|---|
| github.com/sigstore/rekor | v1.5.4 | `h1:A9zITTrkRwO+8lfq7L/gBR7rDHHcBQJRI+a0JQo4xDM=` | Apache-2.0 |
| github.com/sigstore/sigstore | v1.10.11 | `h1:fjrwDfR0AWmRONYV/hKGJyqbT0osMtaBz9FTZ6MH9XI=` | Apache-2.0 |
| golang.org/x/crypto | v0.59.0 | `h1:xS2jhqYbzNrpvkWP2YTDf4TJwBy3ykR03i8vFDxEc7c=` | BSD-3-Clause |
| golang.org/x/net | v0.63.0 | `h1:HCoTmNh9EpD1PpK8gBNFY4gcTY4N+KQEO8ylfIKqFJ0=` | BSD-3-Clause |
| google.golang.org/grpc | v1.83.1 | `h1:HIO0+BEtBP6soyqvqC8sNUjZ7bTs+0hFQuFF+RAy++Y=` | Apache-2.0 |

The corresponding go.mod checksums and complete resolved graph remain in committed go.sum.
Rekor v1.5.4 immutable commit is `a36bd716fd0d81c314092718f37b53dc26b2af38`; Sigstore v1.10.11 is
`e8841f5753b45451f47b703793ab5c6fd1dd46c8`. Runtime/test and isolated reference audits must pass
after resolution; this decision does not preclaim their result. Regenerate the dependency/license
inventory from the final graph and retain the original diagnosed scan in local validation evidence.

## Compatibility and validation

Keep the public-good Rekor v1 DSSE/SET path, strict single-signature selection, standard v0.3 bundle
and external v0.1 root. Standard shared trust snapshots also contain Rekor v2 Ed25519 keys whose
IDs identify a log origin. Accept those unused standard root entries; the M4 v1 verifier cannot
use them for a SET. V1 ECDSA and CT log IDs retain SPKI fingerprints. No v2 bundle, alternate
timestamp, implicit network fetch or signer-policy fallback is enabled by this dependency update.

Run every M4 crypto/negative/CLI and unchanged M2/M3 gate under the exact Go 1.26.11 compiler, plus
independent fixtures, network-disabled container checks, memory, race, lint and vulnerability scans.
The 1 GiB memory harness uses the production Make/Docker `-trimpath -ldflags '-s -w'` flags; its
artifact workload and 64 MiB gate remain unchanged. Record that build-method correction explicitly.

## References

- [Rekor v1.5.4](https://github.com/sigstore/rekor/tree/v1.5.4)
- [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
- [GO-2026-6348](https://pkg.go.dev/vuln/GO-2026-6348)
- [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)
- [ADR 0006](0006-m4-signing-and-offline-verification.md)
