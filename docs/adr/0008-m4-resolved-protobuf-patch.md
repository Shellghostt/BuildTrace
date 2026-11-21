# ADR 0008 — M4 resolved protobuf patch

- Status: accepted
- Date: 2026-11-22
- Supersedes: ADR 0007's retained protobuf-specs v0.5.1 pin only

## Decision

Use `github.com/sigstore/protobuf-specs v0.5.2`, required by the compatible Sigstore v1.10.11
security dependency graph. Its immutable commit is `0342fe5797edd558c58098033220fb27a2542a28`,
module checksum `h1:RSWWUY8QrVTxbYH00jY/jg2e7YnjzrpwP+PeHTMll0E=`, go.mod checksum
`h1:DRBzpFuE+LnvQMN10/dU6nBeKwVLGEQ6o2FovN2Rats=`, license Apache-2.0.

Go's minimal version selection raised the initial v0.5.1 requirement while resolving ADR 0007.
Record the actual patch explicitly; do not force an older transitive version, rewrite accepted ADRs,
or claim that an initial lower requirement identifies the final resolved code. The patch preserves
the accepted DSSE, Sigstore bundle v0.3 and trusted-root v0.1 wire formats and supported Go 1.26 floor.
No additional bundle/log/timestamp modes or trust-policy defaults are enabled.

The compatible signing/verification/trust-setup tests and runtime-plus-test `govulncheck` passed
under Go 1.26.11 after this resolution. Full local gates, independent fixture validation and
published/live CI remain separate required evidence, recorded in the eventual M4 validation.

## References

- [Protobuf-specs v0.5.2](https://github.com/sigstore/protobuf-specs/tree/v0.5.2)
- [ADR 0007](0007-m4-audited-dependency-pins.md)
- [ADR 0006](0006-m4-signing-and-offline-verification.md)
