# Architecture Decision Records

Each file records one decision that was expensive to make and would be expensive to reverse.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-initial-decisions.md) | Initial technology and scope decisions | accepted |
| [0002](0002-m1-implementation-decisions.md) | M1 implementation decisions | accepted, partly superseded by 0003 |
| [0003](0003-go-126-floor-and-ci-contract.md) | Go 1.26 floor and CI contract | accepted |
| [0004](0004-m2-canonical-hashing-and-verification.md) | M2 canonical hashing and manifest verification | accepted; supersedes 0002 decisions 1, 13 and 15 for M2 |
| [0005](0005-m3-unsigned-recorder-contract.md) | M3 unsigned artifact recorder and inspection | accepted; extends 0002 for record/inspect |
| [0006](0006-m4-signing-and-offline-verification.md) | M4 DSSE signing and offline signer verification | accepted; signing formats, external trust and bounded offline policy |
| [0007](0007-m4-audited-dependency-pins.md) | M4 audited signing dependency pins | accepted; supersedes 0006 initial Rekor/signature pins |

New ADRs are numbered sequentially and never edited after acceptance. A changed mind gets a new ADR
that supersedes the old one.
