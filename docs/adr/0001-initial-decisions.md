# ADR 0001 - Initial technology and scope decisions

- Status: accepted
- Date: 2026-11-13
- Deciders: Aditya

## Context

BuildTrace is a greenfield open-source project. Before any code exists, the expensive mistakes to avoid are
scope creep and undocumented stack choices that a future contributor will try to reverse.

## Decisions

1. **Go, single static binary** - runs inside CI containers with no runtime, produces a reproducible digest of itself, and cross-compiles for every runner.
2. **in-toto Statement v1 with the SLSA provenance predicate v1** - a custom format would make everything we produce unverifiable by existing tools. Compatibility is the whole point.
3. **SHA-256 only in v1** - one digest algorithm, no negotiation, no downgrade.
4. **Sigstore keyless signing at M4, local keys supported** - CI identity should come from OIDC. Air-gapped builds must still work with a local key.
5. **Verification is offline-first** - verification must work with no network, no service, no account. If it needs us to be up, it is not verification.
6. **No compliance claims** - we produce provenance compatible with in-toto and SLSA. We do not claim SLSA certification or a level. The README and docs say this explicitly.

## Consequences

- The project ships one narrow capability that actually works rather than a broad surface of stubs.
- Contributors have a reference point: changing any decision above requires a superseding ADR, not a
  silent pull request.
- Reversing a decision later is allowed but must be written down with the reason and the migration cost.

## Follow-up

- ADR 0002 is created at M1, recording the concrete schema and interface decisions made while building.
