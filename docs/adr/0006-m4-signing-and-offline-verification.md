# ADR 0006 — M4 DSSE signing and offline signer verification

- Status: proposed; documentation only
- Date: 2026-11-17
- Required by: [M4 requirements](../phases/M4.md), BT-014–BT-019
- Would extend: ADR 0005 signing/output modes and decision 11 for pinned signing runtime dependencies;
  preserves M2 hashing and M3 unsigned recorder/inspect contracts

## Context

M3 records unsigned observations and caller assertions using a defined recorder build type. Its builder
label is not authenticated. M4 needs DSSE signing, artifact recomputation and an external signer policy.
The PLAN's optional Rekor upload/no-inclusion-proof sketch does not yet explain offline verification
after short-lived Fulcio certificates expire. A timestamp asserted inside the payload is not a trusted
clock. Signing the statement also cannot retroactively witness the original build or its source.

## Recommended design, pending acceptance

1. Sign the exact M3 payload bytes with DSSE PAE and `application/vnd.in-toto+json`; decoded-byte limits
   and parser semantics remain unchanged. Verify signatures over the received bytes, not reserialized
   JSON. Bound the outer envelope/bundle separately (proposal: 32 MiB, at most 16 signatures) and define
   strict certificate/proof/key/parser bounds and deterministic check selection.
2. Local mode supports Ed25519/ECDSA P-256 with documented PEM formats. Private keys come from the
   configured file path; the verifier receives a pinned public key from trusted policy outside the
   attestation. Embedded key IDs/keys never establish trust. No network is needed for local mode.
3. Keyless mode uses maintained pinned Sigstore libraries and an explicit OIDC/Fulcio/log workflow.
   Prefer one standard Sigstore bundle containing the DSSE envelope, certificate and required offline
   verification material, atomically written. This avoids mismatched envelope/sidecar publication.
   Local signed output can remain a DSSE envelope; unsigned mode remains the current JSONL statement.
4. Offline verification consumes authenticated local trust roots, validates certificate/signature and
   exact issuer/identity, and verifies log/time evidence bound to this envelope/signature. Require the
   selected signed entry/timestamp and inclusion proof/checkpoint material under the standard verifier's
   trust policy. Check leaf validity at authenticated signing time, not untrusted provenance times or
   the current clock alone. Missing/untrusted evidence fails; no implicit online lookup or trust-any-root.
5. Keyless expected identity/issuer match certificate evidence exactly. Local policy pins the public key.
   Keep optional builder-label/source-commit assertions separate from signer authentication. Report
   checked selected subjects, recomputed kinds/sizes/digests, scope and stable reasons. An authenticated
   statement establishes signed assertions and artifact consistency, not original build honesty/safety.
6. Default signed verification rejects unsigned input. If `--allow-unsigned` ships, its scope/warning
   remains explicitly unsigned and it cannot satisfy identity/issuer policy. Failed signing/verification
   never silently takes that path. Preserve M2/M3 default formats, exit meanings and unsigned determinism.
7. Pin runtime/library/trust-format versions, checksums/licenses and fixture verification tools before
   adding dependencies. Setup may fetch dependencies/trust data; the actual offline verifier does not.
   Use synthetic keys/certificates/roots in offline tests and a narrowly scoped authorized live CI test.

## Choices that must be resolved before acceptance

- Standard Sigstore bundle media/schema version and output/CLI selection; alternatively, a fully specified
  envelope/sidecar atomicity and association contract. Do not invent a custom security bundle format.
- Maintained library versions, supported algorithms/PEM forms, ephemeral/private-key handling and service
  configuration. The current standard-library-only runtime is preserved until an accepted extension.
- Trust-root distribution/pins, authenticated signing-time mechanism, required SCT/log/inclusion/
  checkpoint evidence and behavior after leaf/root rotation/expiry. State offline revocation/update limits.
  If choosing another mechanism, cite and test its exact cryptographic binding and trust prerequisites.
- Exact signer/issuer matching, mode/flag combinations, public-key and trust-root arguments, optional
  builder/source assertion filters, and explicit unsigned behavior. Payload labels never supply defaults
  for trusted signer identity.
- Subject/root/path mapping, report version/scope, full reason/exit/check precedence and signature selection.
  Preserve existing 0/1/2/3 exits; test every existing planned reason plus certificate/time/trust failures.
- Final outer/decoded/key/certificate/proof/parser/output bounds and failed/cancelled write behavior,
  including Windows paths and named artifacts in multi-subject M3 statements.

## Alternatives considered

- Trust `builder.id`: authenticates an arbitrary string rather than the actual signing identity.
- Verify a short-lived certificate only against the current clock: rejects valid historical signatures
  after expiry, defeating the stated offline consumer use case.
- Use unsigned `integratedTime` or caller build timestamps: an attacker can choose a favorable certificate
  validity time unless the verifier validates authenticated time bound to the exact signature.
- Make transparency material optional while promising complete offline keyless verification: leaves an
  undefined trust/time gap. Choose and document a verifiable time/root policy before implementation.
- Verify signatures without recomputing subjects: permits replay onto unrelated artifact bytes.
- Fetch trust/key material from bundle URLs: makes untrusted input select its own trust and network targets.

## Consequences and validation

BT-016 includes offline-material packaging, not just a Fulcio call. BT-017 depends on both signing modes
and explicit policy/reason design; BT-019 includes expired-leaf historical and negative trust fixtures.
Independent PAE/DSSE/Sigstore checks, network-disabled artifact verification, secret/output/resource tests
and unchanged M2/M3 gates are required by the phase document. This proposal is not an accepted ADR,
does not change recorder v1 semantics and does not claim SLSA certification or witnessed build history.

## Reference specifications to pin during implementation

- [DSSE protocol and PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)
- [Sigstore trust roots](https://docs.sigstore.dev/about/security/)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [Existing recorder v1](../build-types/record/v1.md) and [accepted ADR 0005](0005-m3-unsigned-recorder-contract.md)
