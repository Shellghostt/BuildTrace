# ADR 0006 — M4 DSSE signing and offline signer verification

- Status: accepted
- Date: 2026-11-22
- Required by: [M4 requirements](../phases/M4.md), BT-014–BT-019
- Extends: ADR 0005 signing/output modes and its standard-library-only runtime decision;
  preserves ADRs 0001–0005, M2 hashing and M3 unsigned recorder/inspect semantics

## Context

M3 records unsigned observations and explicit caller assertions. M4 authenticates the signer of
those exact bytes and independently recomputes caller-selected artifacts. A signed recorder label
is not certificate/OIDC identity, witnessed build history, artifact safety or a SLSA level. Offline
historical keyless verification needs authenticated time bound to this signature and external roots.

## Formats, bytes and bounds

1. `record --sign none` remains the default compact LF-terminated M3 statement, byte for byte.
   `--sign local` emits a DSSE JSON envelope; `--sign keyless` emits a single standard Sigstore v0.3
   bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`) with its DSSE envelope and offline material.
   Both wrap the original M3 payload, including LF. Neither emits an unsigned result after a failure.
2. DSSE type is exactly `application/vnd.in-toto+json`. Sign/verify PAE
   `DSSEv1 <decimal UTF-8 byte-length(type)> <type> <decimal byte-length(payload)> <payload>`.
   Authenticate received payload bytes before interpreting their recorder claims; never reserialize
   JSON to authenticate it. Envelope formatting/key order is outside the signed payload.
3. Outer input is at most 32 MiB, 64 nesting levels and 200,000 JSON tokens. Reject duplicate keys,
   unknown security fields, case aliases, non-UTF-8, trailing documents, null required fields and
   noncanonical/malformed standard padded base64. Decoded payload retains M3's 16 MiB, 64 levels,
   200,000 tokens, one terminated line and 1,000 resources per array.
4. M4 authenticates **one signature** against one explicit signer policy. The parser caps arrays at
   16 signatures; 2–16 signatures are `ambiguous_signatures`, and 17 or more exceed the input bound.
   No quorum, fallback selection or trust from an envelope `keyid` is implemented. Signature bytes
   are at most 128; key IDs at most 128 public UTF-8 bytes. A local key ID is `sha256:<SPKI DER hash>`.
5. Bundles contain exactly one leaf certificate (16 KiB DER maximum), one Rekor v1 `dsse/0.0.1` entry,
   a signed entry timestamp (SET), inclusion proof and signed checkpoint. Reject message signatures,
   certificate-chain/embedded-public-key alternatives, RFC3161 alternatives and other bundle/log versions.
   Canonical log body is at most 128 KiB; SET/signature at most 128 bytes; checkpoint at most 16 KiB;
   proof at most 64 SHA-256 hashes; log/checkpoint indices are nonnegative bounded int64 values.
   Security failures are never repaired by an online lookup.
6. Trusted root is the standard Sigstore trusted-root v0.1 JSON supplied through `--trusted-root`.
   Maximum 1 MiB; at most 16 certificate authorities/logs per collection and 8 certificates per
   root chain, each at most 16 KiB. No bundle URL, embedded certificate or payload field is a root.
   Only the maintained library interprets and verifies standard certificate/CT/log formats.

## Local key policy and private material

- Private key path comes only from `BUILDTRACE_SIGNING_KEY`. Support one unencrypted PKCS#8 `PRIVATE KEY`
  for Ed25519/P-256 or SEC1 `EC PRIVATE KEY` for P-256. Reject RSA, other curves, encrypted PEM,
  PEM headers, multiple blocks, trailing material, terminal symlinks and nonregular/oversized files.
  Reads are bounded to 16 KiB and check opened-file identity. POSIX requires owner-only key permissions;
  Windows callers must restrict the file's ACL because Go permission bits do not describe Windows ACLs.
- Local verification requires `--public-key <file>` with one PKIX `PUBLIC KEY` for Ed25519/P-256,
  supplied outside the attestation. The report identifies that external key by its SPKI SHA-256.
  Private keys/public certificates in the input are never trust anchors.
- Ed25519 signs PAE directly; P-256 signs its SHA-256 using strict ASN.1 ECDSA. Public keys and signature
  structure are validated before use. Local operations need no git/OIDC/Fulcio/Rekor/network call.
- Key/token bytes and passphrases are never flags, diagnostics, reports, attestations or subprocess
  environments. Git retains its existing environment allowlist. Keyless ephemeral keys exist only in
  process memory. Temporary key buffers are cleared; Go does not promise complete heap zeroization.

## Pinned keyless workflow and trust

- Use `github.com/sigstore/sigstore-go v1.3.0` (Apache-2.0), immutable commit
  `22d3691c7b8e0c5530fae3c05577690bfef5cd00`, module sum
  `h1:hnIMHREyCNTYFtOE1o7ae3Axa9B5W5EjUSBJICP2NBE=` and go.mod sum
  `h1:AyRQXfpH89py1twjE3kEZxlRersng90GSYqQV9zGJE8=`.
  This is the latest released Sigstore-Go version compatible with the accepted Go 1.26 floor;
  v1.4.0 requires Go 1.27. Keep Go/toolchain 1.26.0/1.26.11.
- Pin the compatible standard formats to `github.com/sigstore/protobuf-specs v0.5.1`, the Rekor client
  to `github.com/sigstore/rekor v1.5.3`, signature/CT support to the compatible library graph, and
  `google.golang.org/protobuf v1.36.12`. The independent DSSE implementation is
  `github.com/secure-systems-lab/go-securesystemslib v0.11.1` (MIT), sum
  `h1:ayahDPjfSIqKegyt5YVGEvQ7SAi72GHXTy+b2YjUd5w=`. Commit all resolved go.mod/go.sum pins and
  license/checksum inventory; audit the runtime and isolated reference dependencies before acceptance.
- Signing uses public-good `https://fulcio.sigstore.dev` (v2 certificate API) and
  `https://rekor.sigstore.dev` (v1 API), explicit P-256 ephemeral keys, no browser login and no service
  override from input. The token comes from `BUILDTRACE_OIDC_TOKEN_FILE` (bounded regular private file)
  or GitHub Actions' OIDC request environment with audience `sigstore`. Validate GitHub's HTTPS
  `*.actions.githubusercontent.com` request host; never log response bodies/tokens or execute curl/git
  to obtain them. Bound each response to 1 MiB, disable redirects/proxies, use finite timeouts/retries
  and a two-minute cancellation deadline. An unavailable service fails visibly.
- Signing requires a pre-provisioned `--trusted-root` and validates the generated bundle before
  publication. Offline verification imports **no TUF client**, performs no network/subprocess call,
  and reads only the explicit input, policy/root and artifact files.
- Require Rekor SET-bound integrated time, the proof/checkpoint and a trusted CT signed certificate
  timestamp. Validate entry binding to the exact payload/signature/certificate, trusted log key,
  checkpoint, Merkle inclusion, certificate chain/algorithm/extensions and SCT. Validate leaf and
  applicable roots/log keys at authenticated signing time. No recorder/caller timestamp or unsigned
  `integratedTime` substitutes for the SET. Historical signatures can verify after leaf expiry.
- Expected certificate identity and OIDC issuer are mandatory, literal, bounded UTF-8 strings under
  `--expect-identity` / `--expect-issuer`. Match exactly without trimming, URL normalization or regex.
  A root file is a caller-provisioned anchor, not self-authenticating JSON. Setup may fetch/update
  roots using authenticated Sigstore TUF and pin their digest; verification never updates them.
  Offline verification cannot discover later revocations/compromise or prove global log consistency;
  callers maintain trusted root snapshots and their own freshness/compromise policy.
- The focused GitHub Actions M4 job signs a disposable synthetic fixture, then verifies with network
  disabled and checks tampering/identity mismatch. Its job alone gets `id-token: write`. It does not
  publish a release or implement the M5 reusable action. Real signing requires feature-branch
  publication authorization; local synthetic checks do not count as live GitHub/Fulcio evidence.

## Artifact mapping and statement interpretation

`verify --manifest` keeps its existing interface, report, reasons and exits. The separate signed path is:

```text
buildtrace verify --attestation <file> --artifact <relative-path> [--artifact ...] --root <dir>
  (--public-key <file> | --trusted-root <file> --expect-identity <exact> --expect-issuer <exact>)
  [--subject <canonical-name> ...] [--expect-builder <exact-recorder-label>]
  [--expect-source-uri <exact-uri> --expect-source-commit <full-lowercase-commit>] [--json]
```

Selections are 1–1,000 explicit relative paths under the caller's root. Their canonical path is the
subject name by default; a complete positional `--subject` list permits relocation without reading
paths supplied by the statement. Reject traversal, absolute/drive paths, duplicates and ambiguous
subjects. Anchor reads with `os.Root`; do not follow a terminal artifact symlink. Reuse unchanged M2
canonical bytes and mutation checks through a rooted hasher entry point. Only selected files open;
report selected checks and all unselected subject names.

Authenticate first, parse the bounded statement, find each unique canonical selected subject, and
recompute selected digests. Then require the known recorder v1 build type, validate its exact field
contract/subject associations and compare observed kind/byte count. A separate `--expect-builder`
constraint compares the signed recorder assertion, never certificate identity. Optional source policy
compares the declared URI/full commit and its `caller_assertion` dependency; it proves no original source.

Unsigned input fails by default. Explicit `--allow-unsigned` accepts M3 JSONL **only without any signer
key/issuer/identity/trust policy**, with `unsigned_statement / matched`, `authenticated: false`, a
warning and the same selected digest/kind/size checks. A signing/verification error never invokes it.

## Reports, precedence and failure reasons

Signed reports are version 1 with `scope: signed_statement`, status `verified` or `failed`, explicit
`authenticated`, external signer evidence/expected policy, selected checks, unselected names and a
one-line fixed explanation. Authentication evidence on a later artifact failure is not an overall
verified verdict. Unsigned opt-in, M3 inspection and M2 unsigned manifests keep distinct statuses/scopes.
`--json` emits exactly one JSON document, including signed usage failures; diagnostics contain no raw
security input. Output failure exits 3 and never reports successful completion.

| Order / condition | Reason | Exit |
|---|---|---|
| Invalid/incompatible policy, parser/bound/format/subject ambiguity | `invalid_input` | 2 |
| 2–16 signatures | `ambiguous_signatures` | 2 |
| No signature / unsigned without opt-in | `missing_signature` | 1 |
| Malformed or unsupported key/curve | `invalid_input` / `unsupported_key` | 2 |
| Malformed/missing trusted-root input | `trust_invalid` | 2 |
| Input/key/root unreadable | `input_unreadable` / `key_unreadable` / `trust_unreadable` | 3 |
| PAE signature fails under the external key or leaf key | `signature_invalid` | 1 |
| Missing SET/proof/checkpoint or authenticated time | `signing_time_missing` | 1 |
| Invalid/untrusted entry, SET, proof, checkpoint or bound time | `transparency_invalid` | 1 |
| Invalid/untrusted certificate, chain, extensions, validity or SCT | `certificate_invalid` | 1 |
| Exact certificate signer/issuer does not match | `identity_mismatch` | 1 |
| A selected unique subject is absent | `subject_missing` | 1 |
| Selected artifact absent / unreadable or concurrently changed | `artifact_missing` / `artifact_unreadable` | 2 / 3 |
| Selected SHA-256 differs | `digest_mismatch` | 1 |
| Unknown build type | `unsupported_build_type` | 2 |
| Known recorder kind/byte count differs | `kind_mismatch` / `size_mismatch` | 1 |
| Separate recorder-label assertion differs | `builder_mismatch` | 1 |
| Explicit declared source/dependency policy differs | `dependency_mismatch` | 1 |
| Cancellation, signing service failure or output failure | `signing_failed` / `output_failed` | 3 |

Missing attestation/public-key files are invalid input (2); other file I/O is 3. Missing artifacts are
2. A valid but untrusted root snapshot fails cryptographic verification (1). Within a phase, selection
order is the caller's order. No later check can replace a failure with success.

## Atomic publication and validation

Validate the destination before capture/signing. It cannot replace/include an artifact or private key.
Publish a complete envelope/bundle through a checked sibling temporary file, sync, cancellation check
and atomic rename; failed/interrupted writes remove the temporary file and preserve old output.
Stdout is written only after signing/validation completes; an interrupted external pipe cannot be
rolled back and exits 3. Redirected stdout must be outside artifacts and key files.

Independent PAE/DSSE vectors and Sigstore verification, synthetic historical Fulcio/CT/Rekor fixtures,
negative trust/time/policy matrices, selected-root traversal/symlink cases, secret/cancellation/output
checks, repeated lifecycle heap/RSS/goroutine evidence and unchanged M2/M3 gates are required. Record
actual versions/commands/limits/skips in M4 validation; never claim live keyless or final CI before it runs.

## References

- [DSSE PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [Sigstore-Go v1.3.0 source](https://github.com/sigstore/sigstore-go/tree/v1.3.0)
- [Sigstore bundle](https://docs.sigstore.dev/about/bundle/)
- [Sigstore trust model](https://docs.sigstore.dev/about/security/)
- [Recorder v1](../build-types/record/v1.md) and [ADR 0005](0005-m3-unsigned-recorder-contract.md)
