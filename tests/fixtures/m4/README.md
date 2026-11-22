# M4 public synthetic fixtures

These files contain no customer data, live token or private key. `artifact.txt` is exactly `hello`
without a newline. Its statement has deliberately synthetic recorder/checkout metadata; it does
not represent a real build or assert artifact origin. The local envelopes use disposable Ed25519
and ECDSA P-256 keys. Their public keys are external verification policy, not embedded trust.

`historical.sigstore.json` is a standard Sigstore v0.3 DSSE bundle generated with synthetic
Fulcio/CT/Rekor keys. Its leaf expires on 2025-01-01 at 00:10Z. Its real cryptographic SET binds
2025-01-01 at 00:05Z to the exact signature/payload/certificate, with a signed one-entry checkpoint
and valid inclusion proof. The trust-root v0.1 file is **test trust only**, unrelated to Sigstore's
public-good service. Its expected exact policy is:

```text
identity: https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4
issuer: https://issuer.fixture.invalid
```

Regenerate from the repository root with `make VERSION=m4-local m4-fixtures` after dependency setup.
Keys/signatures change; unsigned statement bytes and artifact digest do not. The generator returns
only public data, validates the generated keyless bundle, writes eight files plus `SHA256SUMS.json`,
and never writes its private signing material. Ordinary tests validate the committed fixtures and
checksums; they do not regenerate them. Independently verify them through `make schemas`.

Public-good trust provisioning is separate: `make VERSION=m4-local trust-setup`. That opt-in command
authenticates Sigstore TUF using the pinned library's embedded bootstrap root and writes a root
snapshot with a recorded SHA-256. Offline verification only reads the explicit snapshot; it performs
no TUF/network lookup or revocation refresh.
