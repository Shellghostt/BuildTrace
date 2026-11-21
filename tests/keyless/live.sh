#!/usr/bin/env bash
# Focused M4 GitHub OIDC/Fulcio/Rekor evidence using disposable public data.
# It does not publish a release or implement the M5 reusable action.
set -euo pipefail
binary=${1:-bin/buildtrace}
image=${2:-buildtrace:m4-keyless}
identity=${EXPECTED_IDENTITY:?exact workflow identity is required}
issuer=${EXPECTED_ISSUER:?exact OIDC issuer is required}
root=.tmp/m4-live-trusted-root.json
mkdir -p bin/m4-live .tmp
printf 'BuildTrace M4 disposable keyless CI artifact\n' >bin/m4-live/artifact.txt
make VERSION=m4-ci trust-setup TRUST_ROOT="$root"
"$binary" record --repo . --artifact bin/m4-live/artifact.txt --sign keyless \
  --trusted-root "$root" --out bin/m4-live.sigstore.json
docker build --build-arg VERSION=m4-ci -t "$image" .

verify_offline() {
  MSYS_NO_PATHCONV=1 docker run --rm --network none --read-only --cap-drop ALL \
    -v "$PWD:/work:ro" --workdir /work "$image" verify \
    --attestation bin/m4-live.sigstore.json --artifact bin/m4-live/artifact.txt \
    --root /work --trusted-root "$root" --expect-issuer "$issuer" \
    --expect-identity "$1" --json
}
verify_offline "$identity" >.tmp/m4-live-verified.json
grep -q '"status":"verified"' .tmp/m4-live-verified.json
grep -q '"authenticated":true' .tmp/m4-live-verified.json
code=0
verify_offline "$identity-wrong-workflow" >.tmp/m4-live-identity-negative.json || code=$?
test "$code" = 1
grep -q '"reason":"identity_mismatch"' .tmp/m4-live-identity-negative.json
cp bin/m4-live/artifact.txt .tmp/m4-live-original-artifact.txt
printf tampered >bin/m4-live/artifact.txt
code=0
verify_offline "$identity" >.tmp/m4-live-tamper-negative.json || code=$?
test "$code" = 1
grep -q '"reason":"digest_mismatch"' .tmp/m4-live-tamper-negative.json
cp .tmp/m4-live-original-artifact.txt bin/m4-live/artifact.txt
printf 'M4 real keyless signing and offline identity/digest checks passed.\n'
