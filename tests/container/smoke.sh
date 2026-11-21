#!/usr/bin/env bash
# Run the actual runtime image with no network and no persistent test data.
set -euo pipefail
image=${1:-buildtrace:ci}
fixture_dir=$(cd "$(dirname "$0")/../fixtures/m4" && pwd)
if command -v cygpath >/dev/null 2>&1; then fixture_dir=$(cygpath -m "$fixture_dir"); fi
[[ $(docker image inspect --format '{{.Config.User}}' "$image") == '65532:65532' ]]
MSYS_NO_PATHCONV=1 docker run --rm --network none --read-only "$image"
MSYS_NO_PATHCONV=1 docker run --rm -i --network none --read-only --cap-drop ALL \
  -v "$fixture_dir:/fixtures:ro" --tmpfs /work:mode=1777 --entrypoint /bin/sh "$image" -s <<'CONTAINER'
set -eu
binary=/usr/local/bin/buildtrace
test "$(id -u)" = 65532
mkdir /work/repo
cd /work/repo
git init -q
git -c user.name=ContainerSmoke -c user.email=container-smoke@example.invalid \
  commit --allow-empty -qm fixture
git remote add origin https://example.invalid/owner/project.git
printf hello >app
mkdir -p bundle/empty
printf payload >bundle/file
ln -s file bundle/link
"$binary" manifest --repo /work/repo --artifact app --artifact bundle \
  --built-at 2026-11-14T00:00:00Z --out /work/manifest.json
# Independently computed SHA-256 of 'hello', without a trailing newline.
grep -q 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 \
  /work/manifest.json
"$binary" manifest --repo /work/repo --artifact app --artifact bundle \
  --built-at 2026-11-14T00:00:00Z --out /work/again.json
cmp /work/manifest.json /work/again.json
PATH=/no-tools "$binary" verify --manifest /work/manifest.json --root /work/repo \
  --json >/work/matched.json
grep -q '"scope":"unsigned_manifest"' /work/matched.json
grep -q '"status":"matched"' /work/matched.json

# M3 records existing bytes; its inspection needs no git or network and makes
# no claims that the checkout produced the artifacts.
"$binary" record --repo /work/repo --artifact app --artifact bundle --artifact bundle/link \
  --sign none --out /work/artifacts.intoto.jsonl
"$binary" record --repo /work/repo --artifact bundle/link --artifact bundle --artifact app \
  --out /work/again.intoto.jsonl
cmp /work/artifacts.intoto.jsonl /work/again.intoto.jsonl
grep -q 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 /work/artifacts.intoto.jsonl
grep -q '"name":"bundle/link"' /work/artifacts.intoto.jsonl
! grep -q 'startedOn\|finishedOn\|resolvedDependencies\|byproducts' /work/artifacts.intoto.jsonl
PATH=/no-tools "$binary" inspect --attestation /work/artifacts.intoto.jsonl --json >/work/inspection.json
grep -q '"scope":"unsigned_statement"' /work/inspection.json
grep -q '"status":"inspected"' /work/inspection.json
PATH=/no-tools "$binary" inspect --attestation /work/artifacts.intoto.jsonl >/work/inspection.txt
grep -q 'builder label:' /work/inspection.txt
grep -q 'dependencies: none recorded' /work/inspection.txt

# M4 authenticates externally pinned public fixtures, including a historical
# leaf certificate that expired in 2025. PATH and Docker networking are disabled.
for algorithm in ed25519 p256; do
  PATH=/no-tools "$binary" verify --attestation "/fixtures/local-$algorithm.dsse.json" \
    --artifact artifact.txt --root /fixtures --public-key "/fixtures/$algorithm.pub.pem" \
    --json >"/work/signed-$algorithm.json"
  grep -q '"status":"verified"' "/work/signed-$algorithm.json"
  grep -q '"authenticated":true' "/work/signed-$algorithm.json"
done
identity='https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4'
issuer='https://issuer.fixture.invalid'
PATH=/no-tools "$binary" verify --attestation /fixtures/historical.sigstore.json \
  --artifact artifact.txt --root /fixtures --trusted-root /fixtures/trusted-root.json \
  --expect-identity "$identity" --expect-issuer "$issuer" --json >/work/keyless.json
grep -q '"authenticatedSigningTime":"2025-01-01T00:05:00Z"' /work/keyless.json
code=0
PATH=/no-tools "$binary" verify --attestation /fixtures/historical.sigstore.json \
  --artifact artifact.txt --root /fixtures --trusted-root /fixtures/trusted-root.json \
  --expect-identity "$identity-wrong" --expect-issuer "$issuer" --json >/work/identity.json || code=$?
test "$code" = 1
grep -q '"reason":"identity_mismatch"' /work/identity.json
printf tampered >/work/selected.txt
code=0
PATH=/no-tools "$binary" verify --attestation /fixtures/local-ed25519.dsse.json \
  --artifact selected.txt --subject artifact.txt --root /work \
  --public-key /fixtures/ed25519.pub.pem --json >/work/signed-tamper.json || code=$?
test "$code" = 1
grep -q '"reason":"digest_mismatch"' /work/signed-tamper.json
PATH=/no-tools "$binary" verify --attestation /work/artifacts.intoto.jsonl \
  --artifact app --root /work/repo --allow-unsigned --json >/work/unsigned-opt-in.json
grep -q '"authenticated":false' /work/unsigned-opt-in.json

expect_cli_failure() {
  expected=$1
  shift
  code=0
  "$binary" "$@" >/work/rejected.txt 2>/work/rejected.err || code=$?
  test "$code" = "$expected"
  test ! -s /work/rejected.txt
}
expect_cli_failure 2 record --sign keyless
expect_cli_failure 2 record --repo /work/repo --artifact app --out /work/repo/app
test "$(cat app)" = hello
expect_cli_failure 2 record --repo /work/repo --artifact bundle --out /work/repo/bundle/statement.jsonl
cat /work/artifacts.intoto.jsonl /work/artifacts.intoto.jsonl >/work/multiple.jsonl
expect_cli_failure 2 inspect --attestation /work/multiple.jsonl
tr -d '\n' </work/artifacts.intoto.jsonl >/work/unterminated.jsonl
expect_cli_failure 2 inspect --attestation /work/unterminated.jsonl
printf '{\n' >/work/truncated.jsonl
expect_cli_failure 2 inspect --attestation /work/truncated.jsonl
printf '' >/work/empty.jsonl
expect_cli_failure 2 inspect --attestation /work/empty.jsonl
dd if=/dev/zero of=/work/oversized.jsonl bs=1048576 count=17 2>/dev/null
expect_cli_failure 2 inspect --attestation /work/oversized.jsonl

expect_failure() {
  expected=$1
  reason=$2
  manifest=$3
  code=0
  PATH=/no-tools "$binary" verify --manifest "$manifest" --root /work/repo \
    --json >/work/failure.json || code=$?
  test "$code" = "$expected"
  grep -q "\"reason\":\"$reason\"" /work/failure.json
}

# h -> j flips one bit while keeping the byte count unchanged.
printf jello >app
expect_failure 1 digest_mismatch /work/manifest.json
grep -q '"artifact":"app"' /work/failure.json
printf hello >app
printf added >bundle/new
expect_failure 1 digest_mismatch /work/manifest.json
rm bundle/new
sed 's/"schemaVersion": 1/"schemaVersion": 99/' /work/manifest.json >/work/unknown.json
expect_failure 2 unsupported_schema_version /work/unknown.json
rm app
expect_failure 2 artifact_missing /work/manifest.json
PATH=/no-tools "$binary" inspect --attestation /work/artifacts.intoto.jsonl --json >/work/inspection-missing.json
grep -q '"status":"inspected"' /work/inspection-missing.json
printf 'BuildTrace container: nonroot/read-only M2/M3 contracts and M4 local/historical keyless verification, explicit unsigned scope, identity/tamper negatives passed with network and tools disabled.\n'
CONTAINER
