#!/usr/bin/env bash
# Run the actual runtime image with no network and no persistent test data.
set -euo pipefail
image=${1:-buildtrace:ci}
[[ $(docker image inspect --format '{{.Config.User}}' "$image") == '65532:65532' ]]
docker run --rm --network none --read-only "$image"
docker run --rm -i --network none --read-only --cap-drop ALL \
  --tmpfs /work:mode=1777 --entrypoint /bin/sh "$image" -s <<'CONTAINER'
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
printf 'BuildTrace container: nonroot/read-only M2 hashing/verification and M3 unsigned record/inspect, deterministic output, bounds, collisions, signing rejection and negative checks passed.\n'
CONTAINER
