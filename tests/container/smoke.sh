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
printf 'BuildTrace container: nonroot/read-only capture, deterministic file/directory/symlink hashing, offline verification, tamper, schema and missing-file checks passed.\n'
CONTAINER
