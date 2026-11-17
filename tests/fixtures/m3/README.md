# Synthetic unsigned recording fixtures

These two compact, LF-terminated JSONL records exercise the accepted
[recorder contract](../../../docs/build-types/record/v1.md). They are synthetic test data,
not records of the project's actual builds. The repeated `a`/`b` commit IDs, `.invalid` hosts,
fixture recorder version, platform and original-build time claims are deliberately fixed inputs.

| Fixture | Inputs and purpose |
|---|---|
| [observed.intoto.jsonl](observed.intoto.jsonl) | One `dist/app` file containing exactly `hello`, an observed dirty checkout and the default recorder label/derived recording ID. No original-build times, source assertion, dependencies or byproducts. |
| [claimed.intoto.jsonl](claimed.intoto.jsonl) | The same file plus the M2 canonical directory fixture, an explicit recorder label and ID, an asserted source/full commit and paired original-build time claims. The source dependency is annotated `caller_assertion`. |

`hello` has independently known SHA-256
`2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`.
The 16-byte directory fixture contains `a-` (`dash`), `a/x` (`hello`), `é.txt` (`unicode`)
and an empty directory. Its independently computed M2 canonical digest is
`af7be037cf7f2ef0beef5b69314747e532b6ce13738578a8f8f362c105f98727`, exercised by
`TestDirectoryGoldenIgnoresCreationOrderAndMetadata` and the M3 collector test.

`TestRecordGoldenFixtures` compares both files byte for byte; ordinary tests never rewrite them.
The isolated [upstream validator](../../schemas/README.md) checks both fixtures' format offline.
Neither golden comparison nor schema validation establishes an original build, authenticated identity
or SLSA level. `inspect` does not recompute their artifact bytes.

Regenerate only after reviewing a deliberate contract change:

```sh
BUILDTRACE_WRITE_M3_GOLDEN=1 go test ./internal/attestation -run '^TestRecordGoldenFixtures$' -count=1
make schemas
```

Run the schema command with the pinned validator dependencies already installed and the offline
environment documented in its README. Inspect the fixture diff and recompute independent digests
before accepting any golden update.
