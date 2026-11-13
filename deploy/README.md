# Distribution

- Single static binary per platform, built by CI.
- No server component in v0.1: provenance is a file plus a signature, verification is offline.
- A registry service is explicitly out of scope until a real need appears.

## What M1 actually distributes

M1 ships one command: `buildtrace manifest`. It produces a JSON file. There is no service, no port, no
storage and no account. That is deliberate: a tool that claims to be a verification system while
running a server invites the reader to trust the server rather than the file.

## The binary

```bash
make build
./bin/buildtrace version
```

The tool has no third-party dependencies. The standard library and `git` are all it needs. A
supply-chain tool that pulls in dependencies to read a git commit makes the problem it exists to
solve worse.

`git` is required for the `manifest` command, because the manifest describes a repository. The tool
runs `git` as a subprocess with an allowlisted environment and no shell.

## Container image

`Dockerfile` builds a minimal image that runs the binary. It is not a production deployment reference.

```bash
make docker
docker run --rm -v "$PWD:/repo" -w /repo buildtrace:latest \
  manifest --artifact dist/app --out buildtrace.json
```

The image has no credentials in it and reads none. The `git` metadata comes from the repository the
command is pointed at.

## Publishing a manifest

The manifest is meant to be published next to the artifact it describes: as a release asset, next to
the binary in an object store, or committed to the repository. It is a plain JSON file with a stable
schema version, so a consumer can read it without any tool from this project.

Two things to know before you publish one:

- **It contains no digest.** Until M2, a published manifest describes the artifact's name, path and
  size. It is not evidence about the bytes.
- **It is not signed.** Until M4, anyone can edit it. Publishing it next to an artifact tells a reader
  what the builder claimed; it does not stop anyone from changing the claim.

## What is not distributed yet

- No attestation file format (M3).
- No signature or DSSE envelope (M4).
- No reusable GitHub Action (M5).
- No SBOM (M6).
