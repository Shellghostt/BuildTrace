# ADR 0003 - Go 1.26 floor and CI contract

- Status: accepted
- Date: 2026-11-13
- Deciders: Aditya

## Context

The first CI run on GitHub, on 2026-11-13, was green for this project, and it was green on an
end-of-life toolchain. `go.mod` declared `go 1.23`, so `actions/setup-go` installed the newest 1.23
patch release, 1.23.12. The Go project supports the two most recent release lines; 1.23 receives no
fixes. The vulnerability database records the 2026 standard-library advisories with a range that
starts at version 0 and ends at the 1.25 or 1.26 fix, so every 1.23 build is affected by them.
`govulncheck` did not fail here only because this tool does not call the affected functions.

That run also installed golangci-lint v1.64.8, the newest release of the v1 line, because
`golangci/golangci-lint-action@v6` resolves `version: latest` to that release. The v2 line is the
supported one, and the two lines differ: v2 removed errcheck's default exclusion of `fmt` writes, so
the v2 default linter set finds unchecked error returns that v1 did not report.

One limitation recorded in ADR 0002 is no longer true. The race detector could not be run on the
machine that produced M1, because its only C compiler is MinGW GCC 6.3.0. The first CI run on
GitHub executed the race-enabled suite on ubuntu-latest, windows-latest and macos-latest, and it
passed on all three.

## Decisions

1. **The Go floor moves from 1.23 to 1.26.** `go.mod` declares `go 1.26.0`. This supersedes
   decision 1 of ADR 0002. This project has no third-party dependencies, so nothing else moves.
2. **The `toolchain` directive names the exact toolchain CI installs.** `go.mod` declares
   `toolchain go1.26.11`, and `actions/setup-go` prefers it over the `go` directive. A `go` directive
   with a patch version and no `toolchain` line makes setup-go install that exact patch, which is how
   a project ends up pinned to a release with known vulnerabilities. `go mod tidy` preserves the
   `toolchain` line.
3. **The linter is golangci-lint v2.15.0, pinned by version, run by `golangci/golangci-lint-action@v9`.**
   The version is pinned rather than `latest` so that a new release cannot turn a green build red
   without a commit.
4. **Unchecked error returns are fixed, not excluded.** The v2 findings are writes whose error was
   discarded. Each one now says so explicitly with `_, _ =`. No linter exclusion list is added, so
   the next unchecked write is still reported.

## Consequences

- A contributor needs Go 1.26 or newer. `make bootstrap` installs the same linter version CI runs.
- CI installs Go 1.26.11 on every platform and in every job, and the `go version` line in a CI log
  is the exact toolchain the result was produced with.
- The toolchain is on a supported release line, so the next standard-library advisory that affects
  this code is fixed by a patch release of 1.26 rather than by nothing at all.
- The linter now checks this project with the same version as the rest of the portfolio, and the
  findings it produced were fixed in the code rather than hidden in a configuration file.
