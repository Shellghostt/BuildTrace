# Contributing to BuildTrace

Thanks for taking the time. This document is deliberately short and specific.

## Read first

1. [docs/PLAN.md](docs/PLAN.md) - the authoritative specification. It explains scope, architecture,
   milestones and what is explicitly out of scope.
2. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - how the pieces fit together.
3. [docs/adr/](docs/adr/) - decisions that have already been argued about. Do not relitigate them
   without a new ADR.
4. [docs/phases/M4.md](docs/phases/M4.md) - planned signing/trust policy, dependency order and acceptance;
   preserve [M3 contracts](docs/phases/M3.md) and accepted ADR 0005. ADR 0006 remains proposed.
5. [docs/DEVELOPMENT-TOOLS.md](docs/DEVELOPMENT-TOOLS.md) - CodeGraph freshness, static-analysis coverage
   and profiling appropriate to this repository's runtime.

## Ground rules

- Be decent. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security issues never go in a public issue. See [SECURITY.md](SECURITY.md).
- One logical change per pull request. If the description needs "and also", split it.
- Do not invent benchmarks, screenshots or feature claims. If it is not measured, it is not stated.

## Development setup

```bash
git clone https://github.com/shellghostt/buildtrace.git
cd BuildTrace
make bootstrap   # install tooling and dependencies
make test        # unit tests
make lint        # formatting and static analysis
make race        # needs a working 64-bit C compiler on Windows
make schema-setup
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off make schemas
```

The unit tests need a real `git` binary: they create a throwaway repository in a temporary directory
and read it, rather than mocking git's output. A machine without git cannot run them, and the tests
skip themselves with a message saying so.

The upstream format validator lives in a separate `tests/schemas` module. Fetch its pinned
dependencies during setup, then run schema validation offline with the installed Go 1.26.11 compiler.
See its [README](tests/schemas/README.md) for PowerShell setup and the
[M3 validation record](docs/testing/m3-provenance.md) for native race/image/memory commands.
Use `VERSION=m3-local` with Make targets on Windows to bypass the existing Unix version expression.
The CLI itself retains a standard-library-only runtime.

## Code navigation

[CodeGraph](https://github.com/colbymchenry/codegraph) builds a local symbol index of this
repository. It is optional: neither the build nor CI depends on it.

```bash
codegraph init --yes .   # build the index once
codegraph status          # whether the index is current
codegraph sync            # refresh it after a change
```

The index lives in `.codegraph/`. Git ignores its database and temporary files; the
`.codegraph/.gitignore` that enforces that is tracked.

## Commit messages

Conventional Commits, imperative mood, no trailing period:

```
feat(ingest): verify HMAC signature before persisting
fix(retry): honour Retry-After when it exceeds the base delay
docs(plan): record M2 acceptance criteria as met
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.

## Pull request process

1. Open an issue first for anything larger than a typo. It saves everyone time.
2. Branch from `main`: `feat/short-slug`, `fix/short-slug`.
3. Add tests. A pull request that reduces coverage needs a reason in the description.
4. Run `make lint` and `make test` locally before pushing.
5. Fill in the pull request template completely, including how you verified the change.
6. CI must be green. Reviewers are looking for correctness first, style second.

## Definition of done

A change is done when:

- it is implemented, not stubbed;
- it is covered by a test that fails without it;
- `docs/PLAN.md` status fields and `README.md` roadmap reflect the new reality;
- any user-visible behaviour is documented where a user would look for it;
- every field added maps to traceable evidence; artifact digests are independently recomputable and
  caller assertions are explicitly identified rather than presented as authenticated build history;
- the "What this release does not prove" section of the README is updated when the answer changes.

Do not invent a field to fill the format. State which inputs were observed, which are caller assertions,
and what an independent verifier can actually recompute or authenticate.

## Good first issues

Issues labelled `good first issue` are scoped to be completable in one sitting, with the relevant files
listed in the issue body. Claim one by commenting, then open a draft pull request early.
