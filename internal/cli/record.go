package cli

import (
	"errors"
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/internal/metadata"
)

func (a *App) runRecord(args []string) int {
	flags := flag.NewFlagSet("record", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	var artifacts stringList
	flags.Var(&artifacts, "artifact", "existing file, directory or terminal symlink (repeatable)")
	repo := flags.String("repo", ".", "checkout to observe and root for artifact paths")
	output := flags.String("out", "", "unsigned JSONL output (default: stdout)")
	sign := flags.String("sign", "none", "signing mode; M3 supports only none")
	builder := flags.String("builder-id", "", "public recorder label (default: BuildTrace local-recorder URI)")
	invocation := flags.String("invocation-id", "", "public recording ID (default: canonical statement SHA-256)")
	sourceURI := flags.String("source-uri", "", "asserted original source URI; requires source-commit")
	sourceCommit := flags.String("source-commit", "", "asserted full source commit; requires source-uri")
	started := flags.String("started-on", "", "asserted original build start; requires finished-on")
	finished := flags.String("finished-on", "", "asserted original build finish; requires started-on")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(a.Stderr, "Usage: buildtrace record --artifact <path> [--artifact <path>...] [--repo <dir>] [--out <file>] [--sign none]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitInvalidInput
	}
	if *sign != "none" {
		_, _ = fmt.Fprintln(a.Stderr, "error: M3 supports only unsigned record --sign none")
		return ExitInvalidInput
	}
	if flags.NArg() != 0 || len(artifacts) == 0 || len(artifacts) > attestation.MaxArtifacts {
		_, _ = fmt.Fprintln(a.Stderr, "error: record requires 1–1000 artifact selections and no positional arguments")
		return ExitInvalidInput
	}
	empty := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name != "out" && strings.TrimSpace(value.Value.String()) == "" {
			empty = true
		}
	})
	if empty {
		_, _ = fmt.Fprintln(a.Stderr, "error: explicitly supplied metadata and paths must not be empty")
		return ExitInvalidInput
	}
	collector := metadata.GitCollector{Dir: *repo, Runner: a.Git}
	source, err := collector.Collect(a.context())
	if err != nil {
		code := ExitToolError
		if errors.Is(err, metadata.ErrNotARepository) || errors.Is(err, metadata.ErrNoCommits) {
			code = ExitInvalidInput
		}
		_, _ = fmt.Fprintf(a.Stderr, "error: read checkout metadata: %v\n", err)
		return code
	}
	root, err := collector.Root()
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: read checkout root: %v\n", err)
		return ExitToolError
	}
	if err := validateOutput(root, artifacts, *output); err != nil {
		_, _ = fmt.Fprintln(a.Stderr, "error: statement output must be outside and must not replace selected artifacts")
		return ExitInvalidInput
	}
	observations, err := attestation.Collect(root, artifacts)
	if err != nil {
		return a.recordError(err)
	}
	toolchain := metadata.CollectToolchain(a.context(), a.Git)
	version := a.Version
	if version == "" {
		version = "dev"
	}
	encoded, err := attestation.Build(attestation.Options{Artifacts: observations,
		Checkout:  attestation.Checkout{URI: source.URI, Commit: source.Commit, Dirty: source.Dirty},
		Recorder:  attestation.Recorder{Version: version, GoVersion: toolchain.Go, GitVersion: toolchain.Git, OS: runtime.GOOS, Arch: runtime.GOARCH},
		BuilderID: *builder, InvocationID: *invocation, SourceURI: *sourceURI, SourceCommit: *sourceCommit,
		StartedOn: *started, FinishedOn: *finished})
	if err != nil {
		return a.recordError(err)
	}
	if *output == "" {
		if _, err := a.Stdout.Write(encoded); err != nil {
			_, _ = fmt.Fprintln(a.Stderr, "error: write unsigned statement")
			return ExitToolError
		}
	} else if err := writeManifest(*output, encoded); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: write unsigned statement: %v\n", err)
		return ExitToolError
	}
	_, _ = fmt.Fprintln(a.Stderr, "unsigned statement generated; checkout observations and caller claims do not authenticate the original build or builder")
	if source.Dirty {
		_, _ = fmt.Fprintln(a.Stderr, "warning: observed checkout has uncommitted changes; dirty: true")
	}
	return ExitOK
}

func (a *App) recordError(err error) int {
	_, _ = fmt.Fprintf(a.Stderr, "error: record artifact observations: %v\n", err)
	if attestation.IsInputError(err) {
		return ExitInvalidInput
	}
	return ExitToolError
}
