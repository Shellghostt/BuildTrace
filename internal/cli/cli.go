// Package cli implements the buildtrace commands.
//
// The package exists so that the commands can be tested: the exit code and
// the output are part of the tool's contract, and a test that cannot call
// main cannot check them.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shellghostt/buildtrace/internal/manifest"
	"github.com/shellghostt/buildtrace/internal/metadata"
)

// Exit codes, as defined in docs/PLAN.md section 8.
const (
	// ExitOK means the command did what it was asked to do.
	ExitOK = 0
	// ExitVerificationFailed means a verification did not pass. No
	// verification exists in M1.
	ExitVerificationFailed = 1
	// ExitInvalidInput means the input was wrong: a malformed attestation,
	// a missing artifact, a directory that is not a repository.
	ExitInvalidInput = 2
	// ExitToolError means BuildTrace itself failed: an I/O error, an
	// unreadable file, a command that does not exist yet.
	ExitToolError = 3
)

// App is one run of the tool.
type App struct {
	// Version is the version of the binary.
	Version string
	// Stdout receives the command output.
	Stdout io.Writer
	// Stderr receives the warnings and the errors.
	Stderr io.Writer
	// Now returns the current time. It is injectable so that the tests can
	// pin the timestamp.
	Now func() time.Time
	// Runner executes git. Empty means the real git binary.
	Git metadata.Runner
	// LookupEnv reads an environment variable. Empty means os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// Run executes one command and returns the exit code.
func (a *App) Run(args []string) int {
	a.applyDefaults()

	if len(args) == 0 {
		a.usage()
		return ExitInvalidInput
	}

	switch args[0] {
	case "manifest":
		return a.runManifest(args[1:])
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(a.Stdout, "buildtrace %s\n", a.Version)
		return ExitOK
	case "help", "--help", "-h":
		a.usage()
		return ExitOK
	case "record", "verify", "inspect":
		_, _ = fmt.Fprintf(a.Stderr,
			"buildtrace %s is planned for a later milestone and is not implemented yet\n", args[0])
		return ExitToolError
	default:
		_, _ = fmt.Fprintf(a.Stderr, "error: unknown command %q\n", args[0])
		a.usage()
		return ExitInvalidInput
	}
}

func (a *App) applyDefaults() {
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.LookupEnv == nil {
		a.LookupEnv = os.LookupEnv
	}
}

// context returns the context the commands run in.
func (a *App) context() context.Context {
	return context.Background()
}

func (a *App) usage() {
	_, _ = fmt.Fprint(a.Stdout, `buildtrace - build provenance and artifact verification

Usage:
  buildtrace manifest --artifact <file> [--artifact <file>...] --out <file>
                      [--repo <dir>] [--built-at <RFC3339>] [--builder-id <id>]
  buildtrace version
`)
}

// runManifest builds the manifest.
//
// The command fails with exit 2 when the input is wrong: outside a git
// repository, a missing artifact, a directory artifact. It fails with exit
// 3 when the tool itself fails: an unwritable output file.
func (a *App) runManifest(args []string) int {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprint(a.Stderr, `Usage: buildtrace manifest --artifact <file> [--artifact <file>...] --out <file>
                      [--repo <dir>] [--built-at <RFC3339>] [--builder-id <id>]
`)
	}

	var artifactPaths stringList
	flags.Var(&artifactPaths, "artifact", "the file the build produced (repeatable)")
	output := flags.String("out", "", "where to write the manifest (default: stdout)")
	repo := flags.String("repo", ".", "the repository the build came from")
	builtAt := flags.String("built-at", "", "the build timestamp (RFC3339, default: now)")
	builderID := flags.String("builder-id", "local", "the identity of the builder")

	if err := flags.Parse(args); err != nil {
		return ExitInvalidInput
	}
	if len(artifactPaths) == 0 {
		_, _ = fmt.Fprintln(a.Stderr, "error: at least one --artifact is required")
		return ExitInvalidInput
	}

	builtTime, err := a.resolveBuiltAt(*builtAt)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitInvalidInput
	}

	collector := metadata.GitCollector{Dir: *repo, Runner: a.Git}
	source, err := collector.Collect(a.context())
	if err != nil {
		if errors.Is(err, metadata.ErrNotARepository) {
			_, _ = fmt.Fprintf(a.Stderr, "error: %s is not a git repository\n", *repo)
			return ExitInvalidInput
		}
		if errors.Is(err, metadata.ErrNoCommits) {
			_, _ = fmt.Fprintf(a.Stderr, "error: %s has no commits yet\n", *repo)
			return ExitInvalidInput
		}
		_, _ = fmt.Fprintf(a.Stderr, "error: read the git metadata: %v\n", err)
		return ExitToolError
	}

	root, err := repositoryRoot(*repo, a.Git)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: read the repository root: %v\n", err)
		return ExitToolError
	}

	artifacts, err := manifest.CollectArtifacts(root, artifactPaths)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitInvalidInput
	}

	builder := metadata.Platform(*builderID)
	toolchain := metadata.CollectToolchain(a.context(), a.Git)

	document := manifest.New(builtTime, source, builder, toolchain, artifacts)
	encoded, err := document.Marshal()
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitToolError
	}

	if source.Dirty {
		_, _ = fmt.Fprintln(a.Stderr,
			"warning: the working tree has uncommitted changes; the manifest records dirty: true")
	}

	if *output == "" {
		if _, err := a.Stdout.Write(encoded); err != nil {
			_, _ = fmt.Fprintf(a.Stderr, "error: write the manifest: %v\n", err)
			return ExitToolError
		}
		return ExitOK
	}

	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "error: write %s: %v\n", *output, err)
		return ExitToolError
	}
	return ExitOK
}

// resolveBuiltAt returns the build timestamp.
//
// The timestamp can be pinned with --built-at or with SOURCE_DATE_EPOCH, so
// that two runs over the same inputs produce the same bytes.
func (a *App) resolveBuiltAt(value string) (time.Time, error) {
	if value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("--built-at %q is not an RFC3339 timestamp", value)
		}
		return parsed.UTC(), nil
	}

	if epoch, ok := a.LookupEnv("SOURCE_DATE_EPOCH"); ok && strings.TrimSpace(epoch) != "" {
		seconds, err := strconv.ParseInt(strings.TrimSpace(epoch), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH %q is not a Unix timestamp", epoch)
		}
		return time.Unix(seconds, 0).UTC(), nil
	}

	return a.Now().UTC(), nil
}

// repositoryRoot returns the root of the repository the directory belongs to.
func repositoryRoot(dir string, runner metadata.Runner) (string, error) {
	collector := metadata.GitCollector{Dir: dir, Runner: runner}
	root, err := collector.Root()
	if err != nil {
		return "", err
	}
	return root, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}
