package cli

import (
	"context"
	"crypto"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/internal/metadata"
	"github.com/shellghostt/buildtrace/internal/signing"
)

func (a *App) runRecord(args []string) int {
	flags := flag.NewFlagSet("record", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	var artifacts stringList
	flags.Var(&artifacts, "artifact", "existing file, directory or terminal symlink (repeatable)")
	repo := flags.String("repo", ".", "checkout to observe and root for artifact paths")
	output := flags.String("out", "", "statement/envelope/bundle output (default: stdout)")
	sign := flags.String("sign", "none", "signing mode: none, local or keyless")
	trustedRootPath := flags.String("trusted-root", "", "pre-provisioned Sigstore root; required only for keyless signing")
	builder := flags.String("builder-id", "", "public recorder label (default: BuildTrace local-recorder URI)")
	invocation := flags.String("invocation-id", "", "public recording ID (default: canonical statement SHA-256)")
	sourceURI := flags.String("source-uri", "", "asserted original source URI; requires source-commit")
	sourceCommit := flags.String("source-commit", "", "asserted full source commit; requires source-uri")
	started := flags.String("started-on", "", "asserted original build start; requires finished-on")
	finished := flags.String("finished-on", "", "asserted original build finish; requires started-on")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(a.Stderr, "Usage: buildtrace record --artifact <path> [--artifact <path>...] [--repo <dir>] [--out <file>] [--sign none|local|keyless] [--trusted-root <file>]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitInvalidInput
	}
	if *sign != "none" && *sign != "local" && *sign != "keyless" {
		_, _ = fmt.Fprintln(a.Stderr, "invalid_input: signing mode must be none, local or keyless")
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
	if (*sign == "keyless") != (*trustedRootPath != "") {
		_, _ = fmt.Fprintln(a.Stderr, "invalid_input: --trusted-root is required only for keyless signing")
		return ExitInvalidInput
	}
	var privatePath string
	var localKey crypto.Signer
	var trusted signing.TrustedRoot
	if *sign == "local" {
		privatePath, _ = a.LookupEnv("BUILDTRACE_SIGNING_KEY")
		if privatePath == "" {
			return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "local signing requires BUILDTRACE_SIGNING_KEY file path"})
		}
		absolute, err := filepath.Abs(privatePath)
		if err != nil {
			return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "invalid private-key file path"})
		}
		privatePath = absolute
	}
	if *sign == "keyless" {
		var err error
		trusted, err = signing.LoadTrustedRoot(*trustedRootPath)
		if err != nil {
			return a.signingError(err)
		}
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
	protected := []string{}
	if privatePath != "" {
		protected = append(protected, privatePath)
	}
	if *sign == "keyless" {
		absolute, err := filepath.Abs(*trustedRootPath)
		if err != nil {
			return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "invalid trusted-root file path"})
		}
		protected = append(protected, absolute)
		if tokenPath, exists := a.LookupEnv("BUILDTRACE_OIDC_TOKEN_FILE"); exists && tokenPath != "" {
			absolute, err := filepath.Abs(tokenPath)
			if err != nil {
				return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "invalid private token file path"})
			}
			protected = append(protected, absolute)
		}
	}
	if err := validateOutput(root, protected, *output); err != nil {
		return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "signed output must not replace signing policy or private material"})
	}
	if *sign == "local" {
		localKey, err = signing.LoadPrivateKey(privatePath)
		if err != nil {
			return a.signingError(err)
		}
	}
	collect := attestation.Collect
	if *sign != "none" {
		collect = attestation.CollectSigned
	}
	observations, err := collect(root, artifacts)
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
	switch *sign {
	case "local":
		encoded, err = signing.SignLocal(encoded, localKey)
	case "keyless":
		signer := a.KeylessSigner
		if signer == nil {
			signer = signing.SignKeyless
		}
		encoded, err = signer(a.context(), encoded, signing.KeylessOptions{TrustedRoot: trusted, LookupEnv: a.LookupEnv})
	}
	if err != nil {
		return a.signingError(err)
	}
	if *sign != "none" && a.context().Err() != nil {
		return a.signingError(&signing.Error{Reason: "signing_failed", Code: 3, Message: "signing was cancelled before publication"})
	}
	if *sign != "none" {
		if err := validateOutput(root, append(append([]string(nil), artifacts...), protected...), *output); err != nil {
			return a.signingError(&signing.Error{Reason: "invalid_input", Code: 2, Message: "signed output destination changed or overlaps protected input"})
		}
	}
	if *output == "" {
		if n, err := a.Stdout.Write(encoded); err != nil || n != len(encoded) {
			if *sign != "none" {
				return a.signingError(&signing.Error{Reason: "output_failed", Code: 3, Message: "signed output could not be written completely"})
			}
			_, _ = fmt.Fprintln(a.Stderr, "error: write unsigned statement")
			return ExitToolError
		}
	} else {
		write := writeManifest
		if *sign != "none" {
			write = func(path string, data []byte) error { return writeSignedFile(a.context(), path, data) }
		}
		if err := write(*output, encoded); err != nil {
			if *sign != "none" {
				return a.signingError(&signing.Error{Reason: "output_failed", Code: 3, Message: "signed output could not be atomically published"})
			}
			_, _ = fmt.Fprintf(a.Stderr, "error: write unsigned statement: %v\n", err)
			return ExitToolError
		}
	}
	if *sign == "none" {
		_, _ = fmt.Fprintln(a.Stderr, "unsigned statement generated; checkout observations and caller claims do not authenticate the original build or builder")
	} else {
		_, _ = fmt.Fprintf(a.Stderr, "%s signed statement generated; signer authentication does not witness original build history or establish artifact safety\n", *sign)
	}
	if source.Dirty {
		_, _ = fmt.Fprintln(a.Stderr, "warning: observed checkout has uncommitted changes; dirty: true")
	}
	return ExitOK
}

func (a *App) signingError(err error) int {
	var specific *signing.Error
	if errors.As(err, &specific) {
		_, _ = fmt.Fprintln(a.Stderr, specific.Error())
		return specific.Code
	}
	_, _ = fmt.Fprintln(a.Stderr, "signing_failed: signing failed; no output was published")
	return ExitToolError
}

func writeSignedFile(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".buildtrace-signed-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(name) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (a *App) recordError(err error) int {
	_, _ = fmt.Fprintf(a.Stderr, "error: record artifact observations: %v\n", err)
	if attestation.IsInputError(err) {
		return ExitInvalidInput
	}
	return ExitToolError
}
