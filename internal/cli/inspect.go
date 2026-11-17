package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/pkg/intoto"
)

func (a *App) runInspect(args []string) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	input := flags.String("attestation", "", "one unsigned in-toto/SLSA v1 JSONL record to inspect offline")
	asJSON := flags.Bool("json", false, "write unsigned inspection report including the original statement")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitInvalidInput
	}
	if *input == "" || flags.NArg() != 0 {
		_, _ = fmt.Fprintln(a.Stderr, "error: inspect requires --attestation and no positional arguments")
		return ExitInvalidInput
	}
	file, err := os.Open(*input)
	if err != nil {
		code := ExitToolError
		if errors.Is(err, os.ErrNotExist) {
			code = ExitInvalidInput
		}
		_, _ = fmt.Fprintf(a.Stderr, "error: open statement: %v\n", err)
		return code
	}
	report, err := attestation.Read(file)
	_ = file.Close()
	if err != nil {
		code := ExitToolError
		if attestation.IsInputError(err) {
			code = ExitInvalidInput
		}
		_, _ = fmt.Fprintf(a.Stderr, "error: inspect statement: %v\n", err)
		return code
	}
	var encoded []byte
	if *asJSON {
		encoded, err = intoto.MarshalLine(report)
		if err != nil {
			_, _ = fmt.Fprintln(a.Stderr, "error: encode unsigned inspection")
			return ExitToolError
		}
	} else {
		var text strings.Builder
		_, _ = fmt.Fprintln(&text, "inspected: unsigned statement; artifacts, claims and signatures are not verified")
		_, _ = fmt.Fprintf(&text, "build type: %s\nbuilder label: %s\n", report.BuildType, report.BuilderID)
		if !report.RecorderContract {
			_, _ = fmt.Fprintln(&text, "build-type semantics: unknown; fields are displayed without interpretation")
		}
		for _, subject := range report.Subjects {
			name := subject.Name
			if name == "" {
				name = "(unnamed)"
			}
			_, _ = fmt.Fprintf(&text, "subject: %s\n", name)
			// MarshalLine sorts digest map keys for deterministic text output too.
			digests, _ := intoto.MarshalLine(subject.Digest)
			_, _ = fmt.Fprintf(&text, "  declared digests: %s", digests)
		}
		if len(report.Dependencies) == 0 {
			_, _ = fmt.Fprintln(&text, "dependencies: none recorded")
		}
		for _, dependency := range report.Dependencies {
			_, _ = fmt.Fprintf(&text, "declared dependency: %s\n", dependency.URI)
			digests, _ := intoto.MarshalLine(dependency.Digest)
			_, _ = fmt.Fprintf(&text, "  declared digests: %s", digests)
		}
		if report.Metadata != nil {
			_, _ = fmt.Fprintf(&text, "recording ID: %s\n", report.Metadata.InvocationID)
		}
		encoded = []byte(text.String())
	}
	if _, err := a.Stdout.Write(encoded); err != nil {
		_, _ = fmt.Fprintln(a.Stderr, "error: write unsigned inspection")
		return ExitToolError
	}
	return ExitOK
}
