package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shellghostt/buildtrace/internal/manifest"
	"github.com/shellghostt/buildtrace/internal/verify"
)

func (a *App) runVerify(args []string) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(a.Stderr)
	input := flags.String("manifest", "", "unsigned manifest to verify")
	root := flags.String("root", ".", "base directory for relative artifact paths; no git needed")
	asJSON := flags.Bool("json", false, "write a machine-readable verification report")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInput
	}
	report := verify.Report{Scope: "unsigned_manifest", Status: "failed", Reason: "invalid_input"}
	if *input == "" || flags.NArg() != 0 {
		return a.verificationReport(report, *asJSON, ExitInvalidInput, errors.New("--manifest is required and positional arguments are not accepted"))
	}
	f, err := os.Open(*input)
	if err != nil {
		code := ExitToolError
		if errors.Is(err, os.ErrNotExist) {
			code = ExitInvalidInput
		}
		return a.verificationReport(report, *asJSON, code, err)
	}
	m, err := manifest.Read(f)
	_ = f.Close()
	if err != nil {
		code := ExitToolError
		var invalid *manifest.ReadError
		if errors.As(err, &invalid) {
			code = ExitInvalidInput
			report.Reason = invalid.Reason
		}
		return a.verificationReport(report, *asJSON, code, err)
	}
	report, err = verify.Check(m, *root)
	code := ExitVerificationFailed
	if err != nil {
		code = ExitToolError
		if errors.Is(err, os.ErrNotExist) {
			code = ExitInvalidInput
			report.Reason = "artifact_missing"
		}
	}
	if report.Status == "matched" {
		code = ExitOK
	}
	return a.verificationReport(report, *asJSON, code, err)
}

func (a *App) verificationReport(report verify.Report, asJSON bool, code int, err error) int {
	if asJSON {
		if e := json.NewEncoder(a.Stdout).Encode(report); e != nil {
			_, _ = fmt.Fprintf(a.Stderr, "error: write verification report: %v\n", e)
			return ExitToolError
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "%s: %v\n", report.Reason, err)
	}
	if !asJSON {
		if code == ExitOK {
			if _, e := fmt.Fprintf(a.Stdout, "matched: %d artifact(s) against unsigned manifest; signature and builder identity are not verified\n", report.Verified); e != nil {
				return ExitToolError
			}
		} else if err == nil {
			_, _ = fmt.Fprintf(a.Stderr, "%s: artifact %q (%s), expected %s, actual %s\n", report.Reason, report.Artifact, report.Path, report.Expected, report.Actual)
		}
	}
	return code
}

// The manifest must not replace an artifact or become part of a directory
// artifact, which would change the bytes immediately after hashing.
func validateOutput(root string, artifacts []string, output string) error {
	if output == "" {
		return nil
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(parent, filepath.Base(abs))
	}
	for _, p := range artifacts {
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		p, err = filepath.Abs(p)
		if err != nil {
			return err
		}
		if parent, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			p = filepath.Join(parent, filepath.Base(p))
		}
		if info, err := os.Lstat(p); err == nil && info.IsDir() {
			if real, err := filepath.EvalSymlinks(p); err == nil {
				p = real
			}
		}
		rel, err := filepath.Rel(p, abs)
		if err != nil {
			continue
		}
		if rel == "." {
			return errors.New("manifest output cannot replace an artifact")
		}
		info, err := os.Lstat(p)
		if err == nil && info.IsDir() && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("manifest output must be outside directory artifacts")
		}
	}
	return nil
}

// Rename a sibling temporary file rather than following a destination symlink
// or truncating a hard-linked artifact before the write succeeds.
func writeManifest(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".buildtrace-manifest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
