package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/shellghostt/buildtrace/internal/signing"
	"github.com/shellghostt/buildtrace/internal/verify"
)

func signedVerifyArgs(args []string) bool {
	for _, argument := range args {
		name, _, _ := strings.Cut(argument, "=")
		switch name {
		case "--attestation", "--artifact", "--subject", "--public-key", "--trusted-root", "--expect-identity", "--expect-issuer", "--expect-builder", "--expect-source-uri", "--expect-source-commit", "--allow-unsigned":
			return true
		}
	}
	return false
}

func jsonRequested(args []string) bool {
	wanted := false
	for _, argument := range args {
		if argument == "--json" || argument == "--json=true" {
			wanted = true
		}
		if argument == "--json=false" {
			wanted = false
		}
	}
	return wanted
}

func (a *App) runSignedVerify(args []string) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	// Fixed diagnostics keep the flag package from echoing mistaken key/token
	// arguments before the scope report.
	flags.SetOutput(io.Discard)
	input := flags.String("attestation", "", "DSSE envelope, Sigstore v0.3 bundle or explicitly unsigned JSONL")
	manifest := flags.String("manifest", "", "incompatible with signed-attestation verification")
	root := flags.String("root", ".", "caller-declared artifact root; no git/network lookup")
	asJSON := flags.Bool("json", jsonRequested(args), "one machine-readable scope/policy/artifact report")
	pub := flags.String("public-key", "", "externally trusted Ed25519/P-256 PKIX public key")
	trusted := flags.String("trusted-root", "", "externally provisioned Sigstore trusted-root v0.1 JSON")
	identity := flags.String("expect-identity", "", "exact certificate signer SAN")
	issuer := flags.String("expect-issuer", "", "exact certificate OIDC issuer")
	unsigned := flags.Bool("allow-unsigned", false, "explicit unsigned comparison; cannot satisfy signer policy")
	builder := flags.String("expect-builder", "", "separate exact signed recorder-label assertion constraint")
	sourceURI := flags.String("expect-source-uri", "", "exact declared source URI; requires expected source commit")
	sourceCommit := flags.String("expect-source-commit", "", "full lowercase declared source commit; requires expected source URI")
	var artifacts, subjects stringList
	flags.Var(&artifacts, "artifact", "explicit relative artifact path under root (repeatable)")
	flags.Var(&subjects, "subject", "canonical subject name for each artifact in matching order (repeatable)")
	report := verify.NewAttestationReport()
	bad := func(message string) int {
		return a.signedVerificationReport(report, *asJSON, &signing.Error{Reason: "invalid_input", Code: 2, Message: message})
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usage()
			return ExitOK
		}
		return bad("invalid signed-verification flags or values")
	}
	empty, manifestRequested := false, false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "manifest" {
			manifestRequested = true
		}
		if value.Name != "json" && value.Name != "allow-unsigned" && strings.TrimSpace(value.Value.String()) == "" {
			empty = true
		}
	})
	if empty || manifestRequested {
		return bad("explicit policy/paths must not be empty or combine signed and manifest modes")
	}
	if *input == "" || *manifest != "" || flags.NArg() != 0 {
		return bad("signed verification requires --attestation and cannot combine --manifest or positional arguments")
	}
	if len(subjects) != 0 && len(subjects) != len(artifacts) {
		return bad("a subject mapping must name every selected artifact in order")
	}
	selection := make([]verify.Selection, len(artifacts))
	for i, artifact := range artifacts {
		name := filepath.ToSlash(artifact)
		if len(subjects) != 0 {
			name = subjects[i]
		}
		selection[i] = verify.Selection{Subject: name, Path: artifact}
	}
	policy := verify.AttestationPolicy{PublicKey: *pub, TrustedRoot: *trusted, Identity: *identity, Issuer: *issuer,
		AllowUnsigned: *unsigned, Builder: *builder, SourceURI: *sourceURI, SourceCommit: *sourceCommit}
	if err := verify.ValidateAttestationPolicy(selection, policy); err != nil {
		return a.signedVerificationReport(report, *asJSON, err)
	}
	data, err := signing.ReadSecurityFile(*input, signing.MaxOuterBytes, false, "input_unreadable")
	if err != nil {
		return a.signedVerificationReport(report, *asJSON, err)
	}
	report, err = verify.CheckAttestation(data, *root, selection, policy)
	return a.signedVerificationReport(report, *asJSON, err)
}

func (a *App) signedVerificationReport(report verify.AttestationReport, asJSON bool, err error) int {
	code := ExitOK
	if err != nil {
		var specific *signing.Error
		if errors.As(err, &specific) {
			report.Reason, report.Message, code = specific.Reason, specific.Message, specific.Code
		} else {
			report.Reason, report.Message, code = "invalid_input", "invalid signed-verification input", ExitInvalidInput
		}
	}
	if asJSON {
		if e := json.NewEncoder(a.Stdout).Encode(report); e != nil {
			_, _ = fmt.Fprintln(a.Stderr, "output_failed: verification report could not be written")
			return ExitToolError
		}
	} else if code == ExitOK {
		message := "verified: signature and external signer policy; %d selected artifact(s), %d unselected subject(s); recorder claims do not witness original build history\n"
		if !report.Authenticated {
			message = "matched: %d selected artifact(s) against explicitly unsigned statement, %d unselected subject(s); signer and original build history are unauthenticated\n"
		}
		if _, e := fmt.Fprintf(a.Stdout, message, report.Verified, len(report.Unselected)); e != nil {
			return ExitToolError
		}
	}
	if code != ExitOK {
		_, _ = fmt.Fprintf(a.Stderr, "%s: %s\n", report.Reason, report.Message)
	}
	return code
}
