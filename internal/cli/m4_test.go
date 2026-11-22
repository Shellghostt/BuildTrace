package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellghostt/buildtrace/internal/signing"
	"github.com/shellghostt/buildtrace/internal/testrepo"
	"github.com/shellghostt/buildtrace/internal/testsigning"
	"github.com/shellghostt/buildtrace/internal/verify"
)

func m4Keys(t *testing.T, algorithm string) (crypto.Signer, string, string) {
	t.Helper()
	var key crypto.Signer
	if algorithm == "ed25519" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = private
	} else {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = private
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private, pub := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return key, private, pub
}

func m4Report(t *testing.T, stdout string) verify.AttestationReport {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var report verify.AttestationReport
	if err := decoder.Decode(&report); err != nil {
		t.Fatal("expected one JSON verification document", stdout, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatal("stdout contains a second document or trailing data", err)
	}
	return report
}

func TestM4LocalRecordPreservesM3PayloadAndVerifiesWithoutGitClockOrEnvironment(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "p256"} {
		t.Run(algorithm, func(t *testing.T) {
			repo := testrepo.New(t)
			writeArtifact(t, repo.Dir, "app", "hello")
			_, private, pub := m4Keys(t, algorithm)
			unsigned := run(t, &App{Version: "m4-local", Now: func() time.Time { panic("original build clock must not be inferred") }, LookupEnv: func(string) (string, bool) { panic("unsigned mode must not read signing environment") }}, "record", "--repo", repo.Dir, "--artifact", "app")
			if unsigned.code != 0 {
				t.Fatal(unsigned)
			}
			signed := run(t, &App{Version: "m4-local", LookupEnv: func(name string) (string, bool) {
				if name != "BUILDTRACE_SIGNING_KEY" {
					panic("local signer read an unrelated environment value")
				}
				return private, true
			}}, "record", "--repo", repo.Dir, "--artifact", "app", "--sign", "local")
			if signed.code != 0 || strings.Contains(signed.stderr, "unsigned statement generated") {
				t.Fatal(signed)
			}
			decoded, err := signing.DecodeEnvelope([]byte(signed.stdout))
			if err != nil || !bytes.Equal(decoded.Payload, []byte(unsigned.stdout)) {
				t.Fatal("M3 payload bytes changed inside local envelope", err)
			}
			input := filepath.Join(t.TempDir(), "signed.dsse.json")
			if err := os.WriteFile(input, []byte(signed.stdout), 0o644); err != nil {
				t.Fatal(err)
			}
			got := run(t, &App{Git: forbiddenGit{}, Now: func() time.Time { panic("offline verifier must not read caller clock") }, LookupEnv: func(string) (string, bool) { panic("offline verifier must not read environment") }}, "verify", "--attestation", input, "--artifact", "app", "--root", repo.Dir, "--public-key", pub, "--json")
			report := m4Report(t, got.stdout)
			if got.code != 0 || report.Scope != "signed_statement" || report.Status != "verified" || !report.Authenticated || report.Verified != 1 {
				t.Fatal(got, report)
			}
			inspection := run(t, &App{Git: forbiddenGit{}}, "inspect", "--attestation", input, "--json")
			if inspection.code != 2 {
				t.Fatal("M3 unsigned inspection accepted a signed envelope", inspection)
			}
		})
	}
}

func TestM4SignedCLIReasonsExitsAndExactlyOneReport(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	key, _, pub := m4Keys(t, "ed25519")
	payload, err := testsigning.Payload("app", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := signing.SignLocal(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "input.json")
	args := []string{"verify", "--attestation", input, "--artifact", "app", "--root", repo.Dir, "--public-key", pub, "--json"}
	change := func(mutate func(map[string]any)) []byte {
		var value map[string]any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := signing.SignLocal(append(data, '\n'), key)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	var envelope signing.Envelope
	if err := json.Unmarshal(base, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(append([]byte(nil), payload[:len(payload)-1]...))
	tampered, _ := json.Marshal(envelope)
	kind := change(func(o map[string]any) {
		o["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)["observedArtifacts"].([]any)[0].(map[string]any)["kind"] = "directory"
	})
	size := change(func(o map[string]any) {
		o["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)["observedArtifacts"].([]any)[0].(map[string]any)["size"] = 6
	})
	unknown := change(func(o map[string]any) {
		o["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["buildType"] = "https://unknown.fixture.invalid/v1"
	})
	for _, test := range []struct {
		name   string
		data   []byte
		extra  []string
		reason string
		code   int
	}{
		{"invalid JSON", []byte(`{`), nil, "invalid_input", 2},
		{"payload tamper", tampered, nil, "signature_invalid", 1},
		{"subject missing", base, []string{"--subject", "missing"}, "subject_missing", 1},
		{"unknown type", unknown, nil, "unsupported_build_type", 2},
		{"kind", kind, nil, "kind_mismatch", 1},
		{"size", size, nil, "size_mismatch", 1},
		{"builder assertion", base, []string{"--expect-builder", "https://builder.fixture.invalid/wrong"}, "builder_mismatch", 1},
		{"dependency assertion", base, []string{"--expect-source-uri", "git+https://source.fixture.invalid/expected", "--expect-source-commit", strings.Repeat("b", 40)}, "dependency_mismatch", 1},
		{"mixed modes", base, []string{"--manifest", "manifest.json"}, "invalid_input", 2},
		{"empty requested policy", base, []string{"--expect-builder", ""}, "invalid_input", 2},
		{"unsigned downgrade", payload, nil, "missing_signature", 1},
		{"unsigned with signer policy", payload, []string{"--allow-unsigned"}, "invalid_input", 2},
		{"secret unknown flag", base, []string{"--id-token", "fixture-private-token"}, "invalid_input", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(input, test.data, 0o644); err != nil {
				t.Fatal(err)
			}
			got := run(t, &App{Git: forbiddenGit{}, LookupEnv: func(string) (string, bool) { panic("verifier must not consult environment") }}, append(append([]string(nil), args...), test.extra...)...)
			report := m4Report(t, got.stdout)
			if got.code != test.code || report.Reason != test.reason || report.Status != "failed" || strings.Contains(got.stdout+got.stderr, "fixture-private-token") {
				t.Fatal(got, report, test)
			}
		})
	}
	if err := os.WriteFile(input, base, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo.Dir, "app"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := run(t, &App{Git: forbiddenGit{}}, args...)
	report := m4Report(t, got.stdout)
	if got.code != 1 || report.Reason != "digest_mismatch" || !report.Authenticated {
		t.Fatal(got, report)
	}
	if err := os.Remove(filepath.Join(repo.Dir, "app")); err != nil {
		t.Fatal(err)
	}
	got = run(t, &App{Git: forbiddenGit{}}, args...)
	report = m4Report(t, got.stdout)
	if got.code != 2 || report.Reason != "artifact_missing" {
		t.Fatal(got, report)
	}
}

func TestM4KeylessCLIHistoricalIdentityTrustAndTamperExits(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload, err := testsigning.Payload("app", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := testsigning.Generate(payload)
	if err != nil {
		t.Fatal(err)
	}
	input, trust := filepath.Join(t.TempDir(), "bundle.json"), filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(input, fixture.Bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trust, fixture.TrustRoot, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"verify", "--attestation", input, "--artifact", "app", "--root", root, "--trusted-root", trust, "--expect-identity", testsigning.Identity, "--expect-issuer", testsigning.Issuer, "--json"}
	for _, test := range []struct {
		name   string
		extra  []string
		reason string
		code   int
	}{
		{"valid", nil, "", 0}, {"wrong workflow ref", []string{"--expect-identity", testsigning.Identity + "@wrong"}, "identity_mismatch", 1},
		{"wrong issuer", []string{"--expect-issuer", testsigning.Issuer + "/"}, "identity_mismatch", 1},
		{"payload builder is not signer", []string{"--expect-identity", "https://github.com/Shellghostt/BuildTrace#local-recorder"}, "identity_mismatch", 1},
		{"missing root", []string{"--trusted-root", filepath.Join(t.TempDir(), "absent")}, "trust_invalid", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := run(t, &App{Git: forbiddenGit{}, LookupEnv: func(string) (string, bool) { panic("keyless verifier must not access OIDC environment") }}, append(append([]string(nil), args...), test.extra...)...)
			report := m4Report(t, got.stdout)
			if got.code != test.code || report.Reason != test.reason {
				t.Fatal(got, report)
			}
		})
	}
	if err := os.WriteFile(trust, []byte(`{"untrustedUrl":"https://attacker.invalid/"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := run(t, &App{Git: forbiddenGit{}}, args...)
	report := m4Report(t, got.stdout)
	if got.code != 2 || report.Reason != "trust_invalid" {
		t.Fatal(got, report)
	}
}

func TestM4UnsignedOptInAndManifestScopesRemainDistinct(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	statement := filepath.Join(t.TempDir(), "plain.jsonl")
	if got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "app", "--out", statement); got.code != 0 {
		t.Fatal(got)
	}
	got := run(t, &App{Git: forbiddenGit{}}, "verify", "--attestation", statement, "--artifact", "app", "--root", repo.Dir, "--allow-unsigned", "--json")
	report := m4Report(t, got.stdout)
	if got.code != 0 || report.Scope != "unsigned_statement" || report.Status != "matched" || report.Authenticated || len(report.Warnings) == 0 {
		t.Fatal(got, report)
	}
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	if got := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "app", "--out", manifest); got.code != 0 {
		t.Fatal(got)
	}
	got = run(t, &App{Git: forbiddenGit{}}, "verify", "--manifest", manifest, "--root", repo.Dir, "--json")
	var legacy verify.Report
	if json.Unmarshal([]byte(got.stdout), &legacy) != nil || got.code != 0 || legacy.Scope != "unsigned_manifest" || legacy.Status != "matched" {
		t.Fatal("legacy manifest contract changed", got)
	}
}

func TestM4SigningFailureCancellationAndOutputNeverPublishPartialOrPrivateMaterial(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	_, private, _ := m4Keys(t, "ed25519")
	before, err := os.ReadFile(private)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (string, bool) {
		if name == "BUILDTRACE_SIGNING_KEY" {
			return private, true
		}
		return "", false
	}
	got := run(t, &App{LookupEnv: lookup}, "record", "--repo", repo.Dir, "--artifact", "app", "--sign", "local", "--out", private)
	after, err := os.ReadFile(private)
	if err != nil || got.code != 2 || !bytes.Equal(before, after) || bytes.Contains([]byte(got.stdout+got.stderr), before) {
		t.Fatal("private key was replaced or disclosed", got, err)
	}
	payload, err := testsigning.Payload("app", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := testsigning.Generate(payload)
	if err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(trust, fixture.TrustRoot, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "signed.json")
	if err := os.WriteFile(out, []byte("previous-complete-output"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	app := &App{Context: ctx, KeylessSigner: func(context.Context, []byte, signing.KeylessOptions) ([]byte, error) {
		return []byte("partial"), errors.New("fixture-private-token")
	}}
	got = run(t, app, "record", "--repo", repo.Dir, "--artifact", "app", "--sign", "keyless", "--trusted-root", trust, "--out", out)
	if got.code != 3 || got.stdout != "" || strings.Contains(got.stderr, "fixture-private-token") {
		t.Fatal(got)
	}
	app = &App{Context: ctx, KeylessSigner: func(context.Context, []byte, signing.KeylessOptions) ([]byte, error) {
		cancel()
		return fixture.Bundle, nil
	}}
	got = run(t, app, "record", "--repo", repo.Dir, "--artifact", "app", "--sign", "keyless", "--trusted-root", trust, "--out", out)
	if got.code != 3 || got.stdout != "" {
		t.Fatal("cancelled signing published", got)
	}
	if data, err := os.ReadFile(out); err != nil || string(data) != "previous-complete-output" {
		t.Fatal("failed signing changed old output", err)
	}
	if err := writeSignedFile(ctx, out, []byte("replacement")); err == nil {
		t.Fatal("cancelled file writer published output")
	}
	dirTarget := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(dirTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeSignedFile(t.Context(), dirTarget, fixture.Bundle); err == nil {
		t.Fatal("directory output should fail")
	}
	entries, err := os.ReadDir(filepath.Dir(dirTarget))
	if err != nil || len(entries) != 1 {
		t.Fatal("failed file write left a temporary file", entries, err)
	}
}

func TestM4SignedReportOutputFailureIsToolError(t *testing.T) {
	f := verify.NewAttestationReport()
	f.Status = "verified"
	f.Authenticated = true
	var stderr bytes.Buffer
	app := &App{Stdout: brokenOutput{}, Stderr: &stderr}
	if code := app.signedVerificationReport(f, true, nil); code != 3 || !strings.Contains(stderr.String(), "output_failed") {
		t.Fatal("report write failure returned success", code, stderr.String())
	}
}

func TestM4LocalSignedStdoutFailureNeverReportsSuccess(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	_, private, _ := m4Keys(t, "ed25519")
	var stderr bytes.Buffer
	app := &App{Stdout: brokenOutput{}, Stderr: &stderr, LookupEnv: func(name string) (string, bool) {
		if name == "BUILDTRACE_SIGNING_KEY" {
			return private, true
		}
		return "", false
	}}
	code := app.Run([]string{"record", "--repo", repo.Dir, "--artifact", "app", "--sign", "local"})
	if code != 3 || !strings.Contains(stderr.String(), "output_failed") || strings.Contains(stderr.String(), "signed statement generated") {
		t.Fatal("failed stdout was reported as signed success", code, stderr.String())
	}
}
