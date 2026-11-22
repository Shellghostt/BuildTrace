package verify

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/internal/signing"
	"github.com/shellghostt/buildtrace/internal/testsigning"
)

type signedCase struct {
	root      string
	payload   []byte
	key       crypto.Signer
	policy    AttestationPolicy
	selection []Selection
}

func signedFixture(t *testing.T) signedCase {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dist", "app"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload, err := testsigning.Payload("dist/app", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return signedCase{root: root, payload: payload, key: key, policy: AttestationPolicy{PublicKey: pub}, selection: []Selection{{Subject: "dist/app", Path: "dist/app"}}}
}

func signCase(t *testing.T, f signedCase, payload []byte) []byte {
	t.Helper()
	data, err := signing.SignLocal(payload, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func expectFailure(t *testing.T, report AttestationReport, err error, reason string, code int) {
	t.Helper()
	var got *signing.Error
	if !errors.As(err, &got) || got.Reason != reason || got.Code != code || report.Status != "failed" || report.Reason != reason {
		t.Fatalf("report=%+v error=%v, expected %s/%d", report, err, reason, code)
	}
}

func changePayload(t *testing.T, payload []byte, change func(map[string]any)) []byte {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		t.Fatal(err)
	}
	change(obj)
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func definition(obj map[string]any) map[string]any {
	return obj["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
}

func TestSignedVerificationChecksScopeSelectedBytesAndRelocation(t *testing.T) {
	f := signedFixture(t)
	encoded := signCase(t, f, f.payload)
	report, err := CheckAttestation(encoded, f.root, f.selection, f.policy)
	if err != nil || report.Status != "verified" || !report.Authenticated || report.Verified != 1 || report.Signer == nil || report.Signer.Mode != "local" || len(report.Checked) != 1 || !report.Checked[0].KindAndSizeMatched {
		t.Fatal(report, err)
	}
	if err := os.Rename(filepath.Join(f.root, "dist", "app"), filepath.Join(f.root, "relocated")); err != nil {
		t.Fatal(err)
	}
	selection := []Selection{{Subject: "dist/app", Path: "relocated"}}
	report, err = CheckAttestation(encoded, f.root, selection, f.policy)
	if err != nil || report.Checked[0].Subject != "dist/app" || report.Checked[0].Path != "relocated" {
		t.Fatal("explicit mapping failed", report, err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "relocated"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err = CheckAttestation(encoded, f.root, selection, f.policy)
	expectFailure(t, report, err, "digest_mismatch", 1)
	if !report.Authenticated || report.Checked[0].DigestMatched {
		t.Fatal("artifact failure incorrectly erased signer evidence or matched digest", report)
	}
}

func TestSignedRecorderContractAndStableFailureReasons(t *testing.T) {
	f := signedFixture(t)
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		reason string
		code   int
	}{
		{"unknown build type", func(o map[string]any) { definition(o)["buildType"] = "https://unknown.fixture.invalid/v1" }, "unsupported_build_type", 2},
		{"kind", func(o map[string]any) {
			definition(o)["internalParameters"].(map[string]any)["observedArtifacts"].([]any)[0].(map[string]any)["kind"] = "directory"
		}, "kind_mismatch", 1},
		{"size", func(o map[string]any) {
			definition(o)["internalParameters"].(map[string]any)["observedArtifacts"].([]any)[0].(map[string]any)["size"] = 6
		}, "size_mismatch", 1},
		{"duplicate subject", func(o map[string]any) { subjects := o["subject"].([]any); o["subject"] = append(subjects, subjects[0]) }, "invalid_input", 2},
		{"unsafe subject", func(o map[string]any) { o["subject"].([]any)[0].(map[string]any)["name"] = "../private" }, "invalid_input", 2},
		{"unsafe embedded path", func(o map[string]any) {
			definition(o)["externalParameters"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)["path"] = "../private"
		}, "invalid_input", 2},
		{"size alias", func(o map[string]any) {
			a := definition(o)["internalParameters"].(map[string]any)["observedArtifacts"].([]any)[0].(map[string]any)
			a["Size"] = a["size"]
			delete(a, "size")
		}, "invalid_input", 2},
		{"missing dirty", func(o map[string]any) {
			delete(definition(o)["internalParameters"].(map[string]any)["observedCheckout"].(map[string]any), "dirty")
		}, "invalid_input", 2},
		{"bad source commit", func(o map[string]any) {
			definition(o)["internalParameters"].(map[string]any)["observedCheckout"].(map[string]any)["commit"] = "abc"
		}, "invalid_input", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := changePayload(t, f.payload, test.change)
			report, err := CheckAttestation(signCase(t, f, payload), f.root, f.selection, f.policy)
			expectFailure(t, report, err, test.reason, test.code)
		})
	}
	missing := []Selection{{Subject: "dist/missing", Path: "dist/app"}}
	report, err := CheckAttestation(signCase(t, f, f.payload), f.root, missing, f.policy)
	expectFailure(t, report, err, "subject_missing", 1)
	if err := os.Remove(filepath.Join(f.root, "dist", "app")); err != nil {
		t.Fatal(err)
	}
	report, err = CheckAttestation(signCase(t, f, f.payload), f.root, f.selection, f.policy)
	expectFailure(t, report, err, "artifact_missing", 2)
}

func TestSelectedSubjectsDoNotOpenUnselectedArtifactPaths(t *testing.T) {
	f := signedFixture(t)
	payload := changePayload(t, f.payload, func(o map[string]any) {
		original := o["subject"].([]any)[0].(map[string]any)
		o["subject"] = append(o["subject"].([]any), map[string]any{"name": "unselected/private", "digest": original["digest"]})
		def := definition(o)
		ext := def["externalParameters"].(map[string]any)
		ext["artifacts"] = append(ext["artifacts"].([]any), map[string]any{"name": "unselected/private", "path": "unselected/private"})
		internal := def["internalParameters"].(map[string]any)
		internal["observedArtifacts"] = append(internal["observedArtifacts"].([]any), map[string]any{"name": "unselected/private", "kind": "file", "size": 5})
	})
	report, err := CheckAttestation(signCase(t, f, payload), f.root, f.selection, f.policy)
	if err != nil || report.Verified != 1 || len(report.Unselected) != 1 || report.Unselected[0] != "unselected/private" {
		t.Fatal("unselected subject was opened or omitted", report, err)
	}
}

func TestUnsignedOptInCannotSatisfySignerPolicy(t *testing.T) {
	f := signedFixture(t)
	report, err := CheckAttestation(f.payload, f.root, f.selection, f.policy)
	expectFailure(t, report, err, "missing_signature", 1)
	policy := AttestationPolicy{AllowUnsigned: true}
	report, err = CheckAttestation(f.payload, f.root, f.selection, policy)
	if err != nil || report.Authenticated || report.Signer != nil || report.Scope != "unsigned_statement" || report.Status != "matched" || len(report.Warnings) == 0 {
		t.Fatal("unsigned scope was upgraded", report, err)
	}
	policy.PublicKey = f.policy.PublicKey
	report, err = CheckAttestation(f.payload, f.root, f.selection, policy)
	expectFailure(t, report, err, "invalid_input", 2)
	policy = AttestationPolicy{AllowUnsigned: true}
	report, err = CheckAttestation(signCase(t, f, f.payload), f.root, f.selection, policy)
	expectFailure(t, report, err, "invalid_input", 2)
}

func TestExactRecorderLabelAndDeclaredDependencyPolicy(t *testing.T) {
	f := signedFixture(t)
	policy := f.policy
	policy.Builder = attestation.DefaultBuilderID + "-wrong"
	report, err := CheckAttestation(signCase(t, f, f.payload), f.root, f.selection, policy)
	expectFailure(t, report, err, "builder_mismatch", 1)
	payload := changePayload(t, f.payload, func(o map[string]any) {
		def := definition(o)
		uri := "git+https://source.fixture.invalid/declared"
		commit := strings.Repeat("b", 40)
		def["externalParameters"].(map[string]any)["assertedSource"] = map[string]any{"uri": uri, "commit": commit, "evidence": "caller_assertion"}
		def["resolvedDependencies"] = []any{map[string]any{"uri": uri, "digest": map[string]any{"gitCommit": commit}, "annotations": map[string]any{"buildtrace.evidence": "caller_assertion"}}}
	})
	policy = f.policy
	policy.SourceURI = "git+https://source.fixture.invalid/declared"
	policy.SourceCommit = strings.Repeat("b", 40)
	report, err = CheckAttestation(signCase(t, f, payload), f.root, f.selection, policy)
	if err != nil || report.Status != "verified" {
		t.Fatal(report, err)
	}
	policy.SourceCommit = strings.Repeat("c", 40)
	report, err = CheckAttestation(signCase(t, f, payload), f.root, f.selection, policy)
	expectFailure(t, report, err, "dependency_mismatch", 1)
}

func TestArtifactMappingRejectsTraversalAbsoluteAndDuplicatePaths(t *testing.T) {
	f := signedFixture(t)
	for _, selection := range [][]Selection{
		{{Subject: "dist/app", Path: "../outside"}}, {{Subject: "dist/app", Path: filepath.Join(f.root, "dist", "app")}},
		{{Subject: "C:/private", Path: "dist/app"}}, {{Subject: "dist/app", Path: "dist/app"}, {Subject: "dist/app", Path: "dist/app"}},
	} {
		report, err := CheckAttestation(signCase(t, f, f.payload), f.root, selection, f.policy)
		expectFailure(t, report, err, "invalid_input", 2)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.root, "escape")); err != nil {
		t.Skip("platform does not permit symlink creation:", err)
	}
	report, err := CheckAttestation(signCase(t, f, f.payload), f.root, []Selection{{Subject: "dist/app", Path: "escape/private"}}, f.policy)
	expectFailure(t, report, err, "artifact_unreadable", 3)
}

func TestKeylessFullReportUsesExternalIdentityAndHistoricalTime(t *testing.T) {
	f := signedFixture(t)
	fixture, err := testsigning.Generate(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(trust, fixture.TrustRoot, 0o644); err != nil {
		t.Fatal(err)
	}
	policy := AttestationPolicy{TrustedRoot: trust, Identity: testsigning.Identity, Issuer: testsigning.Issuer}
	report, err := CheckAttestation(fixture.Bundle, f.root, f.selection, policy)
	if err != nil || !report.Authenticated || report.Status != "verified" || report.Signer == nil || report.Signer.SigningTime == nil || !report.Signer.SigningTime.Equal(fixture.SigningTime) {
		t.Fatal(report, err)
	}
	policy.Identity = attestation.DefaultBuilderID
	report, err = CheckAttestation(fixture.Bundle, f.root, f.selection, policy)
	expectFailure(t, report, err, "identity_mismatch", 1)
}
