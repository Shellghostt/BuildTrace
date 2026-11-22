package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	prototrust "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/shellghostt/buildtrace/internal/testsigning"
)

func keylessFixture(t *testing.T) (testsigning.Fixture, TrustedRoot) {
	t.Helper()
	payload, err := testsigning.Payload("artifact.txt", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := testsigning.Generate(payload)
	if err != nil {
		t.Fatal("generate synthetic signed material", err)
	}
	trusted, err := ParseTrustedRoot(fixture.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, trusted
}

func TestKeylessHistoricalOfflineAndIndependentSigstoreVerification(t *testing.T) {
	fixture, trusted := keylessFixture(t)
	decoded, err := DecodeKeylessBundle(fixture.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Leaf.NotAfter.Before(time.Now()) {
		t.Fatal("historical fixture leaf has not expired")
	}
	evidence, err := VerifyKeyless(decoded, trusted, testsigning.Identity, testsigning.Issuer)
	if err != nil {
		t.Fatal("historical certificate must validate at authenticated time", err)
	}
	if evidence.SigningTime == nil || !evidence.SigningTime.Equal(fixture.SigningTime) || evidence.Identity != testsigning.Identity || evidence.Issuer != testsigning.Issuer {
		t.Fatal("signer evidence is not authenticated fixture time/identity", evidence)
	}
	// Independent standard verifier checks both crypto and artifact digest.
	verifier, err := sigverify.NewVerifier(trusted.Material, sigverify.WithTransparencyLog(1), sigverify.WithIntegratedTimestamps(1), sigverify.WithSignedCertificateTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sigverify.NewShortCertificateIdentity(testsigning.Issuer, "", testsigning.Identity, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(decoded.Bundle, sigverify.NewPolicy(sigverify.WithArtifact(strings.NewReader("hello")), sigverify.WithCertificateIdentity(identity))); err != nil {
		t.Fatal("independent Sigstore artifact/signature check failed", err)
	}
}

func TestKeylessShardedGlobalIndexAndLocalProofRemainAuthenticated(t *testing.T) {
	payload, err := testsigning.Payload("artifact.txt", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := testsigning.GenerateWithOptions(payload, testsigning.Options{VirtualLogIndex: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := ParseTrustedRoot(fixture.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeKeylessBundle(fixture.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sigverify.NewVerifier(trusted.Material, sigverify.WithTransparencyLog(1), sigverify.WithIntegratedTimestamps(1), sigverify.WithSignedCertificateTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sigverify.NewShortCertificateIdentity(testsigning.Issuer, "", testsigning.Identity, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(decoded.Bundle, sigverify.NewPolicy(sigverify.WithArtifact(strings.NewReader("hello")), sigverify.WithCertificateIdentity(identity))); err != nil {
		t.Fatal("independent verifier rejected authentic sharded evidence", err)
	}
	evidence, err := VerifyKeyless(decoded, trusted, testsigning.Identity, testsigning.Issuer)
	if err != nil || evidence.SigningTime == nil || !evidence.SigningTime.Equal(fixture.SigningTime) {
		t.Fatal("global SET index and shard-local proof must verify at authenticated time", err)
	}
	var altered protobundle.Bundle
	if err := protojson.Unmarshal(fixture.Bundle, &altered); err != nil {
		t.Fatal(err)
	}
	altered.VerificationMaterial.TlogEntries[0].LogIndex++
	encoded, err := protojson.Marshal(&altered)
	if err != nil {
		t.Fatal(err)
	}
	modified, err := DecodeKeylessBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyKeyless(modified, trusted, testsigning.Identity, testsigning.Issuer)
	errorReason(t, err, "transparency_invalid", 1)
}

func TestKeylessTamperTrustTimeIdentityAndProofMatrix(t *testing.T) {
	fixture, trusted := keylessFixture(t)
	for _, test := range []struct {
		name   string
		change func(*protobundle.Bundle)
		reason string
		code   int
	}{
		{"payload", func(b *protobundle.Bundle) { b.GetDsseEnvelope().Payload[0] ^= 1 }, "signature_invalid", 1},
		{"signature", func(b *protobundle.Bundle) { s := b.GetDsseEnvelope().Signatures[0].Sig; s[len(s)-1] ^= 1 }, "signature_invalid", 1},
		{"forged integrated time", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].IntegratedTime++ }, "transparency_invalid", 1},
		{"forged SET", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionPromise.SignedEntryTimestamp[0] ^= 1
		}, "transparency_invalid", 1},
		{"forged root hash", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionProof.RootHash[0] ^= 1 }, "transparency_invalid", 1},
		{"missing SET", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionPromise = nil }, "signing_time_missing", 1},
		{"missing proof", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionProof = nil }, "signing_time_missing", 1},
		{"missing checkpoint", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].InclusionProof.Checkpoint = nil }, "signing_time_missing", 1},
		{"missing log", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries = nil }, "signing_time_missing", 1},
		{"proof bound", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].InclusionProof.Hashes = make([][]byte, 65)
		}, "invalid_input", 2},
		{"certificate bound", func(b *protobundle.Bundle) {
			b.VerificationMaterial.GetCertificate().RawBytes = make([]byte, MaxCertificateBytes+1)
		}, "invalid_input", 2},
		{"bad certificate", func(b *protobundle.Bundle) {
			b.VerificationMaterial.GetCertificate().RawBytes = []byte("fixture-private-token")
		}, "certificate_invalid", 1},
		{"log body bound", func(b *protobundle.Bundle) {
			b.VerificationMaterial.TlogEntries[0].CanonicalizedBody = make([]byte, MaxLogBodyBytes+1)
		}, "invalid_input", 2},
		{"unsupported version", func(b *protobundle.Bundle) { b.MediaType = "application/vnd.dev.sigstore.bundle.v0.4+json" }, "invalid_input", 2},
		{"unsupported log format", func(b *protobundle.Bundle) { b.VerificationMaterial.TlogEntries[0].KindVersion.Version = "0.0.2" }, "invalid_input", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var b protobundle.Bundle
			if err := protojson.Unmarshal(fixture.Bundle, &b); err != nil {
				t.Fatal(err)
			}
			test.change(&b)
			encoded, err := protojson.Marshal(&b)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeKeylessBundle(encoded)
			if err == nil {
				_, err = VerifyKeyless(decoded, trusted, testsigning.Identity, testsigning.Issuer)
			}
			errorReason(t, err, test.reason, test.code)
			if strings.Contains(err.Error(), "fixture-private-token") {
				t.Fatal("security input appeared in error")
			}
		})
	}
	decoded, err := DecodeKeylessBundle(fixture.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range [][2]string{{testsigning.Identity + "/suffix", testsigning.Issuer}, {strings.ToUpper(testsigning.Identity), testsigning.Issuer}, {testsigning.Identity, testsigning.Issuer + "/"}} {
		_, err := VerifyKeyless(decoded, trusted, policy[0], policy[1])
		errorReason(t, err, "identity_mismatch", 1)
	}
	var other prototrust.TrustedRoot
	if err := protojson.Unmarshal(fixture.TrustRoot, &other); err != nil {
		t.Fatal(err)
	}
	// Keep trusted log/CT keys, replace only the root certificate with a valid
	// unrelated root: the log cannot make that certificate chain trusted.
	second, _ := keylessFixture(t)
	var otherRoot prototrust.TrustedRoot
	if err := protojson.Unmarshal(second.TrustRoot, &otherRoot); err != nil {
		t.Fatal(err)
	}
	other.CertificateAuthorities = otherRoot.CertificateAuthorities
	wrong, err := protojson.Marshal(&other)
	if err != nil {
		t.Fatal(err)
	}
	wrongTrust, err := ParseTrustedRoot(wrong)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyKeyless(decoded, wrongTrust, testsigning.Identity, testsigning.Issuer)
	errorReason(t, err, "certificate_invalid", 1)
}

func TestMissingSCTIssuerAndOutOfLeafTimeFailWithAuthenticLogBinding(t *testing.T) {
	payload, err := testsigning.Payload("artifact.txt", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []testsigning.Options{{OmitSCT: true}, {OmitIssuer: true}, {SigningTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		fixture, err := testsigning.GenerateWithOptions(payload, options)
		if err != nil {
			t.Fatal(err)
		}
		trusted, err := ParseTrustedRoot(fixture.TrustRoot)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeKeylessBundle(fixture.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyKeyless(decoded, trusted, testsigning.Identity, testsigning.Issuer)
		errorReason(t, err, "certificate_invalid", 1)
	}
}

func TestBundleAndRootRejectDuplicateUnknownAliasesAndUnsupportedAlternatives(t *testing.T) {
	fixture, _ := keylessFixture(t)
	for _, input := range [][]byte{
		bytes.Replace(fixture.Bundle, []byte(`"mediaType":`), []byte(`"mediaType":"ignored","mediaType":`), 1),
		bytes.Replace(fixture.Bundle, []byte(`"dsseEnvelope":`), []byte(`"dsse_envelope":`), 1),
		append([]byte(`{"untrustedUrl":"https://attacker.invalid/",`), fixture.Bundle[1:]...),
	} {
		_, err := DecodeKeylessBundle(input)
		errorReason(t, err, "invalid_input", 2)
	}
	for _, input := range [][]byte{nil, bytes.Repeat([]byte{' '}, MaxTrustBytes+1),
		bytes.Replace(fixture.TrustRoot, []byte(`"mediaType":`), []byte(`"mediaType":"ignored","mediaType":`), 1)} {
		_, err := ParseTrustedRoot(input)
		errorReason(t, err, "trust_invalid", 2)
	}
}

func TestOIDCAndCancelledTransportExcludeSecretsAndBoundResponses(t *testing.T) {
	const secret = "fixture-private-token"
	lookup := func(name string) (string, bool) {
		switch name {
		case "GITHUB_ACTIONS":
			return "true", true
		case "ACTIONS_ID_TOKEN_REQUEST_URL":
			return "https://attacker.invalid/?token=" + secret, true
		case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
			return secret, true
		}
		return "", false
	}
	_, err := oidcToken(t.Context(), lookup)
	errorReason(t, err, "invalid_input", 2)
	if strings.Contains(err.Error(), secret) {
		t.Fatal("OIDC secret entered diagnostic")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	transport := boundedTransport(ctx, "fulcio.sigstore.dev")
	defer transport.inner.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodPost, FulcioURL+"/api/v2/signingCert", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("cancelled transport made a request")
	}
	body := &boundedResponseBody{inner: io.NopCloser(strings.NewReader(strings.Repeat("x", MaxNetworkBytes+1))), remaining: MaxNetworkBytes, cancel: func() {}, stop: func() bool { return true }}
	if data, err := io.ReadAll(body); err == nil || len(data) > MaxNetworkBytes+1 {
		t.Fatal("network response was not bounded", len(data), err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("e30.e30.Zg"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture, trusted := keylessFixture(t)
	_, err = SignKeyless(ctx, fixture.Payload, KeylessOptions{TrustedRoot: trusted, LookupEnv: func(name string) (string, bool) {
		if name == "BUILDTRACE_OIDC_TOKEN_FILE" {
			return tokenFile, true
		}
		return "", false
	}})
	errorReason(t, err, "signing_failed", 3)
}

func TestTrustRootLogKeyAndCertificateBounds(t *testing.T) {
	fixture, _ := keylessFixture(t)
	var pb prototrust.TrustedRoot
	if err := protojson.Unmarshal(fixture.TrustRoot, &pb); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	pb.Tlogs[0].PublicKey.RawBytes = der
	// A root identifier must actually identify its configured public key.
	data, err := protojson.Marshal(&pb)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseTrustedRoot(data)
	if err == nil {
		t.Fatal("root accepted a mismatched log key ID")
	}
	var unknown map[string]any
	if err := json.Unmarshal(fixture.Bundle, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["verificationMaterial"].(map[string]any)["publicKey"] = map[string]string{"hint": "attacker"}
	data, err = json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeKeylessBundle(data)
	errorReason(t, err, "invalid_input", 2)
	// Confirm the independent loader can consume the unchanged fixture format.
	var independent sigbundle.Bundle
	if err := independent.UnmarshalJSON(fixture.Bundle); err != nil {
		t.Fatal(err)
	}
}
