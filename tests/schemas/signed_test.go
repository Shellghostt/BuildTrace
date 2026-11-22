package schemas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func fixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "m4", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestM4CommittedFixtureChecksums(t *testing.T) {
	var pins map[string]string
	if err := json.Unmarshal(fixtureFile(t, "SHA256SUMS.json"), &pins); err != nil || len(pins) != 8 {
		t.Fatal("expected eight pinned public fixtures", err)
	}
	for name, want := range pins {
		if filepath.Base(name) != name {
			t.Fatal("unsafe fixture path")
		}
		sum := sha256.Sum256(fixtureFile(t, name))
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("fixture checksum changed:", name)
		}
	}
}

type externalKey struct{ key crypto.PublicKey }

func (k externalKey) KeyID() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k.key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func (k externalKey) Public() crypto.PublicKey { return k.key }
func (k externalKey) Verify(_ context.Context, data, sig []byte) error {
	switch key := k.key.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(key, data, sig) {
			return nil
		}
	case *ecdsa.PublicKey:
		h := sha256.Sum256(data)
		if ecdsa.VerifyASN1(key, h[:], sig) {
			return nil
		}
	}
	return errors.New("independent cryptographic signature check failed")
}

func TestM4IndependentDSSESignaturesAndUnsignedPayloadSchema(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "p256"} {
		t.Run(algorithm, func(t *testing.T) {
			var env dsse.Envelope
			if err := json.Unmarshal(fixtureFile(t, "local-"+algorithm+".dsse.json"), &env); err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(fixtureFile(t, algorithm+".pub.pem"))
			if block == nil {
				t.Fatal("missing external public key")
			}
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := dsse.NewEnvelopeVerifier(externalKey{key: key})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(t.Context(), &env); err != nil {
				t.Fatal(err)
			}
			payload, err := env.DecodeB64Payload()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, fixtureFile(t, "statement.intoto.jsonl")) {
				t.Fatal("signature wraps different payload bytes")
			}
			if err := validate(payload); err != nil {
				t.Fatal("upstream statement/SLSA schema failed", err)
			}
			env.Payload += "tampered"
			if _, err := verifier.Verify(t.Context(), &env); err == nil {
				t.Fatal("independent verifier accepted tampered payload")
			}
		})
	}
}

func TestM4IndependentHistoricalSigstoreArtifactTimeAndIdentity(t *testing.T) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(fixtureFile(t, "historical.sigstore.json")); err != nil {
		t.Fatal(err)
	}
	material, err := root.NewTrustedRootFromJSON(fixtureFile(t, "trusted-root.json"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := verify.NewVerifier(material, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1), verify.WithSignedCertificateTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verify.NewShortCertificateIdentity("https://issuer.fixture.invalid", "", "https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(fixtureFile(t, "artifact.txt"))), verify.WithCertificateIdentity(identity)))
	if err != nil {
		t.Fatal(err)
	}
	content, err := b.VerificationContent()
	if err != nil || content.Certificate() == nil || !content.Certificate().NotAfter.Before(time.Now()) {
		t.Fatal("historical fixture is not expired", err)
	}
	if len(result.VerifiedTimestamps) != 1 || !result.VerifiedTimestamps[0].Timestamp.Equal(time.Date(2025, 1, 1, 0, 5, 0, 0, time.UTC)) {
		t.Fatal("time was not authenticated by standard verifier")
	}
	if _, err := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifact(strings.NewReader("tampered")), verify.WithCertificateIdentity(identity))); err == nil {
		t.Fatal("independent verifier accepted wrong artifact")
	}
	wrong, err := verify.NewShortCertificateIdentity("https://issuer.fixture.invalid", "", "https://fixture.invalid/wrong-workflow", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(&b, verify.NewPolicy(verify.WithArtifact(strings.NewReader("hello")), verify.WithCertificateIdentity(wrong))); err == nil {
		t.Fatal("independent verifier accepted wrong identity")
	}
}
