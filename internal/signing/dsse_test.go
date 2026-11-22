package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	independent "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/shellghostt/buildtrace/internal/attestation"
)

func errorReason(t *testing.T, err error, reason string, code int) {
	t.Helper()
	var got *Error
	if !errors.As(err, &got) || got.Reason != reason || got.Code != code {
		t.Fatalf("got %v, want %s/%d", err, reason, code)
	}
}

func TestPAEIndependentVectors(t *testing.T) {
	for _, vector := range []struct {
		typ     string
		payload []byte
		want    string
	}{
		{"", nil, "DSSEv1 0  0 "},
		{"text/plain", []byte("hello"), "DSSEv1 10 text/plain 5 hello"},
		{"té", []byte("\x00é\n"), "DSSEv1 3 té 4 \x00é\n"},
		{PayloadType, []byte("{}\n"), "DSSEv1 28 application/vnd.in-toto+json 3 {}\n"},
	} {
		got := PAE(vector.typ, vector.payload)
		if string(got) != vector.want || !bytes.Equal(got, independent.PAE(vector.typ, vector.payload)) {
			t.Fatalf("PAE differs for %q: %q", vector.typ, got)
		}
	}
}

func testKey(t *testing.T, algorithm string) crypto.Signer {
	t.Helper()
	if algorithm == "ed25519" {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestLocalAlgorithmsAuthenticateExactPayloadAndIndependentVerifier(t *testing.T) {
	payload, err := os.ReadFile("../../tests/fixtures/m3/observed.intoto.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []string{"ed25519", "p256"} {
		t.Run(algorithm, func(t *testing.T) {
			key := testKey(t, algorithm)
			data, err := SignLocal(payload, key)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeEnvelope(data)
			if err != nil || !bytes.Equal(decoded.Payload, payload) {
				t.Fatal("exact LF-terminated payload changed", err)
			}
			if err := VerifyPAE(decoded, key.Public()); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPAE(decoded, testKey(t, algorithm).Public()); err == nil {
				t.Fatal("wrong public key was trusted")
			} else {
				errorReason(t, err, "signature_invalid", 1)
			}
			// Independently check PAE against standard crypto, without BuildTrace's
			// PAE/signature helper deciding what bytes to authenticate.
			var env independent.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				t.Fatal(err)
			}
			verifier, err := independent.NewEnvelopeVerifier(independentKey{key: key.Public()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(t.Context(), &env); err != nil {
				t.Fatal("independent DSSE check failed", err)
			}
			var reordered map[string]any
			if err := json.Unmarshal(data, &reordered); err != nil {
				t.Fatal(err)
			}
			reformatted, _ := json.MarshalIndent(reordered, "", "  ")
			again, err := DecodeEnvelope(reformatted)
			if err != nil || VerifyPAE(again, key.Public()) != nil {
				t.Fatal("unsigned wrapper formatting broke signature", err)
			}
			decoded.Payload = append([]byte(nil), decoded.Payload...)
			decoded.Payload[len(decoded.Payload)-1] = ' '
			errorReason(t, VerifyPAE(decoded, key.Public()), "signature_invalid", 1)
		})
	}
}

type independentKey struct{ key crypto.PublicKey }

func (k independentKey) KeyID() (string, error)   { return PublicKeyID(k.key) }
func (k independentKey) Public() crypto.PublicKey { return k.key }
func (k independentKey) Verify(_ context.Context, data, signature []byte) error {
	switch key := k.key.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(key, data, signature) {
			return nil
		}
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(data)
		if ecdsa.VerifyASN1(key, hash[:], signature) {
			return nil
		}
	}
	return errors.New("independent crypto rejected signature")
}

func TestEnvelopeSecurityFieldsAndSignatureSelection(t *testing.T) {
	base := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte("{}\n")), Signatures: []Signature{{Sig: base64.StdEncoding.EncodeToString(make([]byte, 64))}}}
	valid, _ := json.Marshal(base)
	for name, data := range map[string][]byte{
		"duplicate":         bytes.Replace(valid, []byte(`"payloadType":`), []byte(`"payloadType":"ignored","payloadType":`), 1),
		"escaped duplicate": bytes.Replace(valid, []byte(`"payloadType":`), []byte(`"payloadType":"ignored","payload\u0054ype":`), 1),
		"case alias":        bytes.Replace(valid, []byte(`"payloadType":`), []byte(`"PayloadType":`), 1),
		"unknown":           append([]byte(`{"extra":1,`), valid[1:]...),
		"unsupported type":  bytes.ReplaceAll(valid, []byte(PayloadType), []byte("text/plain")),
		"base64 newline":    bytes.Replace(valid, []byte(base.Payload), []byte("e30K\\n"), 1),
		"base64 no padding": bytes.Replace(valid, []byte(base.Signatures[0].Sig), []byte(strings.TrimRight(base.Signatures[0].Sig, "=")), 1),
		"trailing document": append(append([]byte(nil), valid...), []byte("{}")...),
		"null":              []byte(`{"payloadType":null,"payload":"e30K","signatures":[]}`),
		"empty signature":   bytes.Replace(valid, []byte(base.Signatures[0].Sig), []byte(""), 1),
	} {
		t.Run(name, func(t *testing.T) { _, err := DecodeEnvelope(data); errorReason(t, err, "invalid_input", 2) })
	}
	for _, count := range []int{0, 2, 16, 17} {
		copy := base
		copy.Signatures = make([]Signature, count)
		for i := range copy.Signatures {
			copy.Signatures[i] = base.Signatures[0]
		}
		data, _ := json.Marshal(copy)
		_, err := DecodeEnvelope(data)
		reason, code := "ambiguous_signatures", 2
		if count == 0 {
			reason, code = "missing_signature", 1
		}
		if count == 17 {
			reason = "invalid_input"
		}
		errorReason(t, err, reason, code)
	}
}

func TestEnvelopeDecodedAndOuterBounds(t *testing.T) {
	for _, size := range []int{attestation.MaxInputBytes, attestation.MaxInputBytes + 1} {
		env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, size)), Signatures: []Signature{{Sig: base64.StdEncoding.EncodeToString(make([]byte, 64))}}}
		data, _ := json.Marshal(env)
		_, err := DecodeEnvelope(data)
		if size == attestation.MaxInputBytes && err != nil {
			t.Fatal("inclusive decoded byte bound rejected", err)
		}
		if size > attestation.MaxInputBytes {
			errorReason(t, err, "invalid_input", 2)
		}
	}
	_, err := DecodeEnvelope(bytes.Repeat([]byte{' '}, MaxOuterBytes+1))
	errorReason(t, err, "invalid_input", 2)
	for _, depth := range []int{MaxJSONDepth, MaxJSONDepth + 1} {
		data := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		err := checkJSON(data, MaxOuterBytes)
		if depth == MaxJSONDepth && err != nil {
			t.Fatal(err)
		}
		if depth > MaxJSONDepth {
			errorReason(t, err, "invalid_input", 2)
		}
	}
	for _, values := range []int{MaxJSONTokens - 2, MaxJSONTokens - 1} {
		data := []byte("[" + strings.Repeat("0,", values-1) + "0]")
		err := checkJSON(data, MaxOuterBytes)
		if values == MaxJSONTokens-2 && err != nil {
			t.Fatal(err)
		}
		if values == MaxJSONTokens-1 {
			errorReason(t, err, "invalid_input", 2)
		}
	}
}
