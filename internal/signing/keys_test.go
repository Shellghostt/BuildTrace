package signing

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateAndPinnedPublicPEMFormats(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "p256"} {
		key := testKey(t, algorithm)
		privateDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		private := filepath.Join(dir, "private.pem")
		pub := filepath.Join(dir, "public.pem")
		if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		public, err := LoadPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		data, err := SignLocal([]byte("{}\n"), loaded)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEnvelope(data)
		if err != nil || VerifyPAE(decoded, public) != nil {
			t.Fatal("externally pinned round trip failed", err)
		}
		if algorithm == "p256" {
			sec1, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPrivateKey(private); err != nil {
				t.Fatal("SEC1 rejected", err)
			}
		}
	}
}

func TestKeysRejectUnsupportedAlgorithmsMaterialAndPrivateFileModes(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	for _, key := range []any{p384, rsaKey} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = LoadPrivateKey(path)
		errorReason(t, err, "unsupported_key", 2)
	}
	key := testKey(t, "ed25519")
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	valid := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for name, data := range map[string][]byte{
		"garbage":                 []byte("fixture-private-token"),
		"malformed DER":           pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fixture-private-token")}),
		"two blocks":              append(append([]byte(nil), valid...), valid...),
		"trailing":                append(append([]byte(nil), valid...), []byte("fixture-private-token")...),
		"oversized":               bytes.Repeat([]byte{'x'}, MaxKeyBytes+1),
		"headers":                 pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}),
		"malformed leading block": append([]byte("-----BEGIN PRIVATE KEY-----\nmalformed\n"), valid...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadPrivateKey(path)
			errorReason(t, err, "invalid_input", 2)
			if bytes.Contains([]byte(err.Error()), []byte("fixture-private-token")) {
				t.Fatal("secret entered key diagnostic")
			}
		})
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPrivateKey(path)
		errorReason(t, err, "invalid_input", 2)
	}
	link := filepath.Join(t.TempDir(), "key.pem")
	if err := os.Symlink(path, link); err == nil {
		_, err = LoadPrivateKey(link)
		errorReason(t, err, "invalid_input", 2)
	}
}

func TestPinnedPublicKeysRejectPrivateMalformedAndUnsupportedInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted.pem")
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = LoadPublicKey(path)
		errorReason(t, err, "unsupported_key", 2)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPublicKey(path)
	errorReason(t, err, "unsupported_key", 2)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("fixture-private-token")}), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPublicKey(path)
	errorReason(t, err, "invalid_input", 2)
	if bytes.Contains([]byte(err.Error()), []byte("fixture-private-token")) {
		t.Fatal("malformed key diagnostic echoed security material")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(testKey(t, "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPublicKey(path)
	errorReason(t, err, "unsupported_key", 2)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadPrivateKey(path)
	errorReason(t, err, "unsupported_key", 2)
}
