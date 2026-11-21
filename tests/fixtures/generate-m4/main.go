// Command generate-m4 writes only public synthetic interoperability fixtures.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shellghostt/buildtrace/internal/signing"
	"github.com/shellghostt/buildtrace/internal/testsigning"
)

func main() {
	out := flag.String("out", "tests/fixtures/m4", "public synthetic fixture directory")
	flag.Parse()
	if err := generate(*out); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(out string) error {
	payload, err := testsigning.Payload("artifact.txt", []byte("hello"))
	if err != nil {
		return err
	}
	fixture, err := testsigning.Generate(payload)
	if err != nil {
		return err
	}
	root, err := signing.ParseTrustedRoot(fixture.TrustRoot)
	if err != nil {
		return err
	}
	bundle, err := signing.DecodeKeylessBundle(fixture.Bundle)
	if err != nil {
		return err
	}
	if _, err := signing.VerifyKeyless(bundle, root, testsigning.Identity, testsigning.Issuer); err != nil {
		return err
	}
	files := map[string][]byte{"artifact.txt": []byte("hello"), "statement.intoto.jsonl": payload, "historical.sigstore.json": fixture.Bundle, "trusted-root.json": fixture.TrustRoot}
	for _, algorithm := range []string{"ed25519", "p256"} {
		var key crypto.Signer
		if algorithm == "ed25519" {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			key = private
		} else {
			private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			key = private
		}
		data, err := signing.SignLocal(payload, key)
		if err != nil {
			return err
		}
		public, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return err
		}
		files["local-"+algorithm+".dsse.json"] = data
		files[algorithm+".pub.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	pins := map[string]string{}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		pins[name] = hex.EncodeToString(sum[:])
	}
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "SHA256SUMS.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "Generated %d public synthetic fixtures; private keys were not written.\n", len(files))
	return err
}
