package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"runtime"
)

const MaxKeyBytes = 16 << 10
const MaxTrustBytes = 1 << 20

// ReadSecurityFile never opens devices/pipes or follows a terminal symlink.
// It bounds reads and detects an opened-file replacement before interpretation.
func ReadSecurityFile(path string, maximum int, private bool, reason string) ([]byte, error) {
	if !public(path, 4096) {
		return nil, invalid("a bounded security file path is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, invalid("required security input file does not exist")
		}
		return nil, failure(reason, 3, "security input file cannot be read")
	}
	if !before.Mode().IsRegular() || before.Size() > int64(maximum) || !os.SameFile(before, before) {
		return nil, invalid("security input must be a bounded regular file, without a terminal symlink")
	}
	if private && runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, invalid("private input permissions must restrict access to its owner")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, failure(reason, 3, "security input file cannot be opened")
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, failure(reason, 3, "security input changed during opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if err != nil {
		return nil, failure(reason, 3, "security input could not be read completely")
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		clear(data)
		return nil, failure(reason, 3, "security input changed during reading")
	}
	if len(data) == 0 || len(data) > maximum {
		clear(data)
		return nil, invalid("empty or oversized security input")
	}
	return data, nil
}

func onePEM(data []byte) (*pem.Block, error) {
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, invalid("expected one unencrypted PEM block")
	}
	block, remaining := pem.Decode(trimmed)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(remaining)) != 0 ||
		bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
		return nil, invalid("expected one PEM block without headers or trailing material")
	}
	return block, nil
}

func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := ReadSecurityFile(path, MaxKeyBytes, true, "key_unreadable")
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, err := onePEM(data)
	if err != nil {
		return nil, err
	}
	defer clear(block.Bytes)
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, failure("unsupported_key", 2, "private key PEM must be unencrypted PKCS#8 or SEC1")
	}
	if err != nil {
		return nil, invalid("malformed private key")
	}
	signer, ok := key.(crypto.Signer)
	if !ok || !supportedPublic(signer.Public()) {
		return nil, failure("unsupported_key", 2, "private key must be Ed25519 or ECDSA P-256")
	}
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, invalid("malformed Ed25519 private key")
		}
	case *ecdsa.PrivateKey:
		encoded, err := key.Bytes()
		if err != nil {
			return nil, invalid("malformed ECDSA private key")
		}
		clear(encoded)
	default:
		return nil, failure("unsupported_key", 2, "unsupported local software key")
	}
	return signer, nil
}

func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := ReadSecurityFile(path, MaxKeyBytes, false, "key_unreadable")
	if err != nil {
		return nil, err
	}
	block, err := onePEM(data)
	if err != nil {
		return nil, err
	}
	if block.Type != "PUBLIC KEY" {
		return nil, failure("unsupported_key", 2, "trusted public key must use PKIX PUBLIC KEY PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, invalid("malformed trusted public key")
	}
	if !supportedPublic(key) {
		return nil, failure("unsupported_key", 2, "trusted key must be Ed25519 or ECDSA P-256")
	}
	return key, nil
}

func PublicKeyID(key crypto.PublicKey) (string, error) {
	if !supportedPublic(key) {
		return "", failure("unsupported_key", 2, "unsupported key algorithm")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", invalid("malformed public key")
	}
	digest := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
