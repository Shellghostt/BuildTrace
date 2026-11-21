package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/pkg/intoto"
)

const PayloadType = "application/vnd.in-toto+json"
const MaxSignatures = 16
const MaxSignatureBytes = 128

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Decoded struct {
	Envelope  Envelope
	Payload   []byte
	Signature []byte
}

// PAE uses byte lengths, decimal ASCII, and the original payload (including LF).
func PAE(payloadType string, payload []byte) []byte {
	out := make([]byte, 0, len(payloadType)+len(payload)+64)
	out = append(out, "DSSEv1 "...)
	out = strconv.AppendInt(out, int64(len(payloadType)), 10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(payload)), 10)
	out = append(out, ' ')
	return append(out, payload...)
}

func strictBase64(value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, invalid("empty or oversized base64 material")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maximum || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, invalid("noncanonical or malformed base64 material")
	}
	return decoded, nil
}

func DecodeEnvelope(data []byte) (Decoded, error) {
	if err := checkJSON(data, MaxOuterBytes); err != nil {
		return Decoded{}, err
	}
	obj, err := fields(data, []string{"payloadType", "payload", "signatures"}, "payloadType", "payload", "signatures")
	if err != nil {
		return Decoded{}, err
	}
	var env Envelope
	if err := json.Unmarshal(obj["payloadType"], &env.PayloadType); err != nil || env.PayloadType != PayloadType {
		return Decoded{}, invalid("unsupported or malformed DSSE payload type")
	}
	var signatures []json.RawMessage
	if err := json.Unmarshal(obj["signatures"], &signatures); err != nil || signatures == nil || len(signatures) > MaxSignatures {
		return Decoded{}, invalid("malformed or oversized signature array")
	}
	if len(signatures) == 0 {
		return Decoded{}, failure("missing_signature", 1, "one signature is required")
	}
	if len(signatures) != 1 {
		return Decoded{}, failure("ambiguous_signatures", 2, "M4 requires one signature and one signer policy")
	}
	// Decode typed signatures only after enforcing the selection/count bound.
	if err := json.Unmarshal(data, &env); err != nil {
		return Decoded{}, invalid("malformed DSSE field types")
	}
	if _, err := fields(signatures[0], []string{"sig"}, "keyid", "sig"); err != nil {
		return Decoded{}, err
	}
	if env.Signatures[0].KeyID != "" && !public(env.Signatures[0].KeyID, 128) {
		return Decoded{}, invalid("invalid signature key identifier")
	}
	payload, err := strictBase64(env.Payload, attestation.MaxInputBytes)
	if err != nil {
		return Decoded{}, err
	}
	sig, err := strictBase64(env.Signatures[0].Sig, MaxSignatureBytes)
	if err != nil {
		return Decoded{}, err
	}
	return Decoded{Envelope: env, Payload: payload, Signature: sig}, nil
}

func supportedPublic(key crypto.PublicKey) bool {
	switch key := key.(type) {
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		if key == nil || key.Curve != elliptic.P256() {
			return false
		}
		_, err := key.Bytes()
		return err == nil
	}
	return false
}

func VerifyPAE(decoded Decoded, key crypto.PublicKey) error {
	if !supportedPublic(key) {
		return failure("unsupported_key", 2, "only Ed25519 and ECDSA P-256 are supported")
	}
	pae := PAE(decoded.Envelope.PayloadType, decoded.Payload)
	valid := false
	switch key := key.(type) {
	case ed25519.PublicKey:
		valid = len(decoded.Signature) == ed25519.SignatureSize && ed25519.Verify(key, pae, decoded.Signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(pae)
		valid = ecdsa.VerifyASN1(key, digest[:], decoded.Signature)
	}
	if !valid {
		return failure("signature_invalid", 1, "DSSE signature does not authenticate the received bytes")
	}
	return nil
}

func SignLocal(payload []byte, key crypto.Signer) ([]byte, error) {
	if key == nil || !supportedPublic(key.Public()) {
		return nil, failure("unsupported_key", 2, "only Ed25519 and ECDSA P-256 are supported")
	}
	if len(payload) == 0 || len(payload) > attestation.MaxInputBytes {
		return nil, invalid("payload exceeds the statement bound")
	}
	pae := PAE(PayloadType, payload)
	var data []byte
	var opts crypto.SignerOpts
	switch key.(type) {
	case ed25519.PrivateKey:
		data, opts = pae, crypto.Hash(0)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(pae)
		data, opts = digest[:], crypto.SHA256
	default:
		return nil, failure("unsupported_key", 2, "private key is not a supported local software key")
	}
	sig, err := key.Sign(rand.Reader, data, opts)
	if err != nil {
		return nil, failure("signing_failed", 3, "local signing failed")
	}
	id, err := PublicKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	return intoto.MarshalLine(Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{KeyID: id, Sig: base64.StdEncoding.EncodeToString(sig)}}})
}
