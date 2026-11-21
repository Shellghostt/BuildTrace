package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	prototrust "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	rekorutil "github.com/sigstore/rekor/pkg/util"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
const MaxCertificateBytes = 16 << 10
const MaxLogBodyBytes = 128 << 10
const MaxCheckpointBytes = 16 << 10
const MaxProofHashes = 64

type SignerEvidence struct {
	Mode                 string     `json:"mode"`
	KeyID                string     `json:"keyId"`
	Identity             string     `json:"identity,omitempty"`
	Issuer               string     `json:"issuer,omitempty"`
	SigningTime          *time.Time `json:"authenticatedSigningTime,omitempty"`
	CertificateNotBefore *time.Time `json:"certificateNotBefore,omitempty"`
	CertificateNotAfter  *time.Time `json:"certificateNotAfter,omitempty"`
	TrustRootSHA256      string     `json:"trustRootSha256,omitempty"`
}

type TrustedRoot struct {
	Material *root.TrustedRoot
	SHA256   string
}

func LoadTrustedRoot(path string) (TrustedRoot, error) {
	data, err := ReadSecurityFile(path, MaxTrustBytes, false, "trust_unreadable")
	if err != nil {
		var input *Error
		if errors.As(err, &input) && input.Code == 2 {
			return TrustedRoot{}, failure("trust_invalid", 2, "trusted-root file is missing or invalid")
		}
		return TrustedRoot{}, err
	}
	return ParseTrustedRoot(data)
}

func ParseTrustedRoot(data []byte) (TrustedRoot, error) {
	bad := func() (TrustedRoot, error) {
		return TrustedRoot{}, failure("trust_invalid", 2, "malformed, unsupported or oversized trusted-root material")
	}
	if err := checkJSON(data, MaxTrustBytes); err != nil {
		return bad()
	}
	if _, err := fields(data, []string{"mediaType", "certificateAuthorities", "tlogs", "ctlogs"},
		"mediaType", "certificateAuthorities", "tlogs", "ctlogs", "timestampAuthorities"); err != nil {
		return bad()
	}
	var pb prototrust.TrustedRoot
	if err := canonicalProtoJSON(data, pb.ProtoReflect().Descriptor()); err != nil {
		return bad()
	}
	if err := protojson.Unmarshal(data, &pb); err != nil || pb.GetMediaType() != root.TrustedRootMediaType01 {
		return bad()
	}
	if len(pb.GetCertificateAuthorities()) == 0 || len(pb.GetCertificateAuthorities()) > 16 ||
		len(pb.GetTlogs()) == 0 || len(pb.GetTlogs()) > 16 || len(pb.GetCtlogs()) == 0 || len(pb.GetCtlogs()) > 16 || len(pb.GetTimestampAuthorities()) > 16 {
		return bad()
	}
	for _, collection := range [][]*prototrust.CertificateAuthority{pb.GetCertificateAuthorities(), pb.GetTimestampAuthorities()} {
		for _, ca := range collection {
			if ca == nil || ca.GetCertChain() == nil || len(ca.GetCertChain().GetCertificates()) == 0 || len(ca.GetCertChain().GetCertificates()) > 8 {
				return bad()
			}
			for _, cert := range ca.GetCertChain().GetCertificates() {
				if cert == nil || len(cert.GetRawBytes()) == 0 || len(cert.GetRawBytes()) > MaxCertificateBytes {
					return bad()
				}
			}
		}
	}
	for _, logs := range [][]*prototrust.TransparencyLogInstance{pb.GetTlogs(), pb.GetCtlogs()} {
		seen := map[string]bool{}
		for _, log := range logs {
			if log == nil || log.GetPublicKey() == nil || len(log.GetPublicKey().GetRawBytes()) == 0 || len(log.GetPublicKey().GetRawBytes()) > MaxKeyBytes ||
				log.GetLogId() == nil || len(log.GetLogId().GetKeyId()) != sha256.Size {
				return bad()
			}
			id := string(log.GetLogId().GetKeyId())
			if seen[id] {
				return bad()
			}
			seen[id] = true
		}
	}
	material, err := root.NewTrustedRootFromProtobuf(&pb)
	if err != nil {
		return bad()
	}
	for kind, logs := range []map[string]*root.TransparencyLog{material.RekorLogs(), material.CTLogs()} {
		for _, log := range logs {
			// Standard snapshots also contain Rekor v2 Ed25519 keys. Their
			// log ID hashes the log origin, rather than SPKI. M4's v1 SET
			// path cannot use these keys, but must accept the shared snapshot.
			if _, v2 := log.PublicKey.(ed25519.PublicKey); kind == 0 && v2 {
				continue
			}
			der, err := x509.MarshalPKIXPublicKey(log.PublicKey)
			if err != nil {
				return bad()
			}
			digest := sha256.Sum256(der)
			if !bytes.Equal(log.ID, digest[:]) {
				return bad()
			}
		}
	}
	sum := sha256.Sum256(data)
	return TrustedRoot{Material: material, SHA256: hex.EncodeToString(sum[:])}, nil
}

type KeylessBundle struct {
	Decoded Decoded
	Leaf    *x509.Certificate
	Bundle  *sigbundle.Bundle
}

func securityString(raw json.RawMessage, maximum int, nonempty bool) (string, error) {
	var value string
	if raw == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil ||
		len(value) > maximum || nonempty && !public(value, maximum) {
		return "", invalid("invalid bounded security string")
	}
	return value, nil
}

func base64Field(obj map[string]json.RawMessage, field string, maximum int) ([]byte, error) {
	value, err := securityString(obj[field], (maximum+2)/3*4, true)
	if err != nil {
		return nil, err
	}
	return strictBase64(value, maximum)
}

func decimalField(raw json.RawMessage, positive bool) (int64, error) {
	// Canonical protobuf JSON omits an int64 scalar whose value is zero.
	if raw == nil && !positive {
		return 0, nil
	}
	value, err := securityString(raw, 20, true)
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil || number < 0 || positive && number == 0 || strconv.FormatInt(number, 10) != value {
		return 0, invalid("invalid canonical log index or timestamp")
	}
	return number, nil
}

func DecodeKeylessBundle(data []byte) (KeylessBundle, error) {
	if err := checkJSON(data, MaxOuterBytes); err != nil {
		return KeylessBundle{}, err
	}
	top, err := fields(data, []string{"mediaType", "dsseEnvelope", "verificationMaterial"}, "mediaType", "dsseEnvelope", "verificationMaterial")
	if err != nil {
		return KeylessBundle{}, err
	}
	media, err := securityString(top["mediaType"], 128, true)
	if err != nil || media != BundleMediaType {
		return KeylessBundle{}, invalid("only DSSE Sigstore bundle v0.3 is supported")
	}
	decoded, err := DecodeEnvelope(top["dsseEnvelope"])
	if err != nil {
		return KeylessBundle{}, err
	}
	material, err := fields(top["verificationMaterial"], []string{"certificate"}, "certificate", "tlogEntries")
	if err != nil {
		return KeylessBundle{}, err
	}
	certObject, err := fields(material["certificate"], []string{"rawBytes"}, "rawBytes")
	if err != nil {
		return KeylessBundle{}, err
	}
	der, err := base64Field(certObject, "rawBytes", MaxCertificateBytes)
	if err != nil {
		return KeylessBundle{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || !supportedPublic(leaf.PublicKey) {
		return KeylessBundle{}, failure("certificate_invalid", 1, "invalid certificate or unsupported leaf key")
	}
	var entries []json.RawMessage
	if value, exists := material["tlogEntries"]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return KeylessBundle{}, failure("signing_time_missing", 1, "Rekor SET, inclusion proof and checkpoint are required")
	} else if json.Unmarshal(value, &entries) != nil || len(entries) > 1 {
		return KeylessBundle{}, invalid("exactly one Rekor entry is supported")
	}
	if len(entries) == 0 {
		return KeylessBundle{}, failure("signing_time_missing", 1, "Rekor SET, inclusion proof and checkpoint are required")
	}
	if err := validateLogEntry(entries[0]); err != nil {
		return KeylessBundle{}, err
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(data, &pb); err != nil {
		return KeylessBundle{}, invalid("malformed standard Sigstore bundle")
	}
	b, err := sigbundle.NewBundle(&pb)
	if err != nil {
		return KeylessBundle{}, invalid("invalid standard Sigstore bundle")
	}
	return KeylessBundle{Decoded: decoded, Leaf: leaf, Bundle: b}, nil
}

func validateLogEntry(raw []byte) error {
	entry, err := fields(raw, []string{"logId", "kindVersion", "canonicalizedBody"},
		"logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody")
	if err != nil {
		return err
	}
	for _, name := range []string{"integratedTime", "inclusionPromise", "inclusionProof"} {
		if value, exists := entry[name]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return failure("signing_time_missing", 1, "authenticated log time, SET and proof/checkpoint are required")
		}
	}
	kind, err := fields(entry["kindVersion"], []string{"kind", "version"}, "kind", "version")
	if err != nil {
		return err
	}
	k, err := securityString(kind["kind"], 32, true)
	if err != nil {
		return err
	}
	v, err := securityString(kind["version"], 32, true)
	if err != nil || k != "dsse" || v != "0.0.1" {
		return invalid("only Rekor v1 dsse/0.0.1 entries are supported")
	}
	logID, err := fields(entry["logId"], []string{"keyId"}, "keyId")
	if err != nil {
		return err
	}
	id, err := base64Field(logID, "keyId", sha256.Size)
	if err != nil || len(id) != sha256.Size {
		return invalid("invalid Rekor log key identifier")
	}
	body, err := base64Field(entry, "canonicalizedBody", MaxLogBodyBytes)
	if err != nil {
		return err
	}
	if err := checkJSON(body, MaxLogBodyBytes); err != nil {
		return err
	}
	if _, err := decimalField(entry["logIndex"], false); err != nil {
		return err
	}
	if _, err := decimalField(entry["integratedTime"], true); err != nil {
		return err
	}
	promise, err := fields(entry["inclusionPromise"], []string{"signedEntryTimestamp"}, "signedEntryTimestamp")
	if err != nil {
		return err
	}
	if _, err := base64Field(promise, "signedEntryTimestamp", MaxSignatureBytes); err != nil {
		return err
	}
	proof, err := fields(entry["inclusionProof"], []string{"rootHash", "treeSize"}, "logIndex", "rootHash", "treeSize", "hashes", "checkpoint")
	if err != nil {
		return err
	}
	if _, exists := proof["checkpoint"]; !exists {
		return failure("signing_time_missing", 1, "signed inclusion checkpoint is required")
	}
	if _, err := decimalField(proof["logIndex"], false); err != nil {
		return err
	}
	if _, err := decimalField(proof["treeSize"], true); err != nil {
		return err
	}
	hash, err := base64Field(proof, "rootHash", sha256.Size)
	if err != nil || len(hash) != sha256.Size {
		return invalid("invalid proof root hash")
	}
	if value, exists := proof["hashes"]; exists {
		var hashes []string
		if json.Unmarshal(value, &hashes) != nil || hashes == nil || len(hashes) > MaxProofHashes {
			return invalid("malformed or oversized proof hash array")
		}
		for _, encoded := range hashes {
			if h, err := strictBase64(encoded, sha256.Size); err != nil || len(h) != sha256.Size {
				return invalid("invalid proof hash")
			}
		}
	}
	checkpoint, err := fields(proof["checkpoint"], []string{"envelope"}, "envelope")
	if err != nil {
		return err
	}
	if _, err := securityString(checkpoint["envelope"], MaxCheckpointBytes, false); err != nil {
		return err
	}
	return nil
}

// VerifyKeyless uses only the caller-provisioned root. No live/TUF root, URL
// fetching, process runner or implicit online verification path is constructed.
func VerifyKeyless(input KeylessBundle, trusted TrustedRoot, identity, issuer string) (SignerEvidence, error) {
	if trusted.Material == nil || !public(identity, 4096) || !public(issuer, 4096) {
		return SignerEvidence{}, invalid("external root and exact signer/issuer policy are required")
	}
	if input.Leaf == nil || input.Bundle == nil {
		return SignerEvidence{}, invalid("complete decoded keyless input is required")
	}
	if err := VerifyPAE(input.Decoded, input.Leaf.PublicKey); err != nil {
		return SignerEvidence{}, err
	}
	entries, err := input.Bundle.TlogEntries()
	if err != nil || len(entries) != 1 {
		return SignerEvidence{}, failure("transparency_invalid", 1, "invalid standard Rekor entry")
	}
	entry := entries[0]
	log := trusted.Material.RekorLogs()[hex.EncodeToString([]byte(entry.LogKeyID()))]
	if log == nil || tlog.VerifySET(entry, trusted.Material.RekorLogs()) != nil {
		return SignerEvidence{}, failure("transparency_invalid", 1, "Rekor SET is invalid or its log key/time is untrusted")
	}
	proof := entry.TransparencyLogEntry().GetInclusionProof()
	var checkpoint rekorutil.SignedCheckpoint
	if proof == nil || proof.GetCheckpoint() == nil || checkpoint.UnmarshalText([]byte(proof.GetCheckpoint().GetEnvelope())) != nil ||
		checkpoint.Size != uint64(proof.GetTreeSize()) || !bytes.Equal(checkpoint.Hash, proof.GetRootHash()) || proof.GetLogIndex() >= proof.GetTreeSize() ||
		proof.GetLogIndex() != entry.LogIndex() {
		return SignerEvidence{}, failure("transparency_invalid", 1, "signed checkpoint and proof tree/index/root are inconsistent")
	}
	logVerifier, err := signature.LoadVerifier(log.PublicKey, log.SignatureHashFunc)
	if err != nil || tlog.VerifyInclusion(entry, logVerifier) != nil {
		return SignerEvidence{}, failure("transparency_invalid", 1, "Rekor inclusion proof or signed checkpoint is invalid")
	}
	// Only SET-authenticated time may decide a leaf validity failure. This
	// preserves the certificate reason without trusting an unsigned timestamp.
	at := entry.IntegratedTime()
	if at.Before(input.Leaf.NotBefore) || at.After(input.Leaf.NotAfter) {
		return SignerEvidence{}, failure("certificate_invalid", 1, "leaf certificate is not valid at authenticated signing time")
	}
	verifier, err := sigverify.NewVerifier(trusted.Material, sigverify.WithTransparencyLog(1),
		sigverify.WithIntegratedTimestamps(1), sigverify.WithSignedCertificateTimestamps(1), sigverify.WithoutStatementPredicate())
	if err != nil {
		return SignerEvidence{}, failure("trust_invalid", 2, "invalid trusted-root verifier configuration")
	}
	timestamps, err := verifier.VerifyTransparencyLogInclusion(input.Bundle)
	if err != nil {
		return SignerEvidence{}, failure("transparency_invalid", 1, "Rekor binding, SET, inclusion proof or checkpoint is invalid or untrusted")
	}
	if _, err := verifier.VerifyObserverTimestamps(input.Bundle, timestamps); err != nil {
		return SignerEvidence{}, failure("transparency_invalid", 1, "authenticated log signing time is invalid or untrusted")
	}
	summary, err := fulciocert.SummarizeCertificate(input.Leaf)
	if err != nil || !public(summary.Issuer, 4096) || !public(summary.SubjectAlternativeName, 4096) {
		return SignerEvidence{}, failure("certificate_invalid", 1, "required certificate OIDC issuer and signer extensions are absent or malformed")
	}
	policy, err := sigverify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		return SignerEvidence{}, invalid("exact signer/issuer policy is invalid")
	}
	// Artifact recomputation and canonical subject selection are performed by
	// our rooted pipeline after this crypto stage; this alone is not a verdict.
	result, err := verifier.Verify(input.Bundle, sigverify.NewPolicy(sigverify.WithoutArtifactUnsafe(), sigverify.WithCertificateIdentity(policy)))
	if err != nil {
		var mismatch *sigverify.ErrNoMatchingCertificateIdentity
		if errors.As(err, &mismatch) {
			return SignerEvidence{}, failure("identity_mismatch", 1, "certificate signer or OIDC issuer differs from exact policy")
		}
		return SignerEvidence{}, failure("certificate_invalid", 1, "certificate chain, validity, required extensions or CT signature is invalid or untrusted")
	}
	if result.Signature == nil || result.Signature.Certificate == nil || len(result.VerifiedTimestamps) != 1 {
		return SignerEvidence{}, failure("certificate_invalid", 1, "required authenticated certificate/time evidence is absent")
	}
	id, err := PublicKeyID(input.Leaf.PublicKey)
	if err != nil {
		return SignerEvidence{}, err
	}
	at = result.VerifiedTimestamps[0].Timestamp.UTC()
	notBefore, notAfter := input.Leaf.NotBefore.UTC(), input.Leaf.NotAfter.UTC()
	return SignerEvidence{Mode: "keyless", KeyID: id, Identity: result.Signature.Certificate.SubjectAlternativeName,
		Issuer: result.Signature.Certificate.Issuer, SigningTime: &at, CertificateNotBefore: &notBefore,
		CertificateNotAfter: &notAfter, TrustRootSHA256: trusted.SHA256}, nil
}
