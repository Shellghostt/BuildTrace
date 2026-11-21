// Package testsigning creates disposable synthetic CA/CT/Rekor evidence for
// offline tests. It is never imported by the production CLI. Private signing
// material stays in this generator's memory; returned fixtures are public.
package testsigning

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"

	canonicaljson "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	dsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/dsse" // register the standard entry format
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/shellghostt/buildtrace/internal/attestation"
)

const Identity = "https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4"
const Issuer = "https://issuer.fixture.invalid"

type Fixture struct {
	Bundle      []byte
	TrustRoot   []byte
	Payload     []byte
	Certificate []byte
	SigningTime time.Time
}

func Payload(name string, content []byte) ([]byte, error) {
	digest := sha256.Sum256(content)
	return attestation.Build(attestation.Options{
		Artifacts: []attestation.Observation{{Name: name, Kind: "file", Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}},
		Checkout:  attestation.Checkout{URI: "git+https://source.fixture.invalid/owner/project", Commit: "0123456789012345678901234567890123456789"},
		Recorder:  attestation.Recorder{Version: "m4-synthetic-fixture", GoVersion: "go1.26.11", GitVersion: "fixture", OS: "linux", Arch: "amd64"},
	})
}

func key() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func certificate(template, parent *x509.Certificate, public crypto.PublicKey, private crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Generate creates a standard v0.3 bundle with a real PAE signature, synthetic
// certificate chain/SCT, and signed one-entry Rekor tree/SET. No network runs.
func Generate(payload []byte) (Fixture, error) {
	return GenerateWithOptions(payload, Options{})
}

// Options deliberately removes required evidence or selects a wrong signing
// time for negative certificate tests while keeping the log binding genuine.
type Options struct {
	OmitSCT     bool
	OmitIssuer  bool
	SigningTime time.Time
}

func GenerateWithOptions(payload []byte, options Options) (Fixture, error) {
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	signedAt := start.Add(5 * time.Minute)
	if !options.SigningTime.IsZero() {
		signedAt = options.SigningTime
	}
	validFrom, validUntil := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey, err := key()
	if err != nil {
		return Fixture{}, err
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BuildTrace synthetic M4 root"},
		NotBefore: validFrom, NotAfter: validUntil, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1}
	rootCert, err := certificate(rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return Fixture{}, err
	}
	intermediateKey, err := key()
	if err != nil {
		return Fixture{}, err
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "BuildTrace synthetic M4 intermediate"},
		NotBefore: validFrom, NotAfter: validUntil, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true}
	intermediate, err := certificate(intermediateTemplate, rootCert, intermediateKey.Public(), rootKey)
	if err != nil {
		return Fixture{}, err
	}
	leafKey, err := key()
	if err != nil {
		return Fixture{}, err
	}
	identity, err := url.Parse(Identity)
	if err != nil {
		return Fixture{}, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), URIs: []*url.URL{identity}, NotBefore: start, NotAfter: start.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(Issuer)}}}
	if options.OmitIssuer {
		leafTemplate.ExtraExtensions = nil
	}
	preLeaf, err := certificate(leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	if err != nil {
		return Fixture{}, err
	}
	ctKey, err := key()
	if err != nil {
		return Fixture{}, err
	}
	ctDER, err := x509.MarshalPKIXPublicKey(ctKey.Public())
	if err != nil {
		return Fixture{}, err
	}
	ctID := sha256.Sum256(ctDER)
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: ctID}, Timestamp: uint64(start.Add(time.Minute).UnixMilli())}
	sctLeaf := ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType, TimestampedEntry: &ct.TimestampedEntry{
		EntryType: ct.PrecertLogEntryType, Timestamp: sct.Timestamp, PrecertEntry: &ct.PreCert{
			IssuerKeyHash: sha256.Sum256(intermediate.RawSubjectPublicKeyInfo), TBSCertificate: preLeaf.RawTBSCertificate}}}
	sctInput, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: sctLeaf})
	if err != nil {
		return Fixture{}, err
	}
	sctHash := sha256.Sum256(sctInput)
	sctSignature, err := ecdsa.SignASN1(rand.Reader, ctKey, sctHash[:])
	if err != nil {
		return Fixture{}, err
	}
	sct.Signature = ct.DigitallySigned(cttls.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: sctSignature})
	sctBytes, err := cttls.Marshal(sct)
	if err != nil {
		return Fixture{}, err
	}
	list := make([]byte, len(sctBytes)+4)
	binary.BigEndian.PutUint16(list[:2], uint16(len(sctBytes)+2))
	binary.BigEndian.PutUint16(list[2:4], uint16(len(sctBytes)))
	copy(list[4:], sctBytes)
	sctExtension, err := asn1.Marshal(list)
	if err != nil {
		return Fixture{}, err
	}
	if !options.OmitSCT {
		leafTemplate.ExtraExtensions = append(leafTemplate.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: sctExtension})
	}
	leaf, err := certificate(leafTemplate, intermediate, leafKey.Public(), intermediateKey)
	if err != nil {
		return Fixture{}, err
	}
	pae := dsse.PAE("application/vnd.in-toto+json", payload)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, digest[:])
	if err != nil {
		return Fixture{}, err
	}
	envelope := dsse.Envelope{PayloadType: "application/vnd.in-toto+json", Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}}}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return Fixture{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	proposed, err := types.NewProposedEntry(context.Background(), "dsse", "0.0.1", types.ArtifactProperties{
		ArtifactBytes: envelopeJSON, SignatureBytes: sig, PublicKeyBytes: [][]byte{certPEM}, PKIFormat: "x509"})
	if err != nil {
		return Fixture{}, err
	}
	versioned, err := types.CreateVersionedEntry(proposed)
	if err != nil {
		return Fixture{}, err
	}
	body, err := types.CanonicalizeEntry(context.Background(), versioned)
	if err != nil {
		return Fixture{}, err
	}
	rekorKey, err := key()
	if err != nil {
		return Fixture{}, err
	}
	rekorDER, err := x509.MarshalPKIXPublicKey(rekorKey.Public())
	if err != nil {
		return Fixture{}, err
	}
	rekorID := sha256.Sum256(rekorDER)
	setBody, err := json.Marshal(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: signedAt.Unix(), LogIndex: 0, LogID: hex.EncodeToString(rekorID[:])})
	if err != nil {
		return Fixture{}, err
	}
	canonicalSET, err := canonicaljson.Transform(setBody)
	if err != nil {
		return Fixture{}, err
	}
	setHash := sha256.Sum256(canonicalSET)
	set, err := ecdsa.SignASN1(rand.Reader, rekorKey, setHash[:])
	if err != nil {
		return Fixture{}, err
	}
	rootHash := sha256.Sum256(append([]byte{0}, body...))
	checkpointSigner, err := signature.LoadECDSASignerVerifier(rekorKey, crypto.SHA256)
	if err != nil {
		return Fixture{}, err
	}
	checkpoint, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.fixture.invalid", 1, 1, rootHash[:], checkpointSigner)
	if err != nil {
		return Fixture{}, err
	}
	entry := &protorekor.TransparencyLogEntry{LogIndex: 0, LogId: &common.LogId{KeyId: rekorID[:]},
		KindVersion: &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}, IntegratedTime: signedAt.Unix(), CanonicalizedBody: body,
		InclusionPromise: &protorekor.InclusionPromise{SignedEntryTimestamp: set}, InclusionProof: &protorekor.InclusionProof{
			LogIndex: 0, RootHash: rootHash[:], TreeSize: 1, Checkpoint: &protorekor.Checkpoint{Envelope: string(checkpoint)}}}
	b := &protobundle.Bundle{MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", Content: &protobundle.Bundle_DsseEnvelope{
		DsseEnvelope: &protodsse.Envelope{PayloadType: envelope.PayloadType, Payload: payload, Signatures: []*protodsse.Signature{{Sig: sig}}}},
		VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_Certificate{
			Certificate: &common.X509Certificate{RawBytes: leaf.Raw}}, TlogEntries: []*protorekor.TransparencyLogEntry{entry}}}
	encodedBundle, err := protojson.Marshal(b)
	if err != nil {
		return Fixture{}, err
	}
	trusted, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
		[]root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: rootCert, Intermediates: []*x509.Certificate{intermediate}, URI: "https://fulcio.fixture.invalid", ValidityPeriodStart: validFrom, ValidityPeriodEnd: validUntil}},
		map[string]*root.TransparencyLog{hex.EncodeToString(ctID[:]): {BaseURL: "https://ct.fixture.invalid", ID: ctID[:], PublicKey: ctKey.Public(), HashFunc: crypto.SHA256, SignatureHashFunc: crypto.SHA256, ValidityPeriodStart: validFrom, ValidityPeriodEnd: validUntil}},
		nil, map[string]*root.TransparencyLog{hex.EncodeToString(rekorID[:]): {BaseURL: "https://rekor.fixture.invalid", ID: rekorID[:], PublicKey: rekorKey.Public(), HashFunc: crypto.SHA256, SignatureHashFunc: crypto.SHA256, ValidityPeriodStart: validFrom, ValidityPeriodEnd: validUntil}})
	if err != nil {
		return Fixture{}, err
	}
	encodedRoot, err := trusted.MarshalJSON()
	if err != nil {
		return Fixture{}, err
	}
	return Fixture{Bundle: append(encodedBundle, '\n'), TrustRoot: append(encodedRoot, '\n'), Payload: bytes.Clone(payload), Certificate: bytes.Clone(leaf.Raw), SigningTime: signedAt}, nil
}
