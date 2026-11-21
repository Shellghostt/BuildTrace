package verify

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/internal/hashing"
	"github.com/shellghostt/buildtrace/internal/signing"
)

type Selection struct {
	Subject string
	Path    string
}

type AttestationPolicy struct {
	PublicKey     string
	TrustedRoot   string
	Identity      string
	Issuer        string
	AllowUnsigned bool
	Builder       string
	SourceURI     string
	SourceCommit  string
}

type ArtifactCheck struct {
	Subject            string `json:"subject"`
	Path               string `json:"path"`
	Kind               string `json:"kind"`
	Size               int64  `json:"size"`
	SHA256             string `json:"sha256"`
	ExpectedSHA256     string `json:"expectedSha256"`
	DigestMatched      bool   `json:"digestMatched"`
	KindAndSizeMatched bool   `json:"kindAndSizeMatched"`
}

type AttestationReport struct {
	Version              int                     `json:"version"`
	Scope                string                  `json:"scope"`
	Status               string                  `json:"status"`
	Reason               string                  `json:"reason,omitempty"`
	Message              string                  `json:"message,omitempty"`
	Authenticated        bool                    `json:"authenticated"`
	Signer               *signing.SignerEvidence `json:"signer,omitempty"`
	ExpectedIdentity     string                  `json:"expectedIdentity,omitempty"`
	ExpectedIssuer       string                  `json:"expectedIssuer,omitempty"`
	ExpectedBuilder      string                  `json:"expectedRecorderLabel,omitempty"`
	ExpectedSourceURI    string                  `json:"expectedDeclaredSourceUri,omitempty"`
	ExpectedSourceCommit string                  `json:"expectedDeclaredSourceCommit,omitempty"`
	Checked              []ArtifactCheck         `json:"checked"`
	Unselected           []string                `json:"unselectedSubjects"`
	Verified             int                     `json:"verified"`
	Warnings             []string                `json:"warnings,omitempty"`
}

func NewAttestationReport() AttestationReport {
	return AttestationReport{Version: 1, Scope: "signed_statement", Status: "failed", Checked: []ArtifactCheck{}, Unselected: []string{}}
}

func publicValue(value string) bool {
	if value == "" || len(value) > attestation.MaxIdentifierBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func CanonicalSubject(value string) bool {
	return publicValue(value) && strings.TrimSpace(value) != "" && value != "." && value != ".." && !strings.HasPrefix(value, "../") &&
		!strings.ContainsAny(value, "\\:") && !path.IsAbs(value) && path.Clean(value) == value
}

func policyError(message string) error {
	return &signing.Error{Reason: "invalid_input", Code: 2, Message: message}
}
func mismatch(reason, message string) error {
	return &signing.Error{Reason: reason, Code: 1, Message: message}
}

// ValidateAttestationPolicy checks combinations/selection shapes before file
// reads. The input format later decides which explicit signer pin is required.
func ValidateAttestationPolicy(selections []Selection, policy AttestationPolicy) error {
	if len(selections) == 0 || len(selections) > attestation.MaxArtifacts {
		return policyError("select between 1 and 1000 artifacts")
	}
	seenPaths, seenNames := map[string]bool{}, map[string]bool{}
	for _, selection := range selections {
		name, rel := selection.Subject, filepath.ToSlash(selection.Path)
		if !CanonicalSubject(name) || !CanonicalSubject(rel) {
			return policyError("selected artifacts and subject mappings must be canonical relative paths")
		}
		key := rel
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seenPaths[key] || seenNames[name] {
			return policyError("duplicate or colliding artifact/subject selection")
		}
		seenPaths[key], seenNames[name] = true, true
	}
	if policy.PublicKey != "" && (policy.TrustedRoot != "" || policy.Identity != "" || policy.Issuer != "") {
		return policyError("local public-key and keyless certificate policies cannot be combined")
	}
	if policy.AllowUnsigned && (policy.PublicKey != "" || policy.TrustedRoot != "" || policy.Identity != "" || policy.Issuer != "") {
		return policyError("unsigned opt-in cannot satisfy or be combined with signer policy")
	}
	if (policy.Identity == "") != (policy.Issuer == "") {
		return policyError("exact certificate identity and issuer must be supplied together")
	}
	for _, value := range []string{policy.Identity, policy.Issuer, policy.Builder, policy.SourceURI, policy.SourceCommit} {
		if value != "" && !publicValue(value) {
			return policyError("verification policy must contain bounded public exact identifiers")
		}
	}
	if (policy.SourceURI == "") != (policy.SourceCommit == "") {
		return policyError("expected source URI and full commit must be supplied together")
	}
	if policy.SourceURI != "" {
		u, err := url.Parse(policy.SourceURI)
		commit, e := hex.DecodeString(policy.SourceCommit)
		if err != nil || !u.IsAbs() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || e != nil ||
			(len(commit) != 20 && len(commit) != 32) || strings.ToLower(policy.SourceCommit) != policy.SourceCommit {
			return policyError("expected declared source must use an exact public URI and full lowercase commit")
		}
	}
	return nil
}

func CheckAttestation(input []byte, rootPath string, selections []Selection, policy AttestationPolicy) (AttestationReport, error) {
	report := NewAttestationReport()
	fail := func(err error) (AttestationReport, error) {
		var specific *signing.Error
		if errors.As(err, &specific) {
			report.Reason, report.Message = specific.Reason, specific.Message
		} else {
			report.Reason, report.Message = "invalid_input", "invalid attestation input"
		}
		return report, err
	}
	if err := ValidateAttestationPolicy(selections, policy); err != nil {
		return fail(err)
	}
	report.ExpectedIdentity, report.ExpectedIssuer, report.ExpectedBuilder = policy.Identity, policy.Issuer, policy.Builder
	report.ExpectedSourceURI, report.ExpectedSourceCommit = policy.SourceURI, policy.SourceCommit
	var top map[string]json.RawMessage
	if err := signing.ValidateSecurityJSON(input); err != nil {
		return fail(err)
	}
	if json.Unmarshal(input, &top) != nil || top == nil {
		return fail(policyError("invalid attestation JSON object"))
	}
	var payload []byte
	if _, statement := top["_type"]; statement {
		for _, key := range []string{"payloadType", "payload", "signatures", "mediaType", "dsseEnvelope"} {
			if _, exists := top[key]; exists {
				return fail(policyError("mixed unsigned and signed security formats are ambiguous"))
			}
		}
		if !policy.AllowUnsigned {
			return fail(mismatch("missing_signature", "unsigned statements require explicit unsigned opt-in"))
		}
		payload = input
		report.Scope = "unsigned_statement"
		report.Warnings = []string{"Unsigned comparison does not authenticate a signer or original build history."}
	} else if _, bundle := top["mediaType"]; bundle {
		decoded, err := signing.DecodeKeylessBundle(input)
		if err != nil {
			return fail(err)
		}
		if policy.PublicKey != "" || policy.TrustedRoot == "" || policy.Identity == "" || policy.Issuer == "" {
			return fail(policyError("keyless bundle requires an external root and exact certificate identity/issuer"))
		}
		trusted, err := signing.LoadTrustedRoot(policy.TrustedRoot)
		if err != nil {
			return fail(err)
		}
		evidence, err := signing.VerifyKeyless(decoded, trusted, policy.Identity, policy.Issuer)
		if err != nil {
			return fail(err)
		}
		report.Signer, report.Authenticated, payload = &evidence, true, decoded.Decoded.Payload
	} else {
		decoded, err := signing.DecodeEnvelope(input)
		if err != nil {
			return fail(err)
		}
		if policy.PublicKey == "" || policy.AllowUnsigned {
			return fail(policyError("local DSSE envelope requires an externally trusted public key"))
		}
		key, err := signing.LoadPublicKey(policy.PublicKey)
		if err != nil {
			return fail(err)
		}
		if err := signing.VerifyPAE(decoded, key); err != nil {
			return fail(err)
		}
		id, err := signing.PublicKeyID(key)
		if err != nil {
			return fail(err)
		}
		report.Signer = &signing.SignerEvidence{Mode: "local", KeyID: id}
		report.Authenticated, payload = true, decoded.Payload
	}
	parsed, err := attestation.Read(bytes.NewReader(payload))
	if err != nil {
		return fail(policyError("authenticated payload is not a bounded in-toto/SLSA v1 statement line"))
	}
	subjects := map[string]string{}
	for _, subject := range parsed.Subjects {
		if !CanonicalSubject(subject.Name) || subjects[subject.Name] != "" || len(subject.Digest["sha256"]) != 64 {
			return fail(policyError("subjects must have unique canonical names and SHA-256 digests"))
		}
		subjects[subject.Name] = strings.ToLower(subject.Digest["sha256"])
	}
	selected := map[string]bool{}
	for _, selection := range selections {
		selected[selection.Subject] = true
	}
	for name := range subjects {
		if !selected[name] {
			report.Unselected = append(report.Unselected, name)
		}
	}
	sort.Strings(report.Unselected)
	for _, selection := range selections {
		if _, exists := subjects[selection.Subject]; !exists {
			return fail(mismatch("subject_missing", "a selected canonical subject is absent"))
		}
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fail(policyError("selected artifact root does not exist"))
		}
		return fail(&signing.Error{Reason: "artifact_unreadable", Code: 3, Message: "selected artifact root cannot be opened"})
	}
	defer func() { _ = root.Close() }()
	for _, selection := range selections {
		actual, err := hashing.HashRoot(root, selection.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fail(&signing.Error{Reason: "artifact_missing", Code: 2, Message: "a selected artifact does not exist"})
			}
			return fail(&signing.Error{Reason: "artifact_unreadable", Code: 3, Message: "a selected artifact is unreadable, escaped its root or changed during hashing"})
		}
		check := ArtifactCheck{Subject: selection.Subject, Path: filepath.ToSlash(selection.Path), Kind: actual.Kind, Size: actual.Size,
			SHA256: actual.SHA256, ExpectedSHA256: subjects[selection.Subject], DigestMatched: actual.SHA256 == subjects[selection.Subject]}
		report.Checked = append(report.Checked, check)
		if !check.DigestMatched {
			return fail(mismatch("digest_mismatch", "selected artifact digest differs from its statement subject"))
		}
	}
	if !parsed.RecorderContract {
		return fail(&signing.Error{Reason: "unsupported_build_type", Code: 2, Message: "signed verification only interprets the recorder v1 build type"})
	}
	metadata, source, err := recorderMetadata(parsed)
	if err != nil {
		return fail(err)
	}
	for i := range report.Checked {
		check := &report.Checked[i]
		expected := metadata[check.Subject]
		if expected.Kind != check.Kind {
			return fail(mismatch("kind_mismatch", "selected artifact kind differs from the recorder observation"))
		}
		if expected.Size != check.Size {
			return fail(mismatch("size_mismatch", "selected artifact byte count differs from the recorder observation"))
		}
		check.KindAndSizeMatched = true
		report.Verified++
	}
	if policy.Builder != "" && parsed.BuilderID != policy.Builder {
		return fail(mismatch("builder_mismatch", "signed recorder label differs from the separate assertion constraint"))
	}
	if policy.SourceURI != "" && (source == nil || source.URI != policy.SourceURI || source.Commit != policy.SourceCommit) {
		return fail(mismatch("dependency_mismatch", "declared source/dependency differs from the explicit assertion policy"))
	}
	report.Status = "verified"
	if !report.Authenticated {
		report.Status = "matched"
	}
	return report, nil
}

func exactObject(raw []byte, required []string, allowed ...string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return nil, policyError("malformed recorder v1 parameter object")
	}
	for _, name := range required {
		if value, exists := obj[name]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, policyError("required recorder v1 parameter is absent or null")
		}
	}
	for name := range obj {
		found := false
		for _, candidate := range allowed {
			if name == candidate {
				found = true
				break
			}
		}
		if !found {
			return nil, policyError("unsupported or ambiguous recorder v1 parameter field")
		}
	}
	return obj, nil
}

func recorderMetadata(parsed attestation.Inspection) (map[string]attestation.ArtifactMetadata, *attestation.SourceAssertion, error) {
	var statement map[string]json.RawMessage
	_ = json.Unmarshal(parsed.Raw, &statement)
	var predicate map[string]json.RawMessage
	_ = json.Unmarshal(statement["predicate"], &predicate)
	var definition map[string]json.RawMessage
	_ = json.Unmarshal(predicate["buildDefinition"], &definition)
	external, err := exactObject(definition["externalParameters"], []string{"artifacts"}, "artifacts", "assertedSource")
	if err != nil {
		return nil, nil, err
	}
	internal, err := exactObject(definition["internalParameters"], []string{"observedCheckout", "recorder", "observedArtifacts"}, "observedCheckout", "recorder", "observedArtifacts")
	if err != nil {
		return nil, nil, err
	}
	if _, err := exactObject(internal["observedCheckout"], []string{"commit", "dirty"}, "uri", "commit", "dirty"); err != nil {
		return nil, nil, err
	}
	recorder, err := exactObject(internal["recorder"], []string{"version", "goVersion", "os", "arch"}, "version", "goVersion", "gitVersion", "os", "arch")
	if err != nil {
		return nil, nil, err
	}
	for _, value := range recorder {
		var text string
		if json.Unmarshal(value, &text) != nil || !publicValue(text) {
			return nil, nil, policyError("invalid recorder v1 tool/platform identifier")
		}
	}
	var checkout attestation.Checkout
	if json.Unmarshal(internal["observedCheckout"], &checkout) != nil {
		return nil, nil, policyError("invalid observed checkout parameter")
	}
	commit, err := hex.DecodeString(checkout.Commit)
	if err != nil || (len(commit) != 20 && len(commit) != 32) || strings.ToLower(checkout.Commit) != checkout.Commit ||
		(checkout.URI != "" && attestation.SanitizeObservedRemote(checkout.URI) != checkout.URI) {
		return nil, nil, policyError("observed checkout requires canonical public source/commit metadata")
	}
	var selections, observations []json.RawMessage
	if json.Unmarshal(external["artifacts"], &selections) != nil || len(selections) != len(parsed.Subjects) ||
		json.Unmarshal(internal["observedArtifacts"], &observations) != nil || len(observations) != len(parsed.Subjects) {
		return nil, nil, policyError("recorder subject/selection/observation association is incomplete")
	}
	subjects := map[string]bool{}
	for _, s := range parsed.Subjects {
		subjects[s.Name] = true
	}
	seen := map[string]bool{}
	for _, raw := range selections {
		if _, err := exactObject(raw, []string{"name", "path"}, "name", "path"); err != nil {
			return nil, nil, err
		}
		var selection attestation.ArtifactSelection
		if json.Unmarshal(raw, &selection) != nil || selection.Name != selection.Path || !subjects[selection.Name] || seen[selection.Name] {
			return nil, nil, policyError("invalid recorder selection/subject association")
		}
		seen[selection.Name] = true
	}
	metadata := map[string]attestation.ArtifactMetadata{}
	for _, raw := range observations {
		if _, err := exactObject(raw, []string{"name", "kind", "size"}, "name", "kind", "size"); err != nil {
			return nil, nil, err
		}
		var observation attestation.ArtifactMetadata
		if json.Unmarshal(raw, &observation) != nil || !subjects[observation.Name] || metadata[observation.Name].Name != "" ||
			observation.Size < 0 || (observation.Kind != "file" && observation.Kind != "directory" && observation.Kind != "symlink") {
			return nil, nil, policyError("invalid recorder artifact kind, count or association")
		}
		metadata[observation.Name] = observation
	}
	var source *attestation.SourceAssertion
	if raw, exists := external["assertedSource"]; exists {
		if _, err := exactObject(raw, []string{"uri", "commit", "evidence"}, "uri", "commit", "evidence"); err != nil {
			return nil, nil, err
		}
		var value attestation.SourceAssertion
		if json.Unmarshal(raw, &value) != nil || value.Evidence != "caller_assertion" || !publicValue(value.URI) || len(parsed.Dependencies) != 1 {
			return nil, nil, policyError("invalid declared source assertion")
		}
		commit, err := hex.DecodeString(value.Commit)
		if err != nil || (len(commit) != 20 && len(commit) != 32) || strings.ToLower(value.Commit) != value.Commit ||
			attestation.SanitizeObservedRemote(value.URI) != value.URI {
			return nil, nil, policyError("declared source requires a canonical public URI and full commit")
		}
		var evidence string
		_ = json.Unmarshal(parsed.Dependencies[0].Annotations["buildtrace.evidence"], &evidence)
		if parsed.Dependencies[0].URI != value.URI || parsed.Dependencies[0].Digest["gitCommit"] != value.Commit || evidence != "caller_assertion" {
			return nil, nil, policyError("declared dependency/source assertion is inconsistent")
		}
		source = &value
	} else if len(parsed.Dependencies) != 0 {
		return nil, nil, policyError("recorder v1 does not infer undeclared dependencies")
	}
	return metadata, source, nil
}
