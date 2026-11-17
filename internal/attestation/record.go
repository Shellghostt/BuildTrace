// Package attestation constructs and inspects unsigned artifact observations.
// It does not execute builds, authenticate metadata or verify signatures.
package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shellghostt/buildtrace/pkg/intoto"
)

const BuildType = "https://github.com/Shellghostt/BuildTrace/blob/main/docs/build-types/record/v1.md"
const DefaultBuilderID = "https://github.com/Shellghostt/BuildTrace#local-recorder"
const MaxArtifacts = 1000
const MaxIdentifierBytes = 4096

// InputError identifies invalid public input without including its raw contents
// in diagnostics. URI credentials and malformed identifiers must not be echoed.
type InputError struct {
	Reason string
}

func (e *InputError) Error() string { return e.Reason }

func invalid(reason string) error { return &InputError{Reason: reason} }

// Observation contains recomputed bytes and a canonical name, not a build claim.
type Observation struct {
	Name   string
	Kind   string
	Size   int64
	SHA256 string
}

type Checkout struct {
	URI    string `json:"uri,omitempty"`
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty"`
}

type Recorder struct {
	Version    string `json:"version"`
	GoVersion  string `json:"goVersion"`
	GitVersion string `json:"gitVersion,omitempty"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

type SourceAssertion struct {
	URI      string `json:"uri"`
	Commit   string `json:"commit"`
	Evidence string `json:"evidence"`
}

type ArtifactSelection struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ArtifactMetadata struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Size int64  `json:"size"`
}

type ExternalParameters struct {
	Artifacts      []ArtifactSelection `json:"artifacts"`
	AssertedSource *SourceAssertion    `json:"assertedSource,omitempty"`
}

type InternalParameters struct {
	ObservedCheckout  Checkout           `json:"observedCheckout"`
	Recorder          Recorder           `json:"recorder"`
	ObservedArtifacts []ArtifactMetadata `json:"observedArtifacts"`
}

// Options contains only defined observations and explicit public caller inputs.
// Empty time inputs intentionally do not consult a clock or an environment variable.
type Options struct {
	Artifacts    []Observation
	Checkout     Checkout
	Recorder     Recorder
	BuilderID    string
	InvocationID string
	SourceURI    string
	SourceCommit string
	StartedOn    string
	FinishedOn   string
}

// Build creates a compact unsigned statement. Its default ID hashes the complete
// canonical record with invocationId omitted; no randomness or current time enters it.
func Build(options Options) ([]byte, error) {
	if len(options.Artifacts) == 0 || len(options.Artifacts) > MaxArtifacts {
		return nil, invalid("select between 1 and 1000 artifacts")
	}
	if !fullCommit(options.Checkout.Commit) {
		return nil, invalid("observed checkout must have a full commit ID")
	}
	options.Checkout.Commit = lowerHex(options.Checkout.Commit)
	options.Checkout.URI = SanitizeObservedRemote(options.Checkout.URI)
	for _, value := range []string{options.Recorder.Version, options.Recorder.GoVersion, options.Recorder.OS, options.Recorder.Arch} {
		if !publicString(value) {
			return nil, invalid("recorder metadata must contain bounded public identifiers")
		}
	}
	if options.Recorder.GitVersion != "" && !publicString(options.Recorder.GitVersion) {
		return nil, invalid("invalid observed git version")
	}
	builder := DefaultBuilderID
	if options.BuilderID != "" {
		var err error
		builder, err = sanitizeLabel(options.BuilderID, true)
		if err != nil {
			return nil, invalid("builder ID must be a public network URI or opaque URN")
		}
	}
	metadata := &intoto.BuildMetadata{}
	if (options.StartedOn == "") != (options.FinishedOn == "") {
		return nil, invalid("started-on and finished-on must be supplied together")
	}
	if options.StartedOn != "" {
		start, err := claimedTime(options.StartedOn)
		if err != nil {
			return nil, invalid("started-on must be an in-range RFC3339 timestamp")
		}
		finish, err := claimedTime(options.FinishedOn)
		if err != nil || finish.Before(start) {
			return nil, invalid("finished-on must be an in-range RFC3339 timestamp no earlier than started-on")
		}
		metadata.StartedOn, metadata.FinishedOn = &start, &finish
	}

	artifacts := append([]Observation(nil), options.Artifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	subjects := make([]intoto.ResourceDescriptor, 0, len(artifacts))
	external := ExternalParameters{Artifacts: make([]ArtifactSelection, 0, len(artifacts))}
	internal := InternalParameters{ObservedCheckout: options.Checkout, Recorder: options.Recorder,
		ObservedArtifacts: make([]ArtifactMetadata, 0, len(artifacts))}
	for i, artifact := range artifacts {
		if !artifactName(artifact.Name) || (i > 0 && artifacts[i-1].Name == artifact.Name) {
			return nil, invalid("artifact names must be unique canonical relative paths")
		}
		if !sha256Hex(artifact.SHA256) || artifact.Size < 0 || (artifact.Kind != "file" && artifact.Kind != "directory" && artifact.Kind != "symlink") {
			return nil, invalid("artifact observations require a kind, byte count and SHA-256")
		}
		subjects = append(subjects, intoto.ResourceDescriptor{Name: artifact.Name,
			Digest: map[string]string{"sha256": artifact.SHA256}})
		external.Artifacts = append(external.Artifacts, ArtifactSelection{Name: artifact.Name, Path: artifact.Name})
		internal.ObservedArtifacts = append(internal.ObservedArtifacts, ArtifactMetadata{Name: artifact.Name, Kind: artifact.Kind, Size: artifact.Size})
	}
	var dependencies []intoto.ResourceDescriptor
	if (options.SourceURI == "") != (options.SourceCommit == "") {
		return nil, invalid("source-uri and source-commit must be supplied together")
	}
	if options.SourceURI != "" {
		uri, err := sanitizeSource(options.SourceURI)
		if err != nil || !fullCommit(options.SourceCommit) {
			return nil, invalid("asserted source requires a public network URI and full commit ID")
		}
		commit := lowerHex(options.SourceCommit)
		external.AssertedSource = &SourceAssertion{URI: uri, Commit: commit, Evidence: "caller_assertion"}
		dependencies = []intoto.ResourceDescriptor{{URI: uri, Digest: map[string]string{"gitCommit": commit},
			Annotations: map[string]json.RawMessage{"buildtrace.evidence": json.RawMessage(`"caller_assertion"`)}}}
	}
	externalJSON, err := intoto.MarshalLine(external)
	if err != nil {
		return nil, err
	}
	internalJSON, err := intoto.MarshalLine(internal)
	if err != nil {
		return nil, err
	}
	provenance := intoto.Provenance{BuildDefinition: intoto.BuildDefinition{BuildType: BuildType,
		ExternalParameters: externalJSON, InternalParameters: internalJSON, ResolvedDependencies: dependencies},
		RunDetails: intoto.RunDetails{Builder: intoto.Builder{ID: builder}, Metadata: metadata}}
	statement := intoto.Statement{Type: intoto.StatementType, Subject: subjects, PredicateType: intoto.ProvenanceType}
	encode := func() ([]byte, error) {
		predicate, err := intoto.MarshalLine(provenance)
		if err != nil {
			return nil, err
		}
		statement.Predicate = predicate
		return intoto.MarshalLine(statement)
	}
	if options.InvocationID != "" {
		metadata.InvocationID, err = sanitizeLabel(options.InvocationID, false)
		if err != nil {
			return nil, invalid("invocation ID must be a bounded public identifier")
		}
	} else {
		withoutID, err := encode()
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(withoutID)
		metadata.InvocationID = fmt.Sprintf("sha256:%x", digest)
	}
	encoded, err := encode()
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxInputBytes {
		return nil, invalid("statement exceeds 16 MiB")
	}
	return encoded, nil
}

func claimedTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	parsed = parsed.UTC()
	if err != nil || parsed.Year() < 1 || parsed.Year() > 9999 {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}

func publicString(value string) bool {
	if value == "" || len(value) > MaxIdentifierBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func fullCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(value string) bool {
	return len(value) == 64 && fullCommit(value) && value == lowerHex(value)
}

func lowerHex(value string) string {
	decoded, _ := hex.DecodeString(value)
	return hex.EncodeToString(decoded)
}
