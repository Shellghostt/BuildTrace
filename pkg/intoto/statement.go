// Package intoto defines the in-toto Statement v1 and SLSA provenance v1 wire
// types. Reading these types needs only the standard library, not a schema server.
package intoto

import (
	"bytes"
	"encoding/json"
	"time"
)

const StatementType = "https://in-toto.io/Statement/v1"
const ProvenanceType = "https://slsa.dev/provenance/v1"

// Statement associates independently hashed subjects with a predicate.
// Predicate remains raw JSON because the in-toto format is predicate-neutral.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     json.RawMessage      `json:"predicate"`
}

// ResourceDescriptor is the upstream v1 resource shape. Optional fields support
// inspection of compatible provenance from other recorders without inventing data.
type ResourceDescriptor struct {
	Name             string                     `json:"name,omitempty"`
	URI              string                     `json:"uri,omitempty"`
	Digest           map[string]string          `json:"digest,omitempty"`
	DownloadLocation string                     `json:"downloadLocation,omitempty"`
	MediaType        string                     `json:"mediaType,omitempty"`
	Content          string                     `json:"content,omitempty"`
	Annotations      map[string]json.RawMessage `json:"annotations,omitempty"`
}

type Provenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   json.RawMessage      `json:"externalParameters"`
	InternalParameters   json.RawMessage      `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   *BuildMetadata       `json:"metadata,omitempty"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

type Builder struct {
	ID                  string               `json:"id"`
	Version             map[string]string    `json:"version,omitempty"`
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies,omitempty"`
}

type BuildMetadata struct {
	InvocationID string     `json:"invocationId,omitempty"`
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
}

// MarshalLine emits one compact JSON record, with fixed struct order, sorted map
// keys, no HTML escaping and a final LF. It does not sign or authenticate a record.
func MarshalLine(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
