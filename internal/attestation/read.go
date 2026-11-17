package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/shellghostt/buildtrace/pkg/intoto"
)

const MaxInputBytes = 16 << 20
const MaxNestingDepth = 64
const MaxJSONTokens = 200000

// Inspection reports parsing and formatting only. Raw retains compatible
// extensions; neither its content nor the summary is authenticated.
type Inspection struct {
	Scope            string                      `json:"scope"`
	Status           string                      `json:"status"`
	BuildType        string                      `json:"buildType"`
	BuilderID        string                      `json:"builderId"`
	Subjects         []intoto.ResourceDescriptor `json:"subjects"`
	Dependencies     []intoto.ResourceDescriptor `json:"dependencies"`
	Metadata         *intoto.BuildMetadata       `json:"metadata,omitempty"`
	RecorderContract bool                        `json:"recorderContract"`
	Raw              json.RawMessage             `json:"statement"`
}

// Read accepts exactly one bounded, terminated JSONL record without executing
// anything or looking up schemas, artifacts, checkout metadata or environment.
func Read(reader io.Reader) (Inspection, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return Inspection{}, err
	}
	if len(data) > MaxInputBytes {
		return Inspection{}, invalid("statement exceeds 16 MiB")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return Inspection{}, invalid("expected exactly one LF-terminated JSON statement line")
	}
	line := bytes.TrimSuffix(data[:len(data)-1], []byte{'\r'})
	if !utf8.Valid(line) {
		return Inspection{}, invalid("statement must be UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	tokens := 0
	if err := checkJSON(decoder, 0, &tokens); err != nil {
		return Inspection{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Inspection{}, invalid("trailing or malformed JSON")
	}

	var statement intoto.Statement
	if err := knownFields(line, &statement, "_type", "predicateType", "predicate"); err != nil {
		return Inspection{}, err
	}
	if statement.Type != intoto.StatementType {
		return Inspection{}, invalid("unsupported statement type; expected in-toto Statement v1")
	}
	if statement.PredicateType != intoto.ProvenanceType {
		return Inspection{}, invalid("unsupported predicate type; expected SLSA provenance v1")
	}
	// Decode resource descriptors independently with exact, case-sensitive keys.
	root, _ := object(line)
	subjects, err := resources(root["subject"], true)
	if err != nil {
		return Inspection{}, err
	}
	predicate, err := object(statement.Predicate)
	if err != nil {
		return Inspection{}, err
	}
	var definition intoto.BuildDefinition
	if err := knownFields(predicate["buildDefinition"], &definition, "buildType", "externalParameters", "internalParameters"); err != nil {
		return Inspection{}, err
	}
	if !publicURI(definition.BuildType) {
		return Inspection{}, invalid("buildDefinition.buildType must be a nonempty URI")
	}
	external, err := object(definition.ExternalParameters)
	if err != nil || len(external) == 0 {
		return Inspection{}, invalid("buildDefinition.externalParameters must be a nonempty object")
	}
	if definition.InternalParameters != nil {
		if _, err := object(definition.InternalParameters); err != nil {
			return Inspection{}, err
		}
	}
	definitionObject, _ := object(predicate["buildDefinition"])
	dependencies, err := optionalResources(definitionObject["resolvedDependencies"])
	if err != nil {
		return Inspection{}, err
	}
	details, err := object(predicate["runDetails"])
	if err != nil {
		return Inspection{}, err
	}
	var builder intoto.Builder
	if err := knownFields(details["builder"], &builder, "id", "version"); err != nil {
		return Inspection{}, err
	}
	if !publicURI(builder.ID) {
		return Inspection{}, invalid("runDetails.builder.id must be a nonempty URI")
	}
	for key, value := range builder.Version {
		if !publicString(key) || !publicString(value) {
			return Inspection{}, invalid("invalid builder version")
		}
	}
	builderObject, _ := object(details["builder"])
	if _, err := optionalResources(builderObject["builderDependencies"]); err != nil {
		return Inspection{}, err
	}
	if _, err := optionalResources(details["byproducts"]); err != nil {
		return Inspection{}, err
	}
	var metadata *intoto.BuildMetadata
	if raw, exists := details["metadata"]; exists {
		var value intoto.BuildMetadata
		if err := knownFields(raw, &value, "invocationId", "startedOn", "finishedOn"); err != nil {
			return Inspection{}, err
		}
		if value.InvocationID != "" && !publicString(value.InvocationID) {
			return Inspection{}, invalid("invalid invocation ID")
		}
		if value.StartedOn != nil && (value.StartedOn.UTC().Year() < 1 || value.StartedOn.UTC().Year() > 9999) ||
			value.FinishedOn != nil && (value.FinishedOn.UTC().Year() < 1 || value.FinishedOn.UTC().Year() > 9999) {
			return Inspection{}, invalid("build times are out of range")
		}
		if value.StartedOn != nil && value.FinishedOn != nil && value.FinishedOn.Before(*value.StartedOn) {
			return Inspection{}, invalid("finishedOn precedes startedOn")
		}
		metadata = &value
	}
	return Inspection{Scope: "unsigned_statement", Status: "inspected", BuildType: definition.BuildType,
		BuilderID: builder.ID, Subjects: subjects, Dependencies: dependencies, Metadata: metadata,
		RecorderContract: definition.BuildType == BuildType, Raw: append(json.RawMessage(nil), line...)}, nil
}

// checkJSON rejects exact duplicate keys and bounds nesting/token work before
// allocating typed structures. JSON numbers are never converted to float64.
func checkJSON(decoder *json.Decoder, depth int, count *int) error {
	if depth > MaxNestingDepth {
		return invalid("JSON exceeds 64 nesting levels")
	}
	token, err := boundedToken(decoder, count)
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := boundedToken(decoder, count)
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return invalid("duplicate or invalid JSON key")
			}
			seen[key] = true
			if err := checkJSON(decoder, depth+1, count); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkJSON(decoder, depth+1, count); err != nil {
				return err
			}
		}
	default:
		return invalid("malformed JSON")
	}
	closing, err := boundedToken(decoder, count)
	if err != nil || (delimiter == '{' && closing != json.Delim('}')) || (delimiter == '[' && closing != json.Delim(']')) {
		return invalid("malformed JSON")
	}
	return nil
}

func boundedToken(decoder *json.Decoder, count *int) (json.Token, error) {
	*count = *count + 1
	if *count > MaxJSONTokens {
		return nil, invalid("JSON exceeds 200000 tokens")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, invalid("malformed JSON")
	}
	return token, nil
}

func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, invalid("expected a JSON object")
	}
	return fields, nil
}

// Only exact standard keys enter Go's case-insensitive struct decoder. Unknown
// compatible keys are retained in Raw rather than overriding a critical field.
func knownFields(raw json.RawMessage, destination any, names ...string) error {
	fields, err := object(raw)
	if err != nil {
		return err
	}
	filtered := make(map[string]json.RawMessage, len(names))
	for _, name := range names {
		if value, exists := fields[name]; exists {
			filtered[name] = value
		}
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		return invalid("invalid standard field type")
	}
	return nil
}

func optionalResources(raw json.RawMessage) ([]intoto.ResourceDescriptor, error) {
	if raw == nil {
		return []intoto.ResourceDescriptor{}, nil
	}
	return resources(raw, false)
}

func resources(raw json.RawMessage, subject bool) ([]intoto.ResourceDescriptor, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil || len(entries) > MaxArtifacts || subject && len(entries) == 0 {
		return nil, invalid("invalid or oversized resource array")
	}
	result := make([]intoto.ResourceDescriptor, 0, len(entries))
	for _, rawEntry := range entries {
		var resource intoto.ResourceDescriptor
		if err := knownFields(rawEntry, &resource, "name", "uri", "digest", "downloadLocation", "mediaType", "content", "annotations"); err != nil {
			return nil, err
		}
		for _, value := range []string{resource.Name, resource.URI, resource.DownloadLocation, resource.MediaType} {
			if value != "" && !publicString(value) {
				return nil, invalid("invalid resource identifier")
			}
		}
		if resource.URI == "" && len(resource.Digest) == 0 && resource.Content == "" || subject && len(resource.Digest) == 0 {
			return nil, invalid("resource requires identifying data; subjects require a digest")
		}
		for algorithm, value := range resource.Digest {
			if !publicString(algorithm) || !publicString(value) {
				return nil, invalid("invalid resource digest")
			}
			if algorithm == "sha256" {
				if _, err := hex.DecodeString(value); err != nil || len(value) != 64 {
					return nil, invalid("invalid SHA-256 digest")
				}
			}
		}
		if resource.Content != "" {
			encoding := base64.StdEncoding
			if strings.ContainsAny(resource.Content, "-_") {
				encoding = base64.URLEncoding
			}
			if !strings.HasSuffix(resource.Content, "=") {
				encoding = encoding.WithPadding(base64.NoPadding)
			}
			if _, err := encoding.DecodeString(resource.Content); err != nil {
				return nil, invalid("invalid base64 resource content")
			}
		}
		result = append(result, resource)
	}
	return result, nil
}

func publicURI(value string) bool {
	if !publicString(value) || strings.TrimSpace(value) != value {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.IsAbs()
}
