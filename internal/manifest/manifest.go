// Package manifest defines the buildtrace.json format.
//
// The manifest is the human-readable, unsigned record of a build: where it
// came from, who built it, with which tools, and which artifacts it
// produced. It is deliberately not the in-toto statement: that arrives in
// M3 and is built from this data.
//
// The format is deterministic. The same repository, the same artifacts and
// the same declared timestamp produce the same bytes, which is what makes a
// manifest reviewable in a pull request.
package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shellghostt/buildtrace/internal/metadata"
)

// SchemaVersion is the version of the manifest format this build produces.
//
// It is written into every manifest and enforced by the M2 verifier.
const SchemaVersion = 1

// Manifest is one build.
type Manifest struct {
	// SchemaVersion is the version of this format.
	SchemaVersion int `json:"schemaVersion"`
	// BuiltAt is when the build finished. It is the only field that changes
	// between two runs over the same inputs, and it can be pinned with
	// --built-at or SOURCE_DATE_EPOCH.
	BuiltAt time.Time `json:"builtAt"`
	// Source is the repository the build came from.
	Source metadata.Source `json:"source"`
	// Builder is who ran the build.
	Builder metadata.Builder `json:"builder"`
	// Toolchain is which tools took part.
	Toolchain metadata.Toolchain `json:"toolchain"`
	// Artifacts is what the build produced.
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is a file, directory or symlink produced by the build.
type Artifact struct {
	// Kind is file, directory or symlink. An omitted kind means file in v1.
	Kind string `json:"kind,omitempty"`
	// Name is the file name.
	Name string `json:"name"`
	// Path is the location of the file, relative to the repository root
	// when the file is inside it, with forward slashes.
	Path string `json:"path"`
	// Size is the byte count. Directories sum file bytes and normalized link target bytes.
	Size int64 `json:"size"`
	// Digest is the raw file SHA-256 or the canonical directory/symlink digest.
	// Legacy M1 manifests omit it and cannot pass M2 verification.
	Digest *Digest `json:"digest,omitempty"`
}

// Digest holds the digests of an artifact.
type Digest struct {
	// SHA256 is the lowercase hexadecimal SHA-256 digest.
	SHA256 string `json:"sha256"`
}

// New builds a manifest with the schema version and the artifacts in place.
//
// The artifacts are sorted by path so that the order of the command line
// does not change the output.
func New(builtAt time.Time, source metadata.Source, builder metadata.Builder, toolchain metadata.Toolchain, artifacts []Artifact) Manifest {
	sorted := make([]Artifact, len(artifacts))
	copy(sorted, artifacts)
	sortArtifacts(sorted)

	return Manifest{
		SchemaVersion: SchemaVersion,
		BuiltAt:       builtAt.UTC().Truncate(time.Second),
		Source:        source,
		Builder:       builder,
		Toolchain:     toolchain,
		Artifacts:     sorted,
	}
}

// Marshal serialises the manifest.
//
// The output is indented with two spaces, ends with a newline and has a
// stable field order, because the field order of a Go struct is stable and
// because a manifest is meant to be read in a diff.
func (m Manifest) Marshal() ([]byte, error) {
	if m.Artifacts == nil {
		m.Artifacts = []Artifact{}
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(m); err != nil {
		return nil, fmt.Errorf("encode the manifest: %w", err)
	}
	return buffer.Bytes(), nil
}
