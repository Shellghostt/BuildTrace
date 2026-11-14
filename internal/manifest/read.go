package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"
)

const MaxManifestBytes = 16 << 20

type ReadError struct{ Reason, Problem string }

func (e *ReadError) Error() string { return e.Problem }

// Read accepts one bounded v1 document with unambiguous keys. M1 documents
// without digests can still be serialized, but cannot pass M2 verification.
func Read(r io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, err
	}
	invalid := func(problem string) (Manifest, error) {
		return Manifest{}, &ReadError{Reason: "invalid_input", Problem: problem}
	}
	if len(data) > MaxManifestBytes {
		return invalid("manifest exceeds 16 MiB")
	}
	if !utf8.Valid(data) {
		return invalid("manifest must be UTF-8")
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(tokens, 0); err != nil {
		return invalid(err.Error())
	}
	if _, err := tokens.Token(); err != io.EOF {
		return invalid("expected one manifest JSON document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return invalid(err.Error())
	}
	if m.SchemaVersion != SchemaVersion {
		return Manifest{}, &ReadError{Reason: "unsupported_schema_version", Problem: fmt.Sprintf("unsupported schemaVersion %d; expected %d", m.SchemaVersion, SchemaVersion)}
	}
	if len(m.Artifacts) == 0 {
		return invalid("manifest must contain at least one artifact")
	}
	var required struct {
		Artifacts []struct {
			Size *int64 `json:"size"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &required); err != nil {
		return invalid(err.Error())
	}
	seen := map[string]bool{}
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		if required.Artifacts[i].Size == nil {
			return invalid("artifact size is required and must be an integer")
		}
		if strings.TrimSpace(a.Name) == "" || len(a.Name) > 4096 {
			return invalid("artifact name is empty or too long")
		}
		if a.Path == "" || len(a.Path) > 32768 || !utf8.ValidString(a.Path) || strings.ContainsAny(a.Path, "\\\x00") || path.Clean(a.Path) != a.Path || a.Path == ".." || strings.HasPrefix(a.Path, "../") {
			return invalid("artifact path must be canonical and use forward slashes")
		}
		if seen[a.Path] {
			return invalid("duplicate artifact path: " + a.Path)
		}
		seen[a.Path] = true
		if a.Kind == "" {
			a.Kind = "file"
		}
		if a.Kind != "file" && a.Kind != "directory" && a.Kind != "symlink" {
			return invalid("unknown artifact kind: " + a.Kind)
		}
		if a.Size < 0 {
			return invalid("artifact size must be non-negative")
		}
		if a.Digest == nil {
			return invalid("artifact " + a.Name + " has no digest; generate an M2 manifest")
		}
		digest, err := hex.DecodeString(a.Digest.SHA256)
		if err != nil || len(digest) != 32 || strings.ToLower(a.Digest.SHA256) != a.Digest.SHA256 {
			return invalid("artifact " + a.Name + " requires a lowercase SHA-256 digest")
		}
	}
	return m, nil
}

func checkValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("manifest nesting exceeds 64 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("expected JSON key")
			}
			folded := strings.ToLower(name)
			if seen[folded] {
				return fmt.Errorf("duplicate JSON field: %s", name)
			}
			seen[folded] = true
			if err := checkValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = d.Token()
	return err
}
