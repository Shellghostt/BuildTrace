package manifest

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shellghostt/buildtrace/internal/metadata"
)

func validDocument(t *testing.T) string {
	t.Helper()
	m := New(time.Unix(0, 0), metadata.Source{}, metadata.Builder{}, metadata.Toolchain{}, []Artifact{{Name: "file", Path: "file", Size: 5, Digest: &Digest{SHA256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}}})
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestReadEnforcesVersionAndArtifactContract(t *testing.T) {
	valid := validDocument(t)
	if _, err := Read(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": 2`, 1),
		strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": 1.0`, 1),
		strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": true`, 1),
		strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": 1, "schemaVersion": 1`, 1),
		strings.Replace(valid, `"schemaVersion": 1`, `"schemaVersion": 99, "SchemaVersion": 1`, 1),
		strings.Replace(valid, `"path": "file"`, `"path": "../file"`, 1),
		strings.Replace(valid, `"path": "file"`, `"path": "a/../file"`, 1),
		strings.Replace(valid, `"size": 5`, `"size": -1`, 1),
		strings.Replace(valid, `"size": 5`, `"size": null`, 1),
		strings.Replace(valid, `"digest": {`, `"kind": "unknown", "digest": {`, 1),
		strings.Replace(valid, `"digest": {`, `"unknown": true, "digest": {`, 1),
		strings.Replace(valid, `"sha256": "2cf24`, `"sha256": "2CF24`, 1),
		valid + ` {}`, `null`, `[]`, `{}`, strings.Repeat(" ", MaxManifestBytes+1),
	} {
		if _, err := Read(strings.NewReader(invalid)); err == nil {
			t.Fatalf("accepted invalid document: %.160s", invalid)
		}
	}
	legacy, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(legacy)); err == nil {
		t.Fatal("M1 manifest without digests was accepted")
	}
	m, err := Read(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	m.Artifacts = append(m.Artifacts, m.Artifacts[0])
	duplicate, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate artifact path was accepted")
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"artifacts":[{"name":"file","path":"file","size":0,"digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}]}`))
	f.Add([]byte(`{"schemaVersion":2}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Read(bytes.NewReader(data))
		if err == nil {
			if m.SchemaVersion != 1 || len(m.Artifacts) == 0 {
				t.Fatal("incomplete manifest accepted")
			}
			for _, a := range m.Artifacts {
				if a.Digest == nil {
					t.Fatal("missing digest accepted")
				}
			}
		}
	})
}
