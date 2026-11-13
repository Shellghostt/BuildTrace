package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellghostt/buildtrace/internal/metadata"
)

// fixedManifest builds the manifest the golden file describes.
//
// Everything in it is fixed, including the builder and the toolchain, so
// that the golden file does not change when the machine changes.
func fixedManifest() Manifest {
	return New(
		time.Date(2026, 11, 13, 9, 58, 0, 0, time.UTC),
		metadata.Source{
			URI:    "git+https://github.com/shellghostt/buildtrace",
			Commit: "0123456789abcdef0123456789abcdef01234567",
			Dirty:  false,
		},
		metadata.Builder{
			ID:   "https://github.com/shellghostt/buildtrace/.github/workflows/release.yml",
			Host: "builder-01",
			OS:   "linux",
			Arch: "amd64",
		},
		metadata.Toolchain{
			Go:  "1.23.4",
			Git: "2.45.1",
		},
		[]Artifact{
			{Name: "app", Path: "dist/app", Size: 1024},
			{Name: "app.sig", Path: "dist/app.sig", Size: 64},
		},
	)
}

func TestMarshalMatchesTheGoldenFile(t *testing.T) {
	encoded, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "manifest.golden.json"))
	if err != nil {
		t.Fatalf("read the golden file: %v", err)
	}

	if string(encoded) != string(golden) {
		t.Fatalf("the manifest does not match the golden file.\n--- got ---\n%s\n--- want ---\n%s",
			encoded, golden)
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	first, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := fixedManifest().Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("run %d produced different bytes", i)
		}
	}
}

func TestNewSortsTheArtifactsByPath(t *testing.T) {
	document := New(
		time.Date(2026, 11, 13, 9, 58, 0, 0, time.UTC),
		metadata.Source{},
		metadata.Builder{},
		metadata.Toolchain{},
		[]Artifact{
			{Name: "z", Path: "dist/z", Size: 1},
			{Name: "a", Path: "dist/a", Size: 2},
			{Name: "m", Path: "dist/m", Size: 3},
		},
	)

	if document.Artifacts[0].Path != "dist/a" ||
		document.Artifacts[1].Path != "dist/m" ||
		document.Artifacts[2].Path != "dist/z" {
		t.Fatalf("expected the artifacts to be sorted, got %v", document.Artifacts)
	}
}

func TestNewDoesNotChangeTheSliceItIsGiven(t *testing.T) {
	artifacts := []Artifact{
		{Name: "z", Path: "dist/z"},
		{Name: "a", Path: "dist/a"},
	}

	document := New(time.Now(), metadata.Source{}, metadata.Builder{}, metadata.Toolchain{}, artifacts)

	if artifacts[0].Path != "dist/z" {
		t.Fatal("the caller's slice was reordered")
	}
	if document.Artifacts[0].Path != "dist/a" {
		t.Fatal("the manifest was not sorted")
	}
}

func TestNewNormalisesTheTimestamp(t *testing.T) {
	zone := time.FixedZone("UTC+5:30", 5*60*60+30*60)
	local := time.Date(2026, 11, 13, 15, 28, 0, 123456789, zone)

	document := New(local, metadata.Source{}, metadata.Builder{}, metadata.Toolchain{}, nil)

	if document.BuiltAt.Location() != time.UTC {
		t.Fatalf("expected the timestamp in UTC, got %s", document.BuiltAt.Location())
	}
	if document.BuiltAt.Nanosecond() != 0 {
		t.Fatalf("expected the timestamp truncated to the second, got %s", document.BuiltAt)
	}
	if document.BuiltAt.Hour() != 9 {
		t.Fatalf("expected 09:58 UTC, got %s", document.BuiltAt)
	}
}

func TestMarshalWritesAnEmptyArtifactListAsAnArray(t *testing.T) {
	document := New(time.Now(), metadata.Source{}, metadata.Builder{}, metadata.Toolchain{}, nil)

	encoded, err := document.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"artifacts": []`) {
		t.Fatalf("expected an empty array, got:\n%s", encoded)
	}
}

func TestTheManifestIsValidJSON(t *testing.T) {
	encoded, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("the manifest is not valid JSON: %v\n%s", err, encoded)
	}
	if decoded["schemaVersion"] != float64(SchemaVersion) {
		t.Fatalf("expected the schema version %d, got %v", SchemaVersion, decoded["schemaVersion"])
	}
}

func TestTheManifestEndsWithANewline(t *testing.T) {
	encoded, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasSuffix(string(encoded), "\n") {
		t.Fatal("expected the manifest to end with a newline")
	}
}

func TestM1ManifestsHaveNoDigest(t *testing.T) {
	// The digest is M2 work. A manifest that carries an empty digest would
	// look like a verified artifact, so the field is absent instead.
	encoded, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "digest") {
		t.Fatalf("expected no digest in an M1 manifest, got:\n%s", encoded)
	}
}
