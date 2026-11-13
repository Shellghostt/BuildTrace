package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteTheGoldenFile regenerates the golden file.
//
// It is skipped unless BUILDTRACE_WRITE_GOLDEN is set, so that an ordinary
// test run never rewrites the file it is supposed to compare against.
func TestWriteTheGoldenFile(t *testing.T) {
	if os.Getenv("BUILDTRACE_WRITE_GOLDEN") == "" {
		t.Skip("set BUILDTRACE_WRITE_GOLDEN to regenerate the golden file")
	}

	encoded, err := fixedManifest().Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join("testdata", "manifest.golden.json")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatalf("write the golden file: %v", err)
	}
}
