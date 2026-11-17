package hashing

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Recording reuses this M2 guard. Change the file after the metadata observation
// and before hashing to exercise rejection without a racing writer or sleeps.
func TestRecordingRejectsFileChangesAfterObservation(t *testing.T) {
	for _, change := range []string{"size", "same-size write", "replacement"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "artifact")
			if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
				t.Fatal(err)
			}
			observedTime := time.Unix(1, 0)
			if err := os.Chtimes(path, observedTime, observedTime); err != nil {
				t.Fatal(err)
			}
			before, err := observeArtifact(path)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "size":
				if err := os.WriteFile(path, []byte("different size"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "same-size write":
				if err := os.WriteFile(path, []byte("world"), 0o644); err != nil {
					t.Fatal(err)
				}
				changedTime := observedTime.Add(time.Second)
				if err := os.Chtimes(path, changedTime, changedTime); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				// Allocate the replacement while the original exists, keeping file
				// identity distinct even on filesystems that reuse deleted IDs.
				replacement := filepath.Join(directory, "replacement")
				if err := os.WriteFile(replacement, []byte("hello"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(replacement, observedTime, observedTime); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			if _, _, err := hashFile(file, before, make([]byte, BufferSize)); !errors.Is(err, ErrChanged) {
				t.Fatalf("changed artifact was accepted: %v", err)
			}
		})
	}
}
