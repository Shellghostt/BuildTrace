package hashing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootedHashPreservesM2CanonicalBytesAndPreventsParentEscape(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "tree"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tree", "app"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, path := range []string{"tree", "tree/app"} {
		ordinary, err := Hash(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		anchored, err := HashRoot(root, filepath.FromSlash(path))
		if err != nil || anchored != ordinary {
			t.Fatal("rooted canonical bytes changed", path, ordinary, anchored, err)
		}
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private"), []byte("do-not-open"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skip("platform does not permit symlink creation:", err)
	}
	if _, err := HashRoot(root, "escape/private"); err == nil {
		t.Fatal("rooted hash followed an escaping parent")
	}
	linkOrdinary, err := Hash(filepath.Join(dir, "escape"))
	if err != nil {
		t.Fatal(err)
	}
	linkRooted, err := HashRoot(root, "escape")
	if err != nil || linkRooted != linkOrdinary || linkRooted.Kind != "symlink" {
		t.Fatal("terminal symlink was followed or changed canonical bytes", err)
	}
}
