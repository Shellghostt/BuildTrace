package attestation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactSelectionsUseUniqueRelativeNamesAndM2Digests(t *testing.T) {
	root := t.TempDir()
	for _, item := range []struct{ path, contents string }{{"one/app", "hello"}, {"two/app", "hello"}, {"bundle/a-", "dash"}, {"bundle/a/x", "hello"}, {"bundle/é.txt", "unicode"}} {
		path := filepath.Join(root, filepath.FromSlash(item.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(item.contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "bundle", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Collect(root, []string{"one/app", "two/app", "bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "one/app" || got[1].Name != "two/app" || got[0].SHA256 != helloSHA256 || got[1].SHA256 != helloSHA256 || got[2].SHA256 != directorySHA256 || got[2].Size != 16 {
		t.Fatal(got)
	}
	if _, err := Collect(root, []string{"one/app", "one/../one/app"}); !IsInputError(err) {
		t.Fatal("colliding normalized names were accepted", err)
	}
	if _, err := Collect(root, []string{filepath.Join(t.TempDir(), "app")}); !IsInputError(err) {
		t.Fatal("outside artifact was accepted", err)
	}
}

func TestTerminalSymlinkIsHashedAndParentEscapeIsRejected(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "app"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	got, err := Collect(root, []string{"link"})
	if err != nil || len(got) != 1 || got[0].Kind != "symlink" {
		t.Fatal(got, err)
	}
	if _, err := Collect(root, []string{"link/app"}); !IsInputError(err) {
		t.Fatal("parent symlink escaped the root", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "app"), []byte("different contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := Collect(root, []string{"link"})
	if err != nil || again[0] != got[0] {
		t.Fatal("terminal link followed its target", err)
	}
}
