package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileUsesRawSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	for _, contents := range []string{"", "hello", string(make([]byte, BufferSize+17))} {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := Hash(path)
		if err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256([]byte(contents))
		if got.Kind != "file" || got.Size != int64(len(contents)) || got.SHA256 != hex.EncodeToString(want[:]) {
			t.Fatal(got)
		}
	}
}

func TestDirectoryGoldenIgnoresCreationOrderAndMetadata(t *testing.T) {
	// Independently computed with Python hashlib and big-endian struct.pack.
	const expected = "af7be037cf7f2ef0beef5b69314747e532b6ce13738578a8f8f362c105f98727"
	for _, reverse := range []bool{false, true} {
		root := t.TempDir()
		entries := []struct{ path, content string }{{"a-", "dash"}, {"a/x", "hello"}, {"é.txt", "unicode"}}
		if reverse {
			entries[0], entries[2] = entries[2], entries[0]
		}
		for _, e := range entries {
			p := filepath.Join(root, filepath.FromSlash(e.path))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(e.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(p, time.Unix(1, 0), time.Unix(2, 0)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(root, "empty"), 0o700); err != nil {
			t.Fatal(err)
		}
		got, err := Hash(root)
		if err != nil {
			t.Fatal(err)
		}
		if got.SHA256 != expected || got.Size != 16 || got.Kind != "directory" {
			t.Fatal(got)
		}
		if err := os.Remove(filepath.Join(root, "empty")); err != nil {
			t.Fatal(err)
		}
		changed, err := Hash(root)
		if err != nil {
			t.Fatal(err)
		}
		if changed.SHA256 == got.SHA256 {
			t.Fatal("empty directory was not recorded")
		}
	}
}

func TestSymlinksAreRecordedWithoutFollowingTargets(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	file := filepath.Join(outside, "file")
	if err := os.WriteFile(file, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	first, err := Hash(root)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := Hash(link)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.Kind != "symlink" {
		t.Fatal(terminal)
	}
	if err := os.WriteFile(file, []byte("after and much larger"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := Hash(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("followed symlink target", first, second)
	}
	// Remove only this test's file: the symlink must work while dangling.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(outside); err != nil {
		t.Fatal(err)
	}
	dangling, err := Hash(link)
	if err != nil || dangling != terminal {
		t.Fatal("dangling link was followed", dangling, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("different-target", link); err != nil {
		t.Fatal(err)
	}
	changed, err := Hash(root)
	if err != nil {
		t.Fatal(err)
	}
	if changed.SHA256 == first.SHA256 {
		t.Fatal("target text not recorded")
	}
}
