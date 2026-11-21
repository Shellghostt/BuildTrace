package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// HashRoot applies the unchanged M2 canonical bytes through a caller-opened
// root. Parent replacements cannot redirect signed verification outside it.
// A terminal symlink is hashed as its target string, never followed.
func HashRoot(root *os.Root, path string) (Result, error) {
	before, err := root.Lstat(path)
	if err != nil {
		return Result{}, err
	}
	if !os.SameFile(before, before) {
		return Result{}, ErrChanged
	}
	if before.Mode()&os.ModeSymlink != 0 {
		target, err := root.Readlink(path)
		if err != nil {
			return Result{}, err
		}
		after, err := root.Lstat(path)
		if err != nil || !unchanged(before, after) {
			return Result{}, ErrChanged
		}
		target = filepath.ToSlash(target)
		if !utf8.ValidString(target) {
			return Result{}, errors.New("symlink target is not UTF-8")
		}
		h := sha256.New()
		_, _ = h.Write([]byte("buildtrace-symlink-v1\x00"))
		writeString(h, target)
		return Result{Kind: "symlink", Size: int64(len(target)), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
	}
	buffer := make([]byte, BufferSize)
	var result Result
	if before.Mode().IsRegular() {
		f, err := root.Open(path)
		if err != nil {
			return Result{}, err
		}
		digest, size, err := hashFile(f, before, buffer)
		_ = f.Close()
		if err != nil {
			return Result{}, err
		}
		result = Result{Kind: "file", Size: size, SHA256: hex.EncodeToString(digest)}
	} else if before.IsDir() {
		child, err := root.OpenRoot(path)
		if err != nil {
			return Result{}, err
		}
		opened, err := child.Stat(".")
		if err != nil || !os.SameFile(before, opened) {
			_ = child.Close()
			return Result{}, ErrChanged
		}
		result, err = hashDirectory(child, buffer)
		_ = child.Close()
		if err != nil {
			return Result{}, err
		}
	} else {
		return Result{}, errors.New("unsupported artifact type; expected file, directory or symlink")
	}
	after, err := root.Lstat(path)
	if err != nil || !unchanged(before, after) {
		return Result{}, ErrChanged
	}
	return result, nil
}
