// Package hashing implements streaming SHA-256 and canonical directory digests.
package hashing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const BufferSize = 1 << 20
const MaxDirectoryEntries = 100000

var ErrChanged = errors.New("artifact changed while hashing; stop writers and try again")

type Result struct {
	Kind   string
	SHA256 string
	Size   int64
}

// Hash never follows an artifact symlink. Directory contents are opened through
// an os.Root so that a replaced child cannot redirect a read outside the tree.
func Hash(path string) (Result, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return Result{}, err
		}
		target = filepath.ToSlash(target)
		if !utf8.ValidString(target) {
			return Result{}, errors.New("symlink target is not UTF-8")
		}
		h := sha256.New()
		_, _ = io.WriteString(h, "buildtrace-symlink-v1\x00")
		writeString(h, target)
		return Result{Kind: "symlink", SHA256: hex.EncodeToString(h.Sum(nil)), Size: int64(len(target))}, nil
	}
	buffer := make([]byte, BufferSize)
	if info.Mode().IsRegular() {
		f, err := os.Open(path)
		if err != nil {
			return Result{}, err
		}
		defer func() { _ = f.Close() }()
		digest, size, err := hashFile(f, info, buffer)
		if err != nil {
			return Result{}, err
		}
		after, err := os.Lstat(path)
		if err != nil || !unchanged(info, after) {
			return Result{}, ErrChanged
		}
		return Result{Kind: "file", SHA256: hex.EncodeToString(digest), Size: size}, nil
	}
	if !info.IsDir() {
		return Result{}, errors.New("unsupported artifact type; expected file, directory or symlink")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return Result{}, ErrChanged
	}
	result, err := hashDirectory(root, buffer)
	if err != nil {
		return Result{}, err
	}
	after, err := os.Lstat(path)
	if err != nil || !unchanged(info, after) {
		return Result{}, ErrChanged
	}
	return result, nil
}

func hashFile(f *os.File, before fs.FileInfo, buffer []byte) ([]byte, int64, error) {
	opened, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, 0, ErrChanged
	}
	h := sha256.New()
	var size int64
	for {
		n, err := f.Read(buffer)
		if n > 0 {
			_, _ = h.Write(buffer[:n])
			size += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
	}
	after, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !unchanged(before, after) || size != before.Size() {
		return nil, 0, ErrChanged
	}
	return h.Sum(nil), size, nil
}

func unchanged(a, b fs.FileInfo) bool {
	return b != nil && os.SameFile(a, b) && a.Mode().Type() == b.Mode().Type() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

type entry struct {
	path string
	mode fs.FileMode
}

func hashDirectory(root *os.Root, buffer []byte) (Result, error) {
	entries := make([]entry, 0)
	directories := map[string]fs.FileInfo{}
	rootInfo, err := root.Stat(".")
	if err != nil {
		return Result{}, err
	}
	directories["."] = rootInfo
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		if !utf8.ValidString(path) || strings.Contains(path, "\\") {
			return errors.New("directory paths must be UTF-8 with forward slash separators")
		}
		if len(entries) >= MaxDirectoryEntries {
			return fmt.Errorf("directory exceeds %d entries", MaxDirectoryEntries)
		}
		entries = append(entries, entry{path: path, mode: d.Type()})
		if d.IsDir() {
			info, err := root.Lstat(path)
			if err != nil {
				return err
			}
			directories[path] = info
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	h := sha256.New()
	_, _ = io.WriteString(h, "buildtrace-directory-v1\x00")
	var size int64
	for _, e := range entries {
		info, err := root.Lstat(e.path)
		if err != nil {
			return Result{}, err
		}
		if info.Mode().Type() != e.mode {
			return Result{}, ErrChanged
		}
		switch {
		case info.Mode().IsRegular():
			f, err := root.Open(e.path)
			if err != nil {
				return Result{}, err
			}
			digest, n, err := hashFile(f, info, buffer)
			_ = f.Close()
			if err != nil {
				return Result{}, fmt.Errorf("%s: %w", e.path, err)
			}
			after, err := root.Lstat(e.path)
			if err != nil || !unchanged(info, after) {
				return Result{}, ErrChanged
			}
			_, _ = h.Write([]byte{'f'})
			writeString(h, e.path)
			writeUint(h, uint64(n))
			_, _ = h.Write(digest)
			size += n
		case info.IsDir():
			_, _ = h.Write([]byte{'d'})
			writeString(h, e.path)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := root.Readlink(e.path)
			if err != nil {
				return Result{}, err
			}
			target = filepath.ToSlash(target)
			if !utf8.ValidString(target) {
				return Result{}, errors.New("symlink target is not UTF-8")
			}
			_, _ = h.Write([]byte{'l'})
			writeString(h, e.path)
			writeString(h, target)
			size += int64(len(target))
		default:
			return Result{}, fmt.Errorf("%s: unsupported artifact type", e.path)
		}
	}
	for path, before := range directories {
		after, err := root.Lstat(path)
		if err != nil || !unchanged(before, after) {
			return Result{}, fmt.Errorf("directory %s: %w", path, ErrChanged)
		}
	}
	return Result{Kind: "directory", SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}, nil
}

func writeUint(h hash.Hash, value uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	_, _ = h.Write(buf[:])
}
func writeString(h hash.Hash, value string) {
	writeUint(h, uint64(len(value)))
	_, _ = io.WriteString(h, value)
}
