package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/shellghostt/buildtrace/internal/hashing"
)

// ArtifactError describes a problem with one artifact path.
//
// It is a value error, not a tool failure: the user pointed BuildTrace at
// something that cannot be an artifact.
type ArtifactError struct {
	// Path is the path as the user gave it.
	Path string
	// Problem explains what is wrong with it.
	Problem string
}

func (e *ArtifactError) Error() string {
	return fmt.Sprintf("artifact %q: %s", e.Path, e.Problem)
}

// CollectArtifacts describes the artifacts of a build.
//
// repoRoot is the root of the repository the build came from. It is used to
// make the recorded paths relative, so that a manifest does not leak the
// layout of the machine that produced it and so that the same build
// produces the same manifest on another machine.
//
// M2 hashes files, directories and terminal symlinks without following them.
func CollectArtifacts(repoRoot string, paths []string) ([]Artifact, error) {
	artifacts := make([]Artifact, 0, len(paths))
	seen := map[string]bool{}

	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return nil, &ArtifactError{Path: path, Problem: "the path is empty"}
		}

		absolute := path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(repoRoot, path)
		}
		absolute = filepath.Clean(absolute)
		recorded := relativePath(repoRoot, absolute)
		if !utf8.ValidString(recorded) || strings.Contains(recorded, "\\") {
			return nil, &ArtifactError{Path: path, Problem: "path must be UTF-8 with forward slash separators"}
		}
		if seen[recorded] {
			return nil, &ArtifactError{Path: path, Problem: "duplicate artifact path"}
		}
		seen[recorded] = true

		result, err := hashing.Hash(absolute)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, &ArtifactError{Path: path, Problem: "the file does not exist"}
			}
			return nil, &ArtifactError{Path: path, Problem: err.Error()}
		}
		artifacts = append(artifacts, Artifact{
			Kind:   result.Kind,
			Name:   filepath.Base(absolute),
			Path:   recorded,
			Size:   result.Size,
			Digest: &Digest{SHA256: result.SHA256},
		})
	}

	return artifacts, nil
}

// relativePath returns the path of a file relative to the repository root,
// with forward slashes.
//
// A file outside the repository keeps its absolute path: pretending it is
// relative would point at the wrong file.
func relativePath(repoRoot, absolute string) string {
	relative, err := filepath.Rel(repoRoot, absolute)
	if err != nil {
		return filepath.ToSlash(absolute)
	}
	relative = filepath.ToSlash(relative)
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return filepath.ToSlash(absolute)
	}
	return relative
}
