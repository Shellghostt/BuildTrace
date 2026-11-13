package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// M1 handles files only. Directory artifacts are hashed deterministically in
// M2, and until then saying so is better than recording a size that means
// something else.
func CollectArtifacts(repoRoot string, paths []string) ([]Artifact, error) {
	artifacts := make([]Artifact, 0, len(paths))

	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return nil, &ArtifactError{Path: path, Problem: "the path is empty"}
		}

		absolute := path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(repoRoot, path)
		}
		absolute = filepath.Clean(absolute)

		info, err := os.Stat(absolute)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, &ArtifactError{Path: path, Problem: "the file does not exist"}
			}
			return nil, &ArtifactError{Path: path, Problem: err.Error()}
		}
		if info.IsDir() {
			return nil, &ArtifactError{
				Path:    path,
				Problem: "directory artifacts are supported from M2, when the deterministic directory hasher exists",
			}
		}
		if !info.Mode().IsRegular() {
			return nil, &ArtifactError{Path: path, Problem: "not a regular file"}
		}

		artifacts = append(artifacts, Artifact{
			Name: filepath.Base(absolute),
			Path: relativePath(repoRoot, absolute),
			Size: info.Size(),
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
