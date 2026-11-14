package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectArtifactsDescribesTheFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "dist", "app"), "hello")
	writeFile(t, filepath.Join(root, "dist", "app.sig"), "signature")

	artifacts, err := CollectArtifacts(root, []string{"dist/app", "dist/app.sig"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("expected two artifacts, got %d", len(artifacts))
	}

	first := artifacts[0]
	if first.Name != "app" {
		t.Fatalf("expected the name app, got %q", first.Name)
	}
	if first.Path != "dist/app" {
		t.Fatalf("expected the path dist/app, got %q", first.Path)
	}
	if first.Size != 5 {
		t.Fatalf("expected the size 5, got %d", first.Size)
	}
	if first.Kind != "file" || first.Digest == nil || first.Digest.SHA256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatal("expected the SHA-256 of hello")
	}
}

func TestCollectArtifactsRejectsAMissingFile(t *testing.T) {
	root := t.TempDir()

	_, err := CollectArtifacts(root, []string{"dist/app"})
	if err == nil {
		t.Fatal("expected an error")
	}

	var artifactError *ArtifactError
	if !errors.As(err, &artifactError) {
		t.Fatalf("expected an ArtifactError, got %T", err)
	}
	if !strings.Contains(artifactError.Problem, "does not exist") {
		t.Fatalf("expected the problem to say the file is missing, got %q", artifactError.Problem)
	}
}

func TestCollectArtifactsHashesADirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatalf("create the directory: %v", err)
	}

	artifacts, err := CollectArtifacts(root, []string{"dist"})
	if err != nil || len(artifacts) != 1 || artifacts[0].Kind != "directory" || artifacts[0].Digest == nil || artifacts[0].Size != 0 {
		t.Fatalf("expected a hashed empty directory: %v %v", artifacts, err)
	}
}

func TestCollectArtifactsRejectsAnEmptyPath(t *testing.T) {
	root := t.TempDir()

	_, err := CollectArtifacts(root, []string{"  "})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected the error to say the path is empty, got %q", err.Error())
	}
}

func TestCollectArtifactsRejectsDuplicatePaths(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "file"), "hello")
	if _, err := CollectArtifacts(root, []string{"file", "./file"}); err == nil {
		t.Fatal("generated duplicate artifact paths")
	}
}

func TestCollectArtifactsKeepsAForeignPathAbsolute(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "artifact")
	writeFile(t, outside, "content")

	artifacts, err := CollectArtifacts(root, []string{outside})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !filepath.IsAbs(artifacts[0].Path) {
		t.Fatalf("expected an absolute path for a file outside the repository, got %q", artifacts[0].Path)
	}
}

func TestCollectArtifactsUsesForwardSlashes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "nested", "file.txt"), "content")

	artifacts, err := CollectArtifacts(root, []string{filepath.Join("nested", "file.txt")})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if strings.Contains(artifacts[0].Path, "\\") {
		t.Fatalf("expected forward slashes, got %q", artifacts[0].Path)
	}
}

func TestCollectArtifactsAcceptsAnEmptyList(t *testing.T) {
	artifacts, err := CollectArtifacts(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("expected no artifacts, got %d", len(artifacts))
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
