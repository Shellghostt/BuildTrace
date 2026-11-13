// Package testrepo creates throwaway git repositories for the tests.
//
// It is imported by test files only, so it never ends up in the binary.
package testrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Repo is a temporary git repository.
type Repo struct {
	// Dir is the root of the repository.
	Dir string
}

// New creates a repository with one commit.
//
// The test is skipped when git is not installed: the tests that use this
// package are about git, so a machine without git cannot run them.
func New(t *testing.T) *Repo {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	repo := &Repo{Dir: dir}

	repo.Git(t, "init", "--initial-branch=main")
	repo.Git(t, "config", "user.name", "BuildTrace Test")
	repo.Git(t, "config", "user.email", "test@buildtrace.invalid")
	repo.Git(t, "config", "commit.gpgsign", "false")

	repo.Write(t, "README.md", "# fixture\n")
	repo.Commit(t, "initial commit")

	return repo
}

// Git runs a git command in the repository and fails the test when it
// errors.
func (r *Repo) Git(t *testing.T, args ...string) string {
	t.Helper()

	command := exec.Command("git", args...)
	command.Dir = r.Dir
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=BuildTrace Test",
		"GIT_AUTHOR_EMAIL=test@buildtrace.invalid",
		"GIT_COMMITTER_NAME=BuildTrace Test",
		"GIT_COMMITTER_EMAIL=test@buildtrace.invalid",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

// Write creates or replaces a file in the repository.
func (r *Repo) Write(t *testing.T, name, content string) {
	t.Helper()

	path := filepath.Join(r.Dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Commit stages everything and commits it.
func (r *Repo) Commit(t *testing.T, message string) {
	t.Helper()

	r.Git(t, "add", "-A")
	r.Git(t, "commit", "-m", message)
}

// SetRemote points the origin remote at a URL.
func (r *Repo) SetRemote(t *testing.T, url string) {
	t.Helper()

	// A freshly initialised repository has no remote at all, so there is
	// nothing to remove.
	r.GitAllowFailure(t, "remote", "remove", "origin")
	r.Git(t, "remote", "add", "origin", url)
}

// GitAllowFailure runs a git command and ignores the error.
//
// It is used for the commands that are expected to fail in some states,
// such as removing a remote that does not exist yet.
func (r *Repo) GitAllowFailure(t *testing.T, args ...string) {
	t.Helper()

	command := exec.Command("git", args...)
	command.Dir = r.Dir
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=BuildTrace Test",
		"GIT_AUTHOR_EMAIL=test@buildtrace.invalid",
		"GIT_COMMITTER_NAME=BuildTrace Test",
		"GIT_COMMITTER_EMAIL=test@buildtrace.invalid",
	)
	_ = command.Run()
}

// Head returns the commit SHA of HEAD.
func (r *Repo) Head(t *testing.T) string {
	t.Helper()
	return r.Git(t, "rev-parse", "HEAD")
}
