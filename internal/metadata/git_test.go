package metadata

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellghostt/buildtrace/internal/testrepo"
)

func TestCollectReadsTheCommitAndTheCleanState(t *testing.T) {
	repo := testrepo.New(t)

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if source.Commit != repo.Head(t) {
		t.Fatalf("expected the commit %q, got %q", repo.Head(t), source.Commit)
	}
	if len(source.Commit) != 40 {
		t.Fatalf("expected a full 40 character SHA, got %q", source.Commit)
	}
	if source.Dirty {
		t.Fatal("a clean repository must not be reported as dirty")
	}
	if source.URI != "" {
		t.Fatalf("expected no URI for a repository without a remote, got %q", source.URI)
	}
}

func TestCollectReportsADirtyWorkingTree(t *testing.T) {
	repo := testrepo.New(t)
	repo.Write(t, "untracked.txt", "new file\n")

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !source.Dirty {
		t.Fatal("expected the working tree to be reported as dirty")
	}
}

func TestCollectReportsAModifiedTrackedFile(t *testing.T) {
	repo := testrepo.New(t)
	repo.Write(t, "README.md", "# changed\n")

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !source.Dirty {
		t.Fatal("expected the working tree to be reported as dirty")
	}
}

func TestCollectReadsAndNormalisesTheRemote(t *testing.T) {
	repo := testrepo.New(t)
	repo.SetRemote(t, "https://github.com/shellghostt/buildtrace.git")

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if source.URI != "git+https://github.com/shellghostt/buildtrace" {
		t.Fatalf("expected the normalised remote, got %q", source.URI)
	}
}

func TestCollectStripsCredentialsFromTheRemote(t *testing.T) {
	repo := testrepo.New(t)
	secret := "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	repo.SetRemote(t, "https://user:"+secret+"@github.com/shellghostt/buildtrace.git")

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if strings.Contains(source.URI, secret) {
		t.Fatalf("the secret survived in the URI %q", source.URI)
	}
	if source.URI != "git+https://github.com/shellghostt/buildtrace" {
		t.Fatalf("expected the normalised remote, got %q", source.URI)
	}
}

func TestCollectFindsTheFirstRemoteWhenThereIsNoOrigin(t *testing.T) {
	repo := testrepo.New(t)
	repo.Git(t, "remote", "add", "upstream", "git@github.com:shellghostt/buildtrace.git")

	collector := GitCollector{Dir: repo.Dir}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if source.URI != "git+ssh://github.com/shellghostt/buildtrace" {
		t.Fatalf("expected the normalised remote, got %q", source.URI)
	}
}

func TestCollectWorksFromASubdirectory(t *testing.T) {
	repo := testrepo.New(t)
	repo.Write(t, "nested/deep/file.txt", "content\n")

	collector := GitCollector{Dir: filepath.Join(repo.Dir, "nested", "deep")}
	source, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if source.Commit != repo.Head(t) {
		t.Fatalf("expected the commit %q, got %q", repo.Head(t), source.Commit)
	}
}

func TestCollectOutsideARepository(t *testing.T) {
	dir := outsideARepository(t)

	collector := GitCollector{Dir: dir}
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNotARepository) {
		t.Fatalf("expected ErrNotARepository, got %v", err)
	}
}

func TestCollectInARepositoryWithoutCommits(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init", "--initial-branch=main")

	collector := GitCollector{Dir: dir}
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNoCommits) {
		t.Fatalf("expected ErrNoCommits, got %v", err)
	}
}

func TestRootReturnsTheTopLevelDirectory(t *testing.T) {
	repo := testrepo.New(t)
	repo.Write(t, "nested/deep/file.txt", "content\n")

	collector := GitCollector{Dir: filepath.Join(repo.Dir, "nested", "deep")}
	root, err := collector.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}

	expected, err := filepath.EvalSymlinks(repo.Dir)
	if err != nil {
		expected = repo.Dir
	}
	actual, err := filepath.EvalSymlinks(root)
	if err != nil {
		actual = root
	}
	if !sameDirectory(expected, actual) {
		t.Fatalf("expected the root %q, got %q", expected, actual)
	}
}

func TestRootOutsideARepository(t *testing.T) {
	collector := GitCollector{Dir: outsideARepository(t)}

	_, err := collector.Root()
	if !errors.Is(err, ErrNotARepository) {
		t.Fatalf("expected ErrNotARepository, got %v", err)
	}
}

func TestTheGitSubprocessDoesNotSeeTheWholeEnvironment(t *testing.T) {
	// The git subprocess gets an allowlist. A secret in the environment of
	// BuildTrace must not be reachable from a git hook or a credential
	// helper that git might invoke.
	t.Setenv("BUILDTRACE_TEST_SECRET", "do-not-leak-me")

	repo := testrepo.New(t)
	collector := GitCollector{Dir: repo.Dir}

	environment := gitEnvironment()
	for _, entry := range environment {
		if strings.HasPrefix(entry, "BUILDTRACE_TEST_SECRET=") {
			t.Fatalf("the secret reached the git environment: %v", environment)
		}
	}

	// The allowlist keeps the variables git needs to work.
	if !containsPrefix(environment, "PATH=") {
		t.Fatalf("expected PATH to be kept, got %v", environment)
	}

	// The collector still works with the restricted environment.
	if _, err := collector.Collect(context.Background()); err != nil {
		t.Fatalf("collect with the restricted environment: %v", err)
	}
}

// outsideARepository returns a directory that is not inside a git
// repository.
//
// The temporary directory is used, and repository discovery is stopped at
// its parent with GIT_CEILING_DIRECTORIES, because a machine may well have
// a repository further up the tree. The test is skipped in the unlikely
// case that the directory is still inside one.
func outsideARepository(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))

	command := exec.Command("git", "rev-parse", "--show-toplevel")
	command.Dir = dir
	command.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
	if err := command.Run(); err == nil {
		t.Skip("the temporary directory is inside a git repository")
	}
	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func containsPrefix(entries []string, prefix string) bool {
	for _, entry := range entries {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

func sameDirectory(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
