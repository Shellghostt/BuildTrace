package metadata

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrNotARepository is returned when the directory is not inside a git
// repository.
//
// It has its own type because the CLI treats it as invalid input (exit 2)
// rather than as a tool failure: the user pointed BuildTrace at the wrong
// directory, and that is not a bug in BuildTrace.
var ErrNotARepository = errors.New("not a git repository")

// ErrNoCommits is returned when the repository has no commit yet.
var ErrNoCommits = errors.New("the repository has no commits yet")

// Runner executes a git command in a directory and returns its standard
// output.
//
// The interface exists so that the tests can drive the collector without a
// git binary, and so that no code path can accidentally use a shell.
type Runner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecRunner runs the real git binary.
type ExecRunner struct {
	// Binary is the git executable. Empty means "git" from the PATH.
	Binary string
}

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	binary := r.Binary
	if binary == "" {
		binary = "git"
	}

	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = dir
	// A git command must never wait for a human: a repository with a missing
	// object or a locked index would otherwise hang the build.
	command.Env = append(gitEnvironment(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")

	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output)), nil
}

// gitEnvironment is the environment the git subprocess sees.
//
// It is an allowlist, like everything else in this package. The variables
// kept here are the ones git needs to find the user configuration; every
// other variable, and in particular every credential, is left out.
//
// GIT_CEILING_DIRECTORIES is kept because it is not a credential but a
// deliberate instruction about where repository discovery may stop. A user
// who sets it expects git to honour it, and BuildTrace runs git.
//
// GIT_DIR and GIT_WORK_TREE are deliberately not kept: they would point
// the collector at a different repository than the one the user named.
func gitEnvironment() []string {
	allowed := []string{
		"PATH",
		"HOME",
		"USERPROFILE",
		"HOMEDRIVE",
		"HOMEPATH",
		"USER",
		"USERNAME",
		"SYSTEMROOT",
		"TEMP",
		"TMP",
		"GIT_CEILING_DIRECTORIES",
	}
	environment := make([]string, 0, len(allowed)+2)
	for _, name := range allowed {
		if value, ok := lookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// GitCollector reads the source facts from a git repository.
type GitCollector struct {
	// Dir is the directory the commands run in. It may be a subdirectory of
	// the repository.
	Dir string
	// Runner executes git. Empty means the real git binary.
	Runner Runner
}

// Collect reads the commit, the dirty state and the remote of the
// repository.
func (c GitCollector) Collect(ctx context.Context) (Source, error) {
	runner := c.Runner
	if runner == nil {
		runner = ExecRunner{}
	}

	if _, err := c.Root(); err != nil {
		return Source{}, err
	}

	commit, err := c.commit(ctx, runner)
	if err != nil {
		return Source{}, err
	}

	status, err := runner.Run(ctx, c.Dir, "status", "--porcelain")
	if err != nil {
		return Source{}, fmt.Errorf("read the working tree status: %w", err)
	}

	remote, err := c.remote(ctx, runner)
	if err != nil {
		return Source{}, err
	}

	return Source{
		URI:    NormalizeGitURI(remote),
		Commit: commit,
		Dirty:  strings.TrimSpace(status) != "",
	}, nil
}

// commit returns the full SHA of HEAD.
//
// The check for "the repository has no commits" does not look at the text
// of git's error message: git says "unknown revision" in one version and
// "does not have any commits yet" in another, and the wording is not an
// interface. Instead the repository is asked whether it holds any ref at
// all. A repository with no refs has no commits, whatever git calls it.
func (c GitCollector) commit(ctx context.Context, runner Runner) (string, error) {
	commit, err := runner.Run(ctx, c.Dir, "rev-parse", "--verify", "--quiet", "HEAD")
	if err == nil {
		commit = strings.TrimSpace(commit)
		if commit != "" {
			return commit, nil
		}
	}

	refs, refsErr := runner.Run(ctx, c.Dir, "for-each-ref", "--count=1", "--format=%(objectname)")
	if refsErr == nil && strings.TrimSpace(refs) == "" {
		return "", ErrNoCommits
	}

	return "", fmt.Errorf("read HEAD: %w", err)
}

// Root returns the root directory of the repository the directory belongs
// to.
//
// It is the directory the artifact paths are made relative to.
func (c GitCollector) Root() (string, error) {
	runner := c.Runner
	if runner == nil {
		runner = ExecRunner{}
	}

	root, err := runner.Run(context.Background(), c.Dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotARepository, err)
	}
	return strings.TrimSpace(root), nil
}

// remote returns the URL of the origin remote, or of the first remote when
// there is no origin.
//
// A repository without a remote is normal for a local build, so it is not an
// error: the manifest simply has an empty URI.
func (c GitCollector) remote(ctx context.Context, runner Runner) (string, error) {
	output, err := runner.Run(ctx, c.Dir, "remote", "get-url", "origin")
	if err == nil && strings.TrimSpace(output) != "" {
		return strings.TrimSpace(output), nil
	}

	remotes, err := runner.Run(ctx, c.Dir, "remote")
	if err != nil {
		// A repository without remotes: git exits non-zero.
		return "", nil
	}
	for _, name := range strings.Fields(remotes) {
		if name == "" {
			continue
		}
		url, err := runner.Run(ctx, c.Dir, "remote", "get-url", name)
		if err == nil && strings.TrimSpace(url) != "" {
			return strings.TrimSpace(url), nil
		}
	}
	return "", nil
}
