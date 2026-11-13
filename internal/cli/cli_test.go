package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellghostt/buildtrace/internal/testrepo"
)

// result is what one run of the tool produced.
type result struct {
	code   int
	stdout string
	stderr string
}

// run executes the tool with the given arguments.
func run(t *testing.T, app *App, args ...string) result {
	t.Helper()

	var stdout, stderr bytes.Buffer
	app.Stdout = &stdout
	app.Stderr = &stderr
	if app.Version == "" {
		app.Version = "0.1.0-test"
	}
	if app.Now == nil {
		app.Now = func() time.Time { return time.Date(2026, 11, 13, 9, 58, 0, 0, time.UTC) }
	}

	code := app.Run(args)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestManifestWritesAManifest(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	output := filepath.Join(t.TempDir(), "buildtrace.json")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--out", output,
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}

	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}

	var document struct {
		SchemaVersion int `json:"schemaVersion"`
		BuiltAt       string
		Source        struct {
			Commit string `json:"commit"`
			Dirty  bool   `json:"dirty"`
		} `json:"source"`
		Artifacts []struct {
			Name string `json:"name"`
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode the manifest: %v\n%s", err, encoded)
	}

	if document.SchemaVersion != 1 {
		t.Fatalf("expected the schema version 1, got %d", document.SchemaVersion)
	}
	if document.BuiltAt != "2026-11-13T09:58:00Z" {
		t.Fatalf("expected the pinned timestamp, got %q", document.BuiltAt)
	}
	if document.Source.Commit != repo.Head(t) {
		t.Fatalf("expected the commit %q, got %q", repo.Head(t), document.Source.Commit)
	}
	if len(document.Artifacts) != 1 {
		t.Fatalf("expected one artifact, got %d", len(document.Artifacts))
	}
	if document.Artifacts[0].Path != "dist/app" {
		t.Fatalf("expected the path dist/app, got %q", document.Artifacts[0].Path)
	}
	if document.Artifacts[0].Size != 5 {
		t.Fatalf("expected the size 5, got %d", document.Artifacts[0].Size)
	}
}

func TestManifestWritesToStdoutWhenThereIsNoOutputFile(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, `"schemaVersion": 1`) {
		t.Fatalf("expected the manifest on stdout, got %q", got.stdout)
	}
}

func TestManifestWarnsAboutADirtyWorkingTree(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "dirty") {
		t.Fatalf("expected a dirty warning on stderr, got %q", got.stderr)
	}
	if !strings.Contains(got.stdout, `"dirty": true`) {
		t.Fatalf("expected the manifest to record the dirty state, got %q", got.stdout)
	}
}

func TestManifestOutsideAGitRepository(t *testing.T) {
	dir := outsideARepository(t)
	writeArtifact(t, dir, "dist/app", "hello")

	got := run(t, &App{},
		"manifest",
		"--repo", dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d: %s", ExitInvalidInput, got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "not a git repository") {
		t.Fatalf("expected the error to explain the problem, got %q", got.stderr)
	}
}

func TestManifestWithAMissingArtifact(t *testing.T) {
	repo := testrepo.New(t)

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d: %s", ExitInvalidInput, got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "does not exist") {
		t.Fatalf("expected the error to name the problem, got %q", got.stderr)
	}
}

func TestManifestWithoutAnArtifact(t *testing.T) {
	repo := testrepo.New(t)

	got := run(t, &App{}, "manifest", "--repo", repo.Dir)
	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d: %s", ExitInvalidInput, got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "--artifact") {
		t.Fatalf("expected the error to name the missing flag, got %q", got.stderr)
	}
}

func TestManifestWithABadTimestamp(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "yesterday",
	)
	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d: %s", ExitInvalidInput, got.code, got.stderr)
	}
	if !strings.Contains(got.stderr, "RFC3339") {
		t.Fatalf("expected the error to explain the format, got %q", got.stderr)
	}
}

func TestManifestWithAnUnwritableOutputFile(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	// A path inside a directory that does not exist cannot be written.
	output := filepath.Join(t.TempDir(), "does", "not", "exist", "buildtrace.json")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--out", output,
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitToolError {
		t.Fatalf("expected exit %d, got %d: %s", ExitToolError, got.code, got.stderr)
	}
}

func TestSourceDateEpochPinsTheTimestamp(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	// 2026-11-13T09:58:00Z
	const epoch = "1794563880"

	got := run(t, &App{
		LookupEnv: func(name string) (string, bool) {
			if name == "SOURCE_DATE_EPOCH" {
				return epoch, true
			}
			return "", false
		},
	},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "2026-11-13T09:58:00Z") {
		t.Fatalf("expected the epoch to be used, got %q", got.stdout)
	}
}

func TestBuiltAtWinsOverSourceDateEpoch(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	got := run(t, &App{
		LookupEnv: func(name string) (string, bool) {
			if name == "SOURCE_DATE_EPOCH" {
				return "0", true
			}
			return "", false
		},
	},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "2026-11-13T09:58:00Z") {
		t.Fatalf("expected the flag to win, got %q", got.stdout)
	}
}

func TestNoSecretEverReachesTheManifest(t *testing.T) {
	// The secret is planted in every place it could plausibly leak from:
	// the remote URL, the environment, the artifact name and the builder
	// id. None of them may appear in the manifest.
	const secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	t.Setenv("GITHUB_TOKEN", secret)
	t.Setenv("NPM_TOKEN", secret)
	t.Setenv("AWS_SECRET_ACCESS_KEY", secret)

	repo := testrepo.New(t)
	repo.SetRemote(t, "https://user:"+secret+"@github.com/shellghostt/buildtrace.git")
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	output := filepath.Join(t.TempDir(), "buildtrace.json")

	got := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--out", output,
		"--built-at", "2026-11-13T09:58:00Z",
		"--builder-id", "local",
	)
	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d: %s", ExitOK, got.code, got.stderr)
	}

	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the secret reached the manifest:\n%s", encoded)
	}
	if strings.Contains(got.stdout, secret) || strings.Contains(got.stderr, secret) {
		t.Fatalf("the secret reached the output:\n%s\n%s", got.stdout, got.stderr)
	}
}

func TestVersionPrintsTheVersion(t *testing.T) {
	got := run(t, &App{Version: "0.1.0"}, "version")

	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d", ExitOK, got.code)
	}
	if strings.TrimSpace(got.stdout) != "buildtrace 0.1.0" {
		t.Fatalf("unexpected output %q", got.stdout)
	}
}

func TestTheLaterCommandsSayTheyAreNotImplemented(t *testing.T) {
	for _, command := range []string{"record", "verify", "inspect"} {
		t.Run(command, func(t *testing.T) {
			got := run(t, &App{}, command)

			if got.code != ExitToolError {
				t.Fatalf("expected exit %d, got %d", ExitToolError, got.code)
			}
			if !strings.Contains(got.stderr, "not implemented") {
				t.Fatalf("expected the tool to say it is not implemented, got %q", got.stderr)
			}
			if got.stdout != "" {
				t.Fatalf("expected nothing on stdout, got %q", got.stdout)
			}
		})
	}
}

func TestAnUnknownCommand(t *testing.T) {
	got := run(t, &App{}, "frobnicate")

	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d", ExitInvalidInput, got.code)
	}
	if !strings.Contains(got.stderr, "unknown command") {
		t.Fatalf("expected the error to say the command is unknown, got %q", got.stderr)
	}
}

func TestNoArgumentsPrintsTheUsage(t *testing.T) {
	got := run(t, &App{})

	if got.code != ExitInvalidInput {
		t.Fatalf("expected exit %d, got %d", ExitInvalidInput, got.code)
	}
	if !strings.Contains(got.stdout, "Usage:") {
		t.Fatalf("expected the usage, got %q", got.stdout)
	}
}

func TestHelpSucceeds(t *testing.T) {
	got := run(t, &App{}, "help")

	if got.code != ExitOK {
		t.Fatalf("expected exit %d, got %d", ExitOK, got.code)
	}
	if !strings.Contains(got.stdout, "buildtrace manifest") {
		t.Fatalf("expected the usage, got %q", got.stdout)
	}
}

func TestTwoRunsOverTheSameInputsProduceTheSameBytes(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")

	first := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)
	second := run(t, &App{},
		"manifest",
		"--repo", repo.Dir,
		"--artifact", "dist/app",
		"--built-at", "2026-11-13T09:58:00Z",
	)

	if first.code != ExitOK || second.code != ExitOK {
		t.Fatalf("expected both runs to succeed, got %d and %d", first.code, second.code)
	}
	if first.stdout != second.stdout {
		t.Fatalf("the two runs differ:\n--- first ---\n%s\n--- second ---\n%s", first.stdout, second.stdout)
	}
}

func writeArtifact(t *testing.T, root, name, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// outsideARepository returns a directory that is not inside a git
// repository.
//
// Repository discovery is stopped at the parent of the temporary directory
// with GIT_CEILING_DIRECTORIES, because a machine may well have a
// repository further up the tree.
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
