package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shellghostt/buildtrace/internal/attestation"
	"github.com/shellghostt/buildtrace/internal/testrepo"
)

type forbiddenGit struct{}

func (forbiddenGit) Run(context.Context, string, ...string) (string, error) {
	panic("this operation must not execute git")
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestUnsignedRecordInspectRoundTripDoesNotUseOriginalBuildClock(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")
	app := &App{Now: func() time.Time { panic("original build time must not be inferred") },
		LookupEnv: func(string) (string, bool) { panic("original build metadata must not come from environment") }}
	first := run(t, app, "record", "--repo", repo.Dir, "--artifact", "dist/app")
	second := run(t, app, "record", "--repo", repo.Dir, "--artifact", "dist/app", "--sign", "none")
	if first.code != ExitOK || first.stdout != second.stdout || !strings.Contains(first.stderr, "unsigned") || !strings.Contains(first.stderr, "dirty") {
		t.Fatalf("unsigned determinism/scope failed: %#v %#v", first, second)
	}
	if strings.Contains(first.stdout, "startedOn") || strings.Contains(first.stdout, "finishedOn") || strings.Contains(first.stdout, "resolvedDependencies") || strings.Contains(first.stdout, "byproducts") || strings.Contains(first.stdout, repo.Dir) {
		t.Fatal("record invented history or leaked the host root")
	}
	if !strings.Contains(first.stdout, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") {
		t.Fatal("raw SHA-256 of hello was not recorded")
	}
	path := filepath.Join(t.TempDir(), "app.intoto.jsonl")
	if err := os.WriteFile(path, []byte(first.stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	inspectionApp := &App{Git: forbiddenGit{}, Now: app.Now, LookupEnv: app.LookupEnv}
	got := run(t, inspectionApp, "inspect", "--attestation", path, "--json")
	var report attestation.Inspection
	if err := json.Unmarshal([]byte(got.stdout), &report); err != nil || got.code != ExitOK || report.Status != "inspected" || report.Scope != "unsigned_statement" {
		t.Fatalf("inspection did not report its actual scope: %#v %v", got, err)
	}
	text := run(t, inspectionApp, "inspect", "--attestation", path)
	for _, required := range []string{"unsigned statement", "not verified", "subject: dist/app", "builder label:", "build type:", "dependencies: none recorded"} {
		if !strings.Contains(text.stdout, required) {
			t.Fatal("human inspection omitted", required, text)
		}
	}
}

func TestUnsupportedSigningAndBuildExecutionFailBeforeCollecting(t *testing.T) {
	for _, args := range [][]string{
		{"record", "--sign", "keyless"}, {"record", "--sign", "local"}, {"record", "--sign", "fixture-secret"},
		{"record", "--command", "do-not-execute"}, {"record", "--artifact", "app", "--builder-id", ""},
	} {
		got := run(t, &App{Git: forbiddenGit{}}, args...)
		if got.code != ExitInvalidInput || got.stdout != "" || strings.Contains(got.stderr, "fixture-secret") {
			t.Fatal(args, got)
		}
	}
}

func TestRecordRedactsURIInputsAndDoesNotInferWorkflowOrDependencies(t *testing.T) {
	const secret = "fixture-private-token"
	t.Setenv("GITHUB_TOKEN", secret)
	t.Setenv("NPM_TOKEN", secret)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_WORKFLOW_REF", "invented/workflow@ref")
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	repo := testrepo.New(t)
	repo.SetRemote(t, "https://user:"+secret+"@source.invalid/owner/project.git?token="+secret+"#"+secret)
	writeArtifact(t, repo.Dir, "app", "hello")
	got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "app",
		"--builder-id", "https://user:"+secret+"@builder.invalid/record?token="+secret+"#"+secret,
		"--invocation-id", "https://user:"+secret+"@builder.invalid/run?token="+secret+"#"+secret)
	if got.code != ExitOK {
		t.Fatal(got)
	}
	for _, forbidden := range []string{secret, "invented/workflow", "resolvedDependencies", "startedOn", "finishedOn", repo.Dir} {
		if strings.Contains(got.stdout+got.stderr, forbidden) {
			t.Fatal("private/inferred field reached output", forbidden)
		}
	}
}

func TestRecordExplicitClaimsHaveInputLabelsAndOfflineInspection(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "app", "--invocation-id", "claim-run",
		"--source-uri", "https://source.invalid/claimed.git", "--source-commit", strings.Repeat("b", 40),
		"--started-on", "2026-11-14T05:30:00.125+05:30", "--finished-on", "2026-11-14T00:01:00Z")
	if got.code != ExitOK || !strings.Contains(got.stdout, `"evidence":"caller_assertion"`) || !strings.Contains(got.stdout, `"buildtrace.evidence":"caller_assertion"`) {
		t.Fatal(got)
	}
	parsed, err := attestation.Read(strings.NewReader(got.stdout))
	if err != nil || len(parsed.Dependencies) != 1 || parsed.Metadata.InvocationID != "claim-run" || parsed.Metadata.StartedOn.Nanosecond() != 125000000 {
		t.Fatal(parsed, err)
	}
}

func TestRecordOutputCannotReplaceOrIncludeArtifactsAndWritesAtomically(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "bundle/app", "hello")
	artifact := filepath.Join(repo.Dir, "bundle", "app")
	for _, pair := range [][2]string{{"bundle/app", artifact}, {"bundle", filepath.Join(repo.Dir, "bundle", "attestation.jsonl")}} {
		got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", pair[0], "--out", pair[1])
		if got.code != ExitInvalidInput || got.stdout != "" {
			t.Fatal(pair, got)
		}
	}
	if contents, err := os.ReadFile(artifact); err != nil || string(contents) != "hello" {
		t.Fatal("rejected output changed the artifact", err)
	}
	output := filepath.Join(t.TempDir(), "app.intoto.jsonl")
	for range 2 {
		got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "bundle/app", "--out", output)
		if got.code != ExitOK || got.stdout != "" {
			t.Fatal(got)
		}
		contents, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := attestation.Read(bytes.NewReader(contents)); err != nil {
			t.Fatal("atomic output is not a complete record", err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(output))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary sibling file leaked", err)
	}
	got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "bundle/app", "--out", filepath.Join(t.TempDir(), "missing", "app.jsonl"))
	if got.code != ExitToolError {
		t.Fatal("I/O failure did not exit 3", got)
	}
}

func TestRecordOutputSymlinkDoesNotTruncateTarget(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	output := filepath.Join(t.TempDir(), "app.intoto.jsonl")
	if err := os.Symlink(filepath.Join(repo.Dir, "app"), output); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	got := run(t, &App{}, "record", "--repo", repo.Dir, "--artifact", "app", "--out", output)
	if got.code != ExitOK {
		t.Fatal(got)
	}
	contents, err := os.ReadFile(filepath.Join(repo.Dir, "app"))
	if err != nil || string(contents) != "hello" {
		t.Fatal("output followed and truncated the artifact", err)
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("output symlink was not replaced", err)
	}
}

func TestInspectFailureCodesAndUnknownBuildTypeScope(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{"empty": "", "truncated": "{\n", "multiple": "{}\n{}\n", "unterminated": "{}", "too-large": strings.Repeat(" ", attestation.MaxInputBytes+1)} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		got := run(t, &App{Git: forbiddenGit{}}, "inspect", "--attestation", path, "--json")
		if got.code != ExitInvalidInput || got.stdout != "" {
			t.Fatal(name, got)
		}
	}
	missing := run(t, &App{Git: forbiddenGit{}}, "inspect", "--attestation", filepath.Join(dir, "missing"))
	unreadable := run(t, &App{Git: forbiddenGit{}}, "inspect", "--attestation", dir)
	if missing.code != ExitInvalidInput || unreadable.code != ExitToolError {
		t.Fatal(missing, unreadable)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "m3", "observed.intoto.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "unknown-build-type")
	fixture = bytes.Replace(fixture, []byte(attestation.BuildType), []byte("https://other.invalid/build/v1"), 1)
	if err := os.WriteFile(path, fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	got := run(t, &App{Git: forbiddenGit{}}, "inspect", "--attestation", path)
	if got.code != ExitOK || !strings.Contains(got.stdout, "semantics: unknown") || !strings.Contains(got.stdout, "not verified") {
		t.Fatal(got)
	}
}

func TestM3StdoutFailuresExitAsToolErrors(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "app", "hello")
	var stderr bytes.Buffer
	app := &App{Version: "test", Stdout: brokenOutput{}, Stderr: &stderr}
	if code := app.Run([]string{"record", "--repo", repo.Dir, "--artifact", "app"}); code != ExitToolError {
		t.Fatal(code, stderr.String())
	}
	path := filepath.Join("..", "..", "tests", "fixtures", "m3", "observed.intoto.jsonl")
	app.Git = forbiddenGit{}
	if code := app.Run([]string{"inspect", "--attestation", path, "--json"}); code != ExitToolError {
		t.Fatal(code, stderr.String())
	}
}
