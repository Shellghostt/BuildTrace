package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellghostt/buildtrace/internal/testrepo"
)

func TestManifestVerificationRoundTripAndSingleByteTamper(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")
	output := filepath.Join(t.TempDir(), "manifest.json")
	created := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "dist/app", "--out", output)
	if created.code != ExitOK {
		t.Fatal(created)
	}
	got := run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir, "--json")
	if got.code != ExitOK || !strings.Contains(got.stdout, `"scope":"unsigned_manifest"`) || !strings.Contains(got.stdout, `"status":"matched"`) {
		t.Fatal(got)
	}
	writeArtifact(t, repo.Dir, "dist/app", "jello") // one flipped bit in h -> j
	got = run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir, "--json")
	if got.code != ExitVerificationFailed || !strings.Contains(got.stdout, `"reason":"digest_mismatch"`) || !strings.Contains(got.stdout, `"artifact":"app"`) {
		t.Fatal(got)
	}
	if err := os.Remove(filepath.Join(repo.Dir, "dist", "app")); err != nil {
		t.Fatal(err)
	}
	got = run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir, "--json")
	if got.code != ExitInvalidInput || !strings.Contains(got.stdout, `"reason":"artifact_missing"`) {
		t.Fatal(got)
	}
}

func TestDirectoryVerificationAndOutputProtection(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "dist/app", "hello")
	for _, output := range []string{filepath.Join(repo.Dir, "dist", "app"), filepath.Join(repo.Dir, "dist", "manifest.json")} {
		got := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "dist", "--out", output)
		if got.code != ExitInvalidInput {
			t.Fatal(got)
		}
	}
	output := filepath.Join(t.TempDir(), "manifest.json")
	got := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "dist", "--out", output)
	if got.code != ExitOK {
		t.Fatal(got)
	}
	got = run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir)
	if got.code != ExitOK || !strings.Contains(got.stdout, "unsigned manifest") {
		t.Fatal(got)
	}
	writeArtifact(t, repo.Dir, "dist/new", "new")
	got = run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir)
	if got.code != ExitVerificationFailed || !strings.Contains(got.stderr, "digest_mismatch") {
		t.Fatal(got)
	}
}

func TestActualBinaryVerifiesOfflineAndRejectsVersions(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "buildtrace.exe")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/buildtrace")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, out)
	}
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "artifact", "hello")
	output := filepath.Join(t.TempDir(), "manifest.json")
	created := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "artifact", "--out", output)
	if created.code != ExitOK {
		t.Fatal(created)
	}
	command := exec.Command(binary, "verify", "--manifest", output, "--root", repo.Dir, "--json")
	command.Env = []string{"PATH=" + t.TempDir(), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
	if out, err := command.CombinedOutput(); err != nil || !strings.Contains(string(out), `"status":"matched"`) {
		t.Fatalf("offline CLI: %v %s", err, out)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["schemaVersion"] = 99
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, data, 0o644); err != nil {
		t.Fatal(err)
	}
	command = exec.Command(binary, "verify", "--manifest", output, "--root", repo.Dir, "--json")
	out, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !strings.Contains(string(out), "unsupported_schema_version") || !errors.As(err, &exit) || exit.ExitCode() != ExitInvalidInput {
		t.Fatalf("version accepted or wrong exit: %v %s", err, out)
	}
}

func TestManifestOutputDoesNotFollowSymlink(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "artifact", "hello")
	output := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.Symlink(filepath.Join(repo.Dir, "artifact"), output); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "artifact", "--out", output)
	if got.code != ExitOK {
		t.Fatal(got)
	}
	data, err := os.ReadFile(filepath.Join(repo.Dir, "artifact"))
	if err != nil || string(data) != "hello" {
		t.Fatal("output followed symlink", err)
	}
}

func TestVerificationChecksKindAndDeclaredSize(t *testing.T) {
	repo := testrepo.New(t)
	writeArtifact(t, repo.Dir, "artifact", "hello")
	output := filepath.Join(t.TempDir(), "manifest.json")
	created := run(t, &App{}, "manifest", "--repo", repo.Dir, "--artifact", "artifact", "--out", output)
	if created.code != ExitOK {
		t.Fatal(created)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ before, after, reason string }{{`"size": 5`, `"size": 6`, "size_mismatch"}, {`"kind": "file"`, `"kind": "symlink"`, "kind_mismatch"}} {
		changed := strings.Replace(string(data), tc.before, tc.after, 1)
		if err := os.WriteFile(output, []byte(changed), 0o644); err != nil {
			t.Fatal(err)
		}
		got := run(t, &App{}, "verify", "--manifest", output, "--root", repo.Dir, "--json")
		if got.code != ExitVerificationFailed || !strings.Contains(got.stdout, tc.reason) {
			t.Fatal(got)
		}
	}
}
