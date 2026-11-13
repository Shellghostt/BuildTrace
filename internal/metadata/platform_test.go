package metadata

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformReportsTheRuntimeAndTheHost(t *testing.T) {
	builder := Platform("https://example.com/builder")

	if builder.ID != "https://example.com/builder" {
		t.Fatalf("expected the builder id to be kept, got %q", builder.ID)
	}
	if builder.OS != runtime.GOOS {
		t.Fatalf("expected the OS %q, got %q", runtime.GOOS, builder.OS)
	}
	if builder.Arch != runtime.GOARCH {
		t.Fatalf("expected the arch %q, got %q", runtime.GOARCH, builder.Arch)
	}
	if builder.Host == "" {
		t.Fatal("expected the host name to be recorded")
	}
}

func TestGoVersionHasNoGoPrefix(t *testing.T) {
	version := GoVersion()

	if strings.HasPrefix(version, "go") {
		t.Fatalf("expected the version without the go prefix, got %q", version)
	}
	if version == "" {
		t.Fatal("expected a version")
	}
	if !strings.Contains(version, ".") {
		t.Fatalf("expected a version number, got %q", version)
	}
}

func TestParseGitVersion(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "the usual output",
			output: "git version 2.53.0.windows.1",
			want:   "2.53.0.windows.1",
		},
		{
			name:   "trailing output",
			output: "git version 2.45.1\n",
			want:   "2.45.1",
		},
		{
			name:   "an unexpected output",
			output: "not git at all",
			want:   "",
		},
		{
			name:   "an empty output",
			output: "",
			want:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ParseGitVersion(test.output); got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestCollectToolchainFallsBackWhenGitIsMissing(t *testing.T) {
	toolchain := CollectToolchain(context.Background(), failingRunner{})

	if toolchain.Go == "" {
		t.Fatal("expected the Go version to be recorded even without git")
	}
	if toolchain.Git != "" {
		t.Fatalf("expected no git version, got %q", toolchain.Git)
	}
}

// failingRunner is a Runner that always fails.
type failingRunner struct{}

func (failingRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "", errRunnerFailed
}

var errRunnerFailed = &runnerError{}

type runnerError struct{}

func (*runnerError) Error() string { return "the runner failed" }
