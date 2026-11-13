package metadata

import (
	"context"
	"os"
	"runtime"
	"strings"
)

// lookupEnv is a thin wrapper so that the environment handling can be
// replaced in the tests.
var lookupEnv = os.LookupEnv

// Platform describes the machine the build ran on.
//
// It reads the runtime and the host name. It never reads the environment:
// the list of variables in this project is an allowlist, and the host name
// is not in it because the host name is not a secret.
func Platform(builderID string) Builder {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return Builder{
		ID:   builderID,
		Host: host,
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
}

// CollectToolchain describes the tools that took part in the build.
//
// The Go version comes from the runtime, not from a `go version` subprocess,
// so it is the version the binary was actually built with. The git version
// comes from the git binary and is empty when git is not installed.
func CollectToolchain(ctx context.Context, runner Runner) Toolchain {
	toolchain := Toolchain{Go: GoVersion()}

	if runner == nil {
		runner = ExecRunner{}
	}
	output, err := runner.Run(ctx, ".", "--version")
	if err != nil {
		return toolchain
	}
	toolchain.Git = ParseGitVersion(output)
	return toolchain
}

// GoVersion returns the Go version the binary was built with, without the
// "go" prefix.
func GoVersion() string {
	version := runtime.Version()
	return strings.TrimPrefix(version, "go")
}

// ParseGitVersion extracts the version number from the output of
// "git --version".
//
// The output looks like "git version 2.53.0.windows.1". The manifest keeps
// the number and nothing else.
func ParseGitVersion(output string) string {
	fields := strings.Fields(output)
	for index, field := range fields {
		if field == "version" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	return ""
}
